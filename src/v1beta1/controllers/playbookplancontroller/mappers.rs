use std::sync::Arc;

use k8s_openapi::api::core::v1::{Node, Secret};
use kube::runtime::reflector::{ObjectRef, Store};
use tracing::debug;

use crate::v1beta1::{
    self, ClusterInventory, ExecutionMode, HostOutcome, InventoryRef, NodeAccessPolicy,
    StaticInventory,
    playbookplancontroller::{node_readiness, node_recreation, reconciler, status},
};

/// Returns a closure that maps a `NodeAccessPolicy` change to *every* PlaybookPlan, so their
/// managed-ssh node clamping is re-evaluated promptly when an admin edits a policy. A policy's
/// `namespaceSelector` can match any namespace, so without resolving namespace labels here (which a
/// sync mapper can't do) the safe mapping is "all plans" — plans are few and policy edits are rare.
pub fn node_access_policy_to_playbookplans(
    playbookplan_reader: Arc<Store<v1beta1::PlaybookPlan>>,
) -> impl Fn(NodeAccessPolicy) -> Vec<ObjectRef<v1beta1::PlaybookPlan>> {
    move |policy| {
        playbookplan_reader
            .state()
            .iter()
            .map(|plan| ObjectRef::from(&**plan))
            .inspect(|obj_ref| {
                debug!(
                    "Reconcile of {} triggered by NodeAccessPolicy {}",
                    obj_ref,
                    policy.metadata.name.as_deref().unwrap_or("<unnamed>")
                )
            })
            .collect::<Vec<_>>()
    }
}

/// Returns a closure that maps a `ClusterInventory` to the PlaybookPlans that reference it.
///
/// A plan's host set is *read* live on every tick but was *triggered* by nothing: the
/// `ClusterInventory` controller republishes `.status.resolvedHosts` within seconds of a Node
/// joining, leaving or being relabelled, and until this watch existed that change reached the plans
/// built on it only when their next requeue happened to come round — an hour for an idle
/// `OneShot` plan, the next slot for a scheduled one.
pub fn cluster_inventory_to_playbookplans(
    playbookplan_reader: Arc<Store<v1beta1::PlaybookPlan>>,
) -> impl Fn(ClusterInventory) -> Vec<ObjectRef<v1beta1::PlaybookPlan>> {
    inventory_to_playbookplans(playbookplan_reader, "ClusterInventory", |inventory_ref| {
        inventory_ref.cluster_inventory.as_deref()
    })
}

/// Returns a closure that maps a `StaticInventory` to the PlaybookPlans that reference it.
///
/// Same reasoning as [`cluster_inventory_to_playbookplans`], and more sharply so: a
/// `StaticInventory` has no controller and no status, so an edited host list had *no* path to the
/// plans using it at all — not even the incidental one a `NodeAccessPolicy` rewrite gives a
/// `ClusterInventory`.
pub fn static_inventory_to_playbookplans(
    playbookplan_reader: Arc<Store<v1beta1::PlaybookPlan>>,
) -> impl Fn(StaticInventory) -> Vec<ObjectRef<v1beta1::PlaybookPlan>> {
    inventory_to_playbookplans(playbookplan_reader, "StaticInventory", |inventory_ref| {
        inventory_ref.static_inventory.as_deref()
    })
}

/// The shared body of the two inventory mappers: find every cached plan that names this inventory,
/// in this inventory's own namespace.
///
/// `referenced` is what tells the two kinds apart — an [`InventoryRef`] holds an optional name per
/// kind, so a `ClusterInventory` named `workers` must not match a plan referencing a
/// `StaticInventory` of the same name. `kind` only labels the log line.
///
/// # Panics
///
/// Panics if the inventory returned from the apiserver does not have a name.
fn inventory_to_playbookplans<I: kube::Resource>(
    playbookplan_reader: Arc<Store<v1beta1::PlaybookPlan>>,
    kind: &'static str,
    referenced: fn(&InventoryRef) -> Option<&str>,
) -> impl Fn(I) -> Vec<ObjectRef<v1beta1::PlaybookPlan>> {
    move |inventory| {
        let name = inventory
            .meta()
            .name
            .as_deref()
            .expect("inventory must have a name");
        let namespace = inventory.meta().namespace.as_deref();

        playbookplan_reader
            .state()
            .iter()
            .filter(|plan| plan_references_inventory(plan, namespace, name, referenced))
            .map(|plan| ObjectRef::from(&**plan))
            .inspect(|obj_ref| {
                debug!("Reconcile of {obj_ref} triggered by {kind} {name}");
            })
            .collect::<Vec<_>>()
    }
}

/// Returns a closure that maps a Node becoming `Ready` to the PlaybookPlans still waiting to apply
/// to it.
///
/// The narrow predicate is the point. Every kubelet reposts its Node status periodically, so a
/// mapper that answered "all plans" would reconcile every plan every few minutes for the life of
/// the cluster, scaling with the node count. Asking instead whether *this* plan is still waiting on
/// *this* node makes a settled cluster cost nothing: no plan matches, and the heartbeats fall on the
/// floor. A plan that does have a stranded host is woken by that host's own heartbeats until it
/// converges, which is both the retry signal wanted and a bounded one.
///
/// Only a `Ready` node is mapped, because becoming ready is the transition worth acting on. The
/// plan's cached status is enough to decide: a trigger only picks what to look at, and the reconcile
/// it schedules re-derives everything from live state.
pub fn node_to_playbookplans(
    playbookplan_reader: Arc<Store<v1beta1::PlaybookPlan>>,
) -> impl Fn(Node) -> Vec<ObjectRef<v1beta1::PlaybookPlan>> {
    move |node| {
        let Some(node_name) = node.metadata.name.as_deref() else {
            return Vec::new();
        };
        if !node_readiness::is_ready(&node) {
            return Vec::new();
        }

        playbookplan_reader
            .state()
            .iter()
            .filter(|plan| plan_awaits_node(plan, &node, node_name))
            .map(|plan| ObjectRef::from(&**plan))
            .inspect(|obj_ref| {
                debug!("Reconcile of {obj_ref} triggered by node {node_name} becoming Ready");
            })
            .collect::<Vec<_>>()
    }
}

/// Whether `plan` targets `node` and is waiting on something the node turning `Ready` could supply.
///
/// Every part is read from the plan's own spec and status, which is what makes this answerable
/// without a cluster read: `eligibleHosts` is the host set the last reconcile resolved, and a host is
/// owed a run while the hash it last *succeeded* on is not the one the plan currently wants. A host
/// with no recorded status at all has never succeeded, so it is owed one too.
///
/// The host's state is only half the question, though, and asking it alone is what let this wake a
/// plan that could not act on the wake-up. A suspended plan is waiting on an operator, never on a
/// Node: `spec.suspend` is not read anywhere earlier in the reconcile — `may_start_new_run` folds it
/// in far too late to matter here — so suspending a plan and editing its playbook (which moves the
/// hash, so every host is outdated) would otherwise wake it on every kubelet heartbeat of every
/// matching Node for as long as it stayed suspended, which is an ordinary workflow.
///
/// `Recurring` is not woken at all, whatever its hosts say, because nothing it does is started by a
/// Node. Its runs are started by the clock: a tick outside its schedule window lands in the
/// `Timing::Delayed` arm and does nothing, and inside the window the plan is already requeueing on
/// its own. The one thing a Node event releases — the readiness gate — is `OneShot`-only by
/// construction (`node_readiness::holds_for_unready_nodes`), and every path that can make a
/// `Recurring` plan actionable has a trigger of its own: the slot arriving is its own requeue, a hash
/// edit the plan watch, a key rotation the Secret watch, a result the Job watch.
///
/// Leaving it in cost what the rest of this predicate exists to avoid, with nothing to bound it: the
/// budget check below cannot answer for that mode (`attempt_budget_available` returns `true`
/// unconditionally for `Recurring`, because its slot-scoped budget is enforced by the window gate),
/// so a single host left `Unknown` or `Unreachable` kept a `Recurring` plan woken by that Node's
/// every kubelet heartbeat for the life of the plan. A `OneShot` plan in the same state at least
/// stops once its attempts are spent.
///
/// A `OneShot` plan whose attempt budget is spent is the other half of that question, and it is
/// asked through `reconciler::attempt_budget_available` rather than restated here so the wake set and
/// the start gate cannot drift. It matters because two of the outcomes deliberately left in the set
/// below outlive the budget: a host whose recap could not be read stays `Unknown` however many times
/// the run repeats, and a host a down Node excluded stays `Unreachable` after the flap rule
/// (`classify_run_failure`) has refused to refund the attempts. Both then sit on a Node that is
/// `Ready` again and has nothing left to supply. Nothing that restores the budget arrives by this
/// route either — a hash edit, an SSH key rotation and a successful run each have their own watch —
/// so a Node event cannot be the thing that makes an exhausted plan actionable.
///
/// The budget check cannot strand a plan the readiness gate is holding, which is the trap the
/// allow-list version of this predicate fell into: that hold is only ever asserted inside
/// `eligible_to_start`, which already requires the budget, so a held plan always has one.
///
/// The outcome check is what keeps that from meaning "forever". `lastAppliedHash` is only stamped on
/// `Succeeded` (`status::apply_terminal_play_status`), so a host that was reached and failed for real
/// never advances it and would otherwise match this predicate for the life of the plan — waking a
/// plan whose budget is long spent once per Ready node per heartbeat, at a cost of re-resolving both
/// inventory kinds, re-reading every referenced Secret and listing every Node for policy enforcement,
/// none of which can change the outcome. `Failed` means Ansible connected and a task failed; a Node
/// reporting `Ready` does not fix that. `NotReached` covers two causes that agree on exactly this
/// point: an earlier host in the `serial` batch stopped the play, so it is that host's recovery that
/// matters and that host's own heartbeats that carry it — or the run excluded this host because its
/// proxy pod never came up on a Node that was *already* `Ready` (an untolerated taint, a failing
/// image pull, a rejecting admission webhook), where the Node has nothing further to report and only
/// the pod's scheduling can resolve it. `Incomplete` is the same shape of answer: this host ran and
/// did not fail, and what cut it short was some *other* host's failure — so its own Node returning
/// changes nothing, and if a Node recovery is what unblocks the run, it is the failing host's
/// heartbeats that say so.
///
/// Everything else stays in: a host with no entry, one left `Unreachable` — which now means a Node
/// that was genuinely down, the one exclusion a `Ready` heartbeat does resolve — one whose recap was
/// unreadable (`Unknown` — nothing proves it was reached), and one that
/// `Succeeded` on an older revision. The last matters more than it looks: a plan held by the
/// readiness gate never ran, so it still carries the *previous* run's `Succeeded` outcomes, and this
/// watch is the only thing that releases it.
///
/// The Node object itself is read for one thing only: whether it is the *same machine* the record
/// was written about. A rebuilt Node keeps the name `hostsStatus` is keyed by, so a plan's cached
/// status still claims it is converged — and the reconcile this wakes is precisely what drops that
/// claim (`node_recreation`). Asking here too is what keeps the wake set and the start gate from
/// disagreeing about one host: without it a replaced machine is ignored until the plan's next
/// hourly requeue, having been declared outdated by the very tick that would have run on it.
fn plan_awaits_node(plan: &v1beta1::PlaybookPlan, node: &Node, node_name: &str) -> bool {
    if plan.spec.suspend || !matches!(plan.spec.mode, ExecutionMode::OneShot) {
        return false;
    }

    let Some(status) = plan.status.as_ref() else {
        return false;
    };

    if !reconciler::attempt_budget_available(
        &plan.spec.mode,
        status.retry_count,
        reconciler::max_attempts(&plan.spec.mode, plan.spec.max_attempts),
    ) {
        return false;
    }

    let targeted = status
        .eligible_hosts
        .iter()
        .any(|group| group.hosts.iter().any(|host| host == node_name));

    targeted
        && status
            .hosts_status
            .as_ref()
            .and_then(|hosts| hosts.get(node_name))
            .is_none_or(|host| {
                node_recreation::node_replaced_since(host.applied_node_uid.as_deref(), node)
                    || (host.last_applied_hash != status.current_hash
                        && !matches!(
                            host.last_outcome,
                            HostOutcome::Failed | HostOutcome::NotReached | HostOutcome::Incomplete
                        ))
            })
}

/// Whether `plan` targets the inventory `namespace`/`name` of the kind `referenced` selects.
///
/// The namespace is part of the identity, not a formality: `inventoryRefs` are bare names resolved
/// in the plan's own namespace (`reconciler::resolve_inventory`), so two tenants may each own an
/// inventory called `workers` and neither may be woken by the other's edits.
fn plan_references_inventory(
    plan: &v1beta1::PlaybookPlan,
    namespace: Option<&str>,
    name: &str,
    referenced: fn(&InventoryRef) -> Option<&str>,
) -> bool {
    plan.metadata.namespace.as_deref() == namespace
        && plan
            .spec
            .inventory_refs
            .iter()
            .filter_map(referenced)
            .any(|inventory_name| inventory_name == name)
}

/// The Secret watch's mapper. A Secret reaches a plan two ways, and both are asked here so that one
/// watch per enrolled namespace serves both — a second watch on the same collection would double
/// the operator's Secret traffic to answer a question this closure already has in hand.
///
/// The two rules stay separate functions because they are different rules with different
/// predicates: naming a Secret in `variables`/`files` makes it *content*, and a change re-applies
/// the playbook; holding a `StaticInventory`'s SSH key does not, and a change is only worth waking a
/// plan that has something left to apply. Duplicates need no handling — the controller's scheduler
/// is keyed by `ObjectRef`.
pub fn secret_to_affected_playbookplans(
    playbookplan_reader: Arc<Store<v1beta1::PlaybookPlan>>,
    static_inventory_reader: Arc<Store<StaticInventory>>,
) -> impl Fn(Secret) -> Vec<ObjectRef<v1beta1::PlaybookPlan>> {
    let by_reference = secret_to_playbookplans(Arc::clone(&playbookplan_reader));
    let by_ssh_key = ssh_secret_to_playbookplans(playbookplan_reader, static_inventory_reader);

    move |secret| {
        let mut affected = by_reference(secret.clone());
        affected.extend(by_ssh_key(secret));
        affected
    }
}

/// Returns a closure that maps a Secret holding SSH key material to the PlaybookPlans an SSH key
/// rotation could unstick.
///
/// The reference is two hops — a plan names a `StaticInventory`, and the inventory names the Secret
/// — so unlike [`secret_to_playbookplans`] this cannot be answered from the plan store alone, and
/// takes the inventory store too.
///
/// **A plan whose last run succeeded is deliberately left asleep.** Rotating a key changes how the
/// operator connects, not what it applies, so there is nothing for a converged plan to do with the
/// news. The interesting case is the opposite one: a plan whose hosts rejected the old key sits
/// `Failed` with its attempt budget spent, and this is the only thing that will offer it the fix.
/// The predicate is [`status::may_need_another_run`], shared with the budget reset on the other
/// side, so this can never wake a plan that would then decline to act.
///
/// # Panics
///
/// Panics if the secret returned from the apiserver does not have a name.
pub fn ssh_secret_to_playbookplans(
    playbookplan_reader: Arc<Store<v1beta1::PlaybookPlan>>,
    static_inventory_reader: Arc<Store<StaticInventory>>,
) -> impl Fn(Secret) -> Vec<ObjectRef<v1beta1::PlaybookPlan>> {
    move |secret| {
        let secret_name = secret
            .metadata
            .name
            .as_deref()
            .expect("Secret must have a name");

        let inventories: Vec<String> = static_inventory_reader
            .state()
            .iter()
            .filter(|inventory| inventory.metadata.namespace == secret.metadata.namespace)
            .filter(|inventory| inventory.spec.ssh.secret_ref.name == secret_name)
            .filter_map(|inventory| inventory.metadata.name.clone())
            .collect();
        if inventories.is_empty() {
            return Vec::new();
        }

        playbookplan_reader
            .state()
            .iter()
            .filter(|plan| plan.metadata.namespace == secret.metadata.namespace)
            .filter(|plan| {
                plan.status
                    .as_ref()
                    .is_some_and(status::may_need_another_run)
            })
            .filter(|plan| {
                plan.spec
                    .inventory_refs
                    .iter()
                    .filter_map(|inventory_ref| inventory_ref.static_inventory.as_deref())
                    .any(|named| inventories.iter().any(|inventory| inventory == named))
            })
            .map(|plan| ObjectRef::from(&**plan))
            .inspect(|obj_ref| {
                debug!(
                    "Reconcile of {obj_ref} triggered by a change to SSH key Secret {secret_name}"
                );
            })
            .collect::<Vec<_>>()
    }
}

/// Returns a closure that maps a Secret to all PlaybookPlans that reference it.
///
/// # Panics
///
/// Panics if the secret returned from the apiserver does not have a name.
pub fn secret_to_playbookplans(
    secret_reflector_reader: Arc<kube::runtime::reflector::Store<v1beta1::PlaybookPlan>>,
) -> impl Fn(Secret) -> Vec<ObjectRef<v1beta1::PlaybookPlan>> {
    move |secret| {
        let secret_name = secret
            .metadata
            .name
            .as_deref()
            .expect("Secret must have a name");

        secret_reflector_reader
            .state()
            .iter()
            .filter(|resource| resource.metadata.namespace == secret.metadata.namespace)
            .filter(|plan| {
                if let Some(vars) = &plan.spec.template.variables
                    && vars.iter().any(|var| {
                        matches!(
                            var,
                            v1beta1::PlaybookVariableSource::SecretRef { secret_ref }
                            if secret_ref.name == secret_name
                        )
                    })
                {
                    return true;
                }

                if let Some(files) = &plan.spec.template.files {
                    return files.iter().any(|file| {
                        matches!(
                            file,
                            v1beta1::FilesSource::Secret { secret_ref, .. }
                            if secret_ref.name == secret_name
                        )
                    });
                }

                false
            })
            .map(|plan| ObjectRef::from(&**plan))
            .inspect(|obj_ref| {
                debug!(
                    "Reconcile of {} triggered by secret {}",
                    obj_ref, secret_name
                )
            })
            .collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1beta1::{Phase, PlaybookPlan, PlaybookPlanSpec};

    fn cluster_inventory_name(inventory_ref: &InventoryRef) -> Option<&str> {
        inventory_ref.cluster_inventory.as_deref()
    }

    fn static_inventory_name(inventory_ref: &InventoryRef) -> Option<&str> {
        inventory_ref.static_inventory.as_deref()
    }

    fn plan_in(namespace: &str, inventory_refs: Vec<InventoryRef>) -> PlaybookPlan {
        let mut plan = PlaybookPlan::new(
            "web",
            PlaybookPlanSpec {
                inventory_refs,
                ..Default::default()
            },
        );
        plan.metadata.namespace = Some(namespace.to_string());
        plan
    }

    fn cluster(name: &str) -> InventoryRef {
        InventoryRef {
            cluster_inventory: Some(name.to_string()),
            static_inventory: None,
        }
    }

    fn static_(name: &str) -> InventoryRef {
        InventoryRef {
            cluster_inventory: None,
            static_inventory: Some(name.to_string()),
        }
    }

    #[test]
    fn a_plan_matches_the_inventory_it_names() {
        let plan = plan_in("tenant", vec![cluster("workers")]);

        assert!(plan_references_inventory(
            &plan,
            Some("tenant"),
            "workers",
            cluster_inventory_name
        ));
        assert!(!plan_references_inventory(
            &plan,
            Some("tenant"),
            "storage",
            cluster_inventory_name
        ));
    }

    /// `inventoryRefs` are bare names resolved in the plan's own namespace, so an identically named
    /// inventory in another tenant's namespace is a different object and must not wake this plan.
    #[test]
    fn an_inventory_in_another_namespace_is_a_different_inventory() {
        let plan = plan_in("tenant", vec![cluster("workers")]);

        assert!(!plan_references_inventory(
            &plan,
            Some("other-tenant"),
            "workers",
            cluster_inventory_name
        ));
        assert!(!plan_references_inventory(
            &plan,
            None,
            "workers",
            cluster_inventory_name
        ));
    }

    /// The two kinds share one `InventoryRef` and one namespace, so the only thing keeping a
    /// `ClusterInventory` event off a plan that references a *StaticInventory* of the same name is
    /// which field the selector reads.
    #[test]
    fn the_two_inventory_kinds_do_not_match_each_other() {
        let cluster_plan = plan_in("tenant", vec![cluster("workers")]);
        let static_plan = plan_in("tenant", vec![static_("workers")]);

        assert!(!plan_references_inventory(
            &cluster_plan,
            Some("tenant"),
            "workers",
            static_inventory_name
        ));
        assert!(!plan_references_inventory(
            &static_plan,
            Some("tenant"),
            "workers",
            cluster_inventory_name
        ));
        assert!(plan_references_inventory(
            &static_plan,
            Some("tenant"),
            "workers",
            static_inventory_name
        ));
    }

    /// A plan may span several inventories of both kinds in one run; every one of them has to be
    /// able to trigger it, not just the first.
    #[test]
    fn a_plan_matches_any_of_the_inventories_it_names() {
        let plan = plan_in(
            "tenant",
            vec![
                cluster("controlplanes"),
                cluster("workers"),
                static_("edge"),
            ],
        );

        for name in ["controlplanes", "workers"] {
            assert!(plan_references_inventory(
                &plan,
                Some("tenant"),
                name,
                cluster_inventory_name
            ));
        }
        assert!(plan_references_inventory(
            &plan,
            Some("tenant"),
            "edge",
            static_inventory_name
        ));
    }

    fn plan_with_status(status: v1beta1::PlaybookPlanStatus) -> PlaybookPlan {
        let mut plan = PlaybookPlan::new("web", PlaybookPlanSpec::default());
        plan.status = Some(status);
        plan
    }

    fn eligible(hosts: &[&str]) -> Vec<crate::v1beta1::ResolvedHosts> {
        vec![crate::v1beta1::ResolvedHosts {
            name: "workers".into(),
            hosts: hosts.iter().map(|host| host.to_string()).collect(),
        }]
    }

    /// A Node that cannot be a replacement for anything: with no `uid` there is
    /// nothing for `node_recreation::node_replaced_since` to read as one. Every case below that is
    /// about the *host's* recorded state uses it, so each keeps asking exactly what it asked before
    /// the predicate learned about rebuilt machines.
    fn unreplaced_node() -> Node {
        Node::default()
    }

    fn node_with_uid(uid: &str) -> Node {
        Node {
            metadata: kube::core::ObjectMeta {
                uid: Some(uid.to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// A rebuilt machine inherits the name its record is keyed by, so the plan's cached status still
    /// says the host carries the current revision. The reconcile a Node event wakes is what drops
    /// that claim, so this predicate has to agree with it — otherwise the machine that just came
    /// back is passed over until the plan's hourly requeue, declared outdated by the very tick that
    /// would have run on it.
    #[test]
    fn a_plan_awaits_a_host_whose_node_was_replaced_since_it_applied() {
        let mut converged = host("abc", HostOutcome::Succeeded);
        converged.applied_node_uid = Some("uid-1".into());
        let plan = plan_awaiting("node-a", converged);

        assert!(
            !plan_awaits_node(&plan, &unreplaced_node(), "node-a"),
            "on the machine the record was written about, this plan is converged"
        );
        assert!(
            !plan_awaits_node(&plan, &node_with_uid("uid-1"), "node-a"),
            "a Node with the recorded uid is that same machine"
        );
        assert!(plan_awaits_node(&plan, &node_with_uid("uid-2"), "node-a"));
    }

    #[test]
    fn a_plan_awaits_a_targeted_host_it_has_never_applied_to() {
        let plan = plan_with_status(v1beta1::PlaybookPlanStatus {
            eligible_hosts: eligible(&["node-a", "node-b"]),
            current_hash: "abc".into(),
            hosts_status: None,
            ..Default::default()
        });

        assert!(plan_awaits_node(&plan, &unreplaced_node(), "node-a"));
        assert!(plan_awaits_node(&plan, &unreplaced_node(), "node-b"));
    }

    #[test]
    fn a_plan_does_not_await_a_host_it_does_not_target() {
        let plan = plan_with_status(v1beta1::PlaybookPlanStatus {
            eligible_hosts: eligible(&["node-a"]),
            current_hash: "abc".into(),
            ..Default::default()
        });

        assert!(!plan_awaits_node(&plan, &unreplaced_node(), "node-b"));
    }

    /// The whole point of the predicate: a converged plan must not be woken by the periodic Node
    /// status reposts of the hosts it already applied to.
    #[test]
    fn a_plan_does_not_await_a_host_already_on_the_current_revision() {
        let plan = plan_with_status(v1beta1::PlaybookPlanStatus {
            eligible_hosts: eligible(&["node-a", "node-b"]),
            current_hash: "abc".into(),
            hosts_status: Some(std::collections::BTreeMap::from([
                (
                    "node-a".to_string(),
                    crate::v1beta1::HostStatus {
                        last_applied_hash: "abc".into(),
                        ..Default::default()
                    },
                ),
                (
                    "node-b".to_string(),
                    crate::v1beta1::HostStatus {
                        last_applied_hash: "older".into(),
                        ..Default::default()
                    },
                ),
            ])),
            ..Default::default()
        });

        assert!(!plan_awaits_node(&plan, &unreplaced_node(), "node-a"));
        assert!(
            plan_awaits_node(&plan, &unreplaced_node(), "node-b"),
            "a host left behind by the current revision is still owed a run"
        );
    }

    fn host(last_applied_hash: &str, last_outcome: HostOutcome) -> crate::v1beta1::HostStatus {
        crate::v1beta1::HostStatus {
            last_applied_hash: last_applied_hash.into(),
            last_outcome,
            ..Default::default()
        }
    }

    fn plan_awaiting(node: &str, host_status: crate::v1beta1::HostStatus) -> PlaybookPlan {
        plan_with_status(v1beta1::PlaybookPlanStatus {
            eligible_hosts: eligible(&[node]),
            current_hash: "abc".into(),
            hosts_status: Some(std::collections::BTreeMap::from([(
                node.to_string(),
                host_status,
            )])),
            ..Default::default()
        })
    }

    /// A host Ansible connected to and failed on is not fixed by its Node reporting `Ready`, and its
    /// `lastAppliedHash` never advances — so without this it would match the hash check on every
    /// kubelet heartbeat for the life of a plan that provably cannot act on the wake-up.
    #[test]
    fn a_plan_does_not_await_a_host_that_was_reached_and_failed() {
        let plan = plan_awaiting("node-a", host("", HostOutcome::Failed));

        assert!(!plan_awaits_node(&plan, &unreplaced_node(), "node-a"));
    }

    /// A `NotReached` host is blocked on whichever host stopped its `serial` batch, not on its own
    /// Node; if that host is one a Node recovery unblocks, its own heartbeats carry the plan.
    #[test]
    fn a_plan_does_not_await_a_host_an_earlier_batch_stopped_the_play_for() {
        let plan = plan_awaiting("node-a", host("", HostOutcome::NotReached));

        assert!(!plan_awaits_node(&plan, &unreplaced_node(), "node-a"));
    }

    /// The other cause of `NotReached`, and the one this predicate was costing the most: a host the
    /// run excluded because its proxy pod never came up on a Node that was *already* `Ready`. The
    /// Node has nothing further to report — it is Ready and stays Ready — so every one of its
    /// kubelet heartbeats would wake the plan, for the plan's whole life, each wake re-resolving
    /// both inventory kinds, re-reading every referenced Secret and listing every Node. Only the
    /// pod's scheduling can resolve it, and no Node event says anything about that.
    #[test]
    fn a_plan_does_not_await_a_host_whose_proxy_failed_on_a_ready_node() {
        let plan = plan_awaiting("node-a", host("", HostOutcome::NotReached));

        assert!(!plan_awaits_node(&plan, &unreplaced_node(), "node-a"));
    }

    /// An `Incomplete` host ran and did not fail — the playbook stopped for it because a *different*
    /// host failed. Its own Node is healthy and was healthy, so its heartbeats have nothing to say
    /// about the run, and waking the plan on them would be a per-node reconcile every ~5 minutes for
    /// as long as the playbook stays broken.
    #[test]
    fn a_plan_does_not_await_a_host_another_hosts_failure_cut_short() {
        let plan = plan_awaiting("node-a", host("", HostOutcome::Incomplete));

        assert!(!plan_awaits_node(&plan, &unreplaced_node(), "node-a"));
    }

    /// The case the watch exists for: a Node that was down is excluded from the run and recorded
    /// `Unreachable`, and its return is exactly what should start the next run.
    #[test]
    fn a_plan_awaits_a_host_left_unreachable_by_a_node_that_was_down() {
        let plan = plan_awaiting("node-a", host("", HostOutcome::Unreachable));

        assert!(plan_awaits_node(&plan, &unreplaced_node(), "node-a"));
    }

    /// An unreadable recap proves nothing about whether the host was reached, so it stays eligible
    /// for a Node-triggered retry rather than being written off like a real failure.
    #[test]
    fn a_plan_awaits_a_host_whose_recap_could_not_be_read() {
        let plan = plan_awaiting("node-a", host("", HostOutcome::Unknown));

        assert!(plan_awaits_node(&plan, &unreplaced_node(), "node-a"));
    }

    /// A plan held by the readiness gate never ran, so its hosts still carry the *previous* run's
    /// `Succeeded` outcomes against the previous hash. This watch is the only thing that releases
    /// such a plan, so narrowing the predicate must not exclude it.
    #[test]
    fn a_plan_awaits_a_host_that_succeeded_on_an_older_revision() {
        let plan = plan_awaiting("node-a", host("older", HostOutcome::Succeeded));

        assert!(plan_awaits_node(&plan, &unreplaced_node(), "node-a"));
    }

    /// Suspending a plan and editing its playbook is an ordinary workflow, and it leaves every host
    /// outdated against the new hash — so without this the plan is woken by every kubelet heartbeat
    /// of every Node it targets, for as long as it stays suspended, to reach a start gate that
    /// refuses it. The check has to live here because `spec.suspend` is read nowhere earlier in the
    /// reconcile.
    #[test]
    fn a_suspended_plan_awaits_nothing() {
        let mut plan = plan_awaiting("node-a", host("", HostOutcome::Unreachable));
        assert!(
            plan_awaits_node(&plan, &unreplaced_node(), "node-a"),
            "the same plan unsuspended is one the watch exists for"
        );

        plan.spec.suspend = true;

        assert!(!plan_awaits_node(&plan, &unreplaced_node(), "node-a"));
    }

    fn plan_awaiting_with_attempts(
        node: &str,
        host_status: crate::v1beta1::HostStatus,
        retry_count: u32,
    ) -> PlaybookPlan {
        let mut plan = plan_awaiting(node, host_status);
        plan.spec.max_attempts = Some(3);
        plan.status.as_mut().unwrap().retry_count = retry_count;
        plan
    }

    /// The two outcomes that outlive the attempt budget, and the reason the host's own state is not
    /// a sufficient answer. `Unreachable` is where a flapping Node ends up once `classify_run_failure`
    /// has refused to refund its attempts; the Node then returns to `Ready` and reposts its status
    /// every few minutes, with nothing the plan is allowed to do about it.
    #[test]
    fn a_plan_with_no_attempts_left_awaits_nothing() {
        for outcome in [HostOutcome::Unreachable, HostOutcome::Unknown] {
            let plan = plan_awaiting_with_attempts("node-a", host("", outcome.clone()), 3);

            assert!(
                !plan_awaits_node(&plan, &unreplaced_node(), "node-a"),
                "{outcome:?}: an exhausted budget is not something a Ready Node can restore"
            );
            assert!(
                plan_awaits_node(
                    &plan_awaiting_with_attempts("node-a", host("", outcome.clone()), 2),
                    &unreplaced_node(),
                    "node-a"
                ),
                "{outcome:?}: a plan with a try left is exactly what the watch is for"
            );
        }
    }

    /// A `Recurring` plan is started by its schedule and by nothing else, so a Node reporting
    /// `Ready` is never what it was waiting for — and it is the one mode the budget check cannot
    /// bound, since `attempt_budget_available` answers `true` for it unconditionally (its
    /// slot-scoped budget lives in the window gate). Left in the wake set, one host stuck
    /// `Unreachable` or `Unknown` woke such a plan on that Node's every heartbeat for the life of
    /// the plan, with every woken tick falling straight through to the schedule arm.
    #[test]
    fn a_recurring_plan_is_never_woken_by_a_node() {
        for outcome in [HostOutcome::Unreachable, HostOutcome::Unknown] {
            let oneshot = plan_awaiting("node-a", host("", outcome.clone()));
            assert!(
                plan_awaits_node(&oneshot, &unreplaced_node(), "node-a"),
                "{outcome:?}: the same plan as OneShot is one the watch exists for"
            );

            let mut recurring = oneshot;
            recurring.spec.mode = ExecutionMode::Recurring;

            assert!(!plan_awaits_node(&recurring, &unreplaced_node(), "node-a"));
        }
    }

    /// The budget is asked of `OneShot` alone, so a `Recurring` plan must not reach it — the mode
    /// check is what decides, not `retryCount`. Pinned separately so the two reasons stay legible:
    /// a `Recurring` plan with attempts left is refused for the same reason as one without.
    #[test]
    fn a_recurring_plan_is_refused_whatever_its_retry_count() {
        for retry_count in [0, 9] {
            let mut plan = plan_awaiting_with_attempts(
                "node-a",
                host("", HostOutcome::Unreachable),
                retry_count,
            );
            plan.spec.mode = ExecutionMode::Recurring;

            assert!(
                !plan_awaits_node(&plan, &unreplaced_node(), "node-a"),
                "retryCount {retry_count}"
            );
        }
    }

    #[test]
    fn a_plan_without_a_status_awaits_nothing() {
        let plan = PlaybookPlan::new("web", PlaybookPlanSpec::default());

        assert!(!plan_awaits_node(&plan, &unreplaced_node(), "node-a"));
    }

    fn node_named(name: &str, ready: bool) -> Node {
        let mut node = Node {
            metadata: kube::core::ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        node.status.get_or_insert_default().conditions =
            Some(vec![k8s_openapi::api::core::v1::NodeCondition {
                type_: "Ready".into(),
                status: if ready { "True" } else { "False" }.into(),
                ..Default::default()
            }]);
        node
    }

    fn store_holding(plan: PlaybookPlan) -> Arc<Store<PlaybookPlan>> {
        let mut writer = kube::runtime::reflector::store::Writer::<PlaybookPlan>::default();
        let reader = Arc::new(writer.as_reader());
        writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(plan));
        reader
    }

    /// The two halves of the mapper are tested apart — `node_readiness::is_ready` and
    /// `plan_awaits_node` — but their *order* is the part that costs something, and only the
    /// composed closure has it. Every kubelet heartbeat of every Node enters here, so the readiness
    /// check has to reject a not-`Ready` Node before the store is scanned: reversing the two would
    /// still return the right answer and would still pass both halves' own tests, while walking
    /// every plan in the cluster on every heartbeat to do it.
    #[test]
    fn a_node_that_is_not_ready_maps_to_no_plans_without_consulting_the_store() {
        let plan = plan_awaiting("node-a", host("", HostOutcome::Unreachable));
        let mapper = node_to_playbookplans(store_holding(plan));

        assert!(
            mapper(node_named("node-a", false)).is_empty(),
            "a Node that is not Ready supplies nothing, whatever the plans want"
        );
        // The same plan and the same Node, so the emptiness above is the readiness check and not a
        // store that never held anything.
        assert_eq!(mapper(node_named("node-a", true)).len(), 1);
    }

    fn static_inventory(name: &str, namespace: &str, secret: &str) -> StaticInventory {
        let mut inventory = StaticInventory::new(
            name,
            v1beta1::StaticInventorySpec {
                hosts: Vec::new(),
                ssh: v1beta1::SshConfig {
                    user: "root".into(),
                    secret_ref: v1beta1::SecretRef {
                        name: secret.into(),
                    },
                },
            },
        );
        inventory.metadata.namespace = Some(namespace.to_string());
        inventory
    }

    fn plan_using(name: &str, namespace: &str, inventory: &str, phase: Phase) -> PlaybookPlan {
        let mut plan = PlaybookPlan::new(
            name,
            PlaybookPlanSpec {
                inventory_refs: vec![static_(inventory)],
                ..Default::default()
            },
        );
        plan.metadata.namespace = Some(namespace.to_string());
        plan.status = Some(v1beta1::PlaybookPlanStatus {
            phase,
            ..Default::default()
        });
        plan
    }

    fn secret_named(name: &str, namespace: &str) -> Secret {
        Secret {
            metadata: kube::core::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn store_of<K>(objects: Vec<K>) -> Arc<Store<K>>
    where
        K: kube::Resource + Clone + 'static,
        K::DynamicType: Eq + std::hash::Hash + Clone + Default,
    {
        let mut writer = kube::runtime::reflector::store::Writer::<K>::default();
        let reader = Arc::new(writer.as_reader());
        for object in objects {
            writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(object));
        }
        reader
    }

    /// The case the mapper exists for: the hosts rejected the old key, the plan is `Failed` with its
    /// attempts spent, and rotating the Secret is the fix. Nothing else would ever wake it — the key
    /// is not in the execution hash, so the plan's revision has not moved.
    #[test]
    fn rotating_an_ssh_key_wakes_the_plan_it_may_have_broken() {
        let mapper = ssh_secret_to_playbookplans(
            store_of(vec![plan_using("web", "tenant", "ccu", Phase::Failed)]),
            store_of(vec![static_inventory("ccu", "tenant", "ssh-key")]),
        );

        assert_eq!(mapper(secret_named("ssh-key", "tenant")).len(), 1);
    }

    /// A converged plan is left asleep. Rotating a key changes how the operator connects, not what
    /// it applies, so waking it could only re-apply a playbook to hosts that are already current —
    /// and the budget reset on the other side would decline anyway, by the same predicate.
    #[test]
    fn rotating_an_ssh_key_does_not_wake_a_plan_that_succeeded() {
        let mapper = ssh_secret_to_playbookplans(
            store_of(vec![plan_using("web", "tenant", "ccu", Phase::Succeeded)]),
            store_of(vec![static_inventory("ccu", "tenant", "ssh-key")]),
        );

        assert!(mapper(secret_named("ssh-key", "tenant")).is_empty());
    }

    /// Both hops are namespaced, and both must be checked: `inventoryRefs` are bare names resolved
    /// in the plan's own namespace, so two tenants may each own a `ccu` inventory and a `ssh-key`
    /// Secret, and neither may be woken by the other's rotation.
    #[test]
    fn an_ssh_key_rotation_stays_inside_its_namespace() {
        let mapper = ssh_secret_to_playbookplans(
            store_of(vec![
                plan_using("web", "tenant", "ccu", Phase::Failed),
                plan_using("web", "other", "ccu", Phase::Failed),
            ]),
            store_of(vec![
                static_inventory("ccu", "tenant", "ssh-key"),
                static_inventory("ccu", "other", "ssh-key"),
            ]),
        );

        let woken = mapper(secret_named("ssh-key", "tenant"));
        assert_eq!(woken.len(), 1);
        assert_eq!(woken[0].namespace.as_deref(), Some("tenant"));
    }

    /// A Secret that no `StaticInventory` names is not key material, whatever else it is — the plan
    /// store is not even consulted for it.
    #[test]
    fn a_secret_no_inventory_names_wakes_nothing_by_this_route() {
        let mapper = ssh_secret_to_playbookplans(
            store_of(vec![plan_using("web", "tenant", "ccu", Phase::Failed)]),
            store_of(vec![static_inventory("ccu", "tenant", "ssh-key")]),
        );

        assert!(mapper(secret_named("unrelated", "tenant")).is_empty());
    }

    /// One watch, two rules. The composed mapper is what the controller actually installs, so the
    /// union has to be pinned here rather than inferred from the halves: a Secret that is both a
    /// plan's `variables` source and an inventory's key reaches the plan by either route, and a
    /// plan that only holds the second must not be dropped because the first did not match.
    #[test]
    fn the_secret_watch_asks_both_rules() {
        let mut by_variables = plan_in("tenant", Vec::new());
        by_variables.metadata.name = Some("vars".into());
        by_variables.spec.template.variables =
            Some(vec![v1beta1::PlaybookVariableSource::SecretRef {
                secret_ref: v1beta1::SecretRef {
                    name: "ssh-key".into(),
                },
            }]);

        let mapper = secret_to_affected_playbookplans(
            store_of(vec![
                by_variables,
                plan_using("web", "tenant", "ccu", Phase::Failed),
            ]),
            store_of(vec![static_inventory("ccu", "tenant", "ssh-key")]),
        );

        let mut woken: Vec<String> = mapper(secret_named("ssh-key", "tenant"))
            .into_iter()
            .map(|object_ref| object_ref.name)
            .collect();
        woken.sort();
        assert_eq!(woken, vec!["vars".to_string(), "web".to_string()]);
    }

    #[test]
    fn a_plan_that_names_no_inventory_matches_nothing() {
        let plan = plan_in("tenant", Vec::new());

        assert!(!plan_references_inventory(
            &plan,
            Some("tenant"),
            "workers",
            cluster_inventory_name
        ));
    }
}
