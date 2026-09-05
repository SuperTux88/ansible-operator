use std::sync::Arc;

use k8s_openapi::api::core::v1::{Node, Secret};
use kube::runtime::reflector::{ObjectRef, Store};
use tracing::debug;

use crate::v1beta1::{
    self, ClusterInventory, InventoryRef, NodeAccessPolicy, StaticInventory,
    playbookplancontroller::node_readiness,
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
/// the cluster, scaling with the node count. Asking instead whether *this* plan still owes *this*
/// node a run makes a converged cluster cost nothing: no plan matches, and the heartbeats fall on
/// the floor. A plan that does have a stranded host is woken by that host's own heartbeats until it
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
            .filter(|plan| plan_awaits_node(plan, node_name))
            .map(|plan| ObjectRef::from(&**plan))
            .inspect(|obj_ref| {
                debug!("Reconcile of {obj_ref} triggered by node {node_name} becoming Ready");
            })
            .collect::<Vec<_>>()
    }
}

/// Whether `plan` targets `node` and has not yet applied its current revision to it.
///
/// Both halves are read from the plan's own status, which is what makes this answerable without a
/// cluster read: `eligibleHosts` is the host set the last reconcile resolved, and a host is owed a
/// run while the hash it last *succeeded* on is not the one the plan currently wants. A host with no
/// recorded status at all has never succeeded, so it is owed one too.
fn plan_awaits_node(plan: &v1beta1::PlaybookPlan, node: &str) -> bool {
    let Some(status) = plan.status.as_ref() else {
        return false;
    };

    let targeted = status
        .eligible_hosts
        .iter()
        .any(|group| group.hosts.iter().any(|host| host == node));

    targeted
        && status
            .hosts_status
            .as_ref()
            .and_then(|hosts| hosts.get(node))
            .is_none_or(|host| host.last_applied_hash != status.current_hash)
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
    use crate::v1beta1::{PlaybookPlan, PlaybookPlanSpec};

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

    #[test]
    fn a_plan_awaits_a_targeted_host_it_has_never_applied_to() {
        let plan = plan_with_status(v1beta1::PlaybookPlanStatus {
            eligible_hosts: eligible(&["node-a", "node-b"]),
            current_hash: "abc".into(),
            hosts_status: None,
            ..Default::default()
        });

        assert!(plan_awaits_node(&plan, "node-a"));
        assert!(plan_awaits_node(&plan, "node-b"));
    }

    #[test]
    fn a_plan_does_not_await_a_host_it_does_not_target() {
        let plan = plan_with_status(v1beta1::PlaybookPlanStatus {
            eligible_hosts: eligible(&["node-a"]),
            current_hash: "abc".into(),
            ..Default::default()
        });

        assert!(!plan_awaits_node(&plan, "node-b"));
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

        assert!(!plan_awaits_node(&plan, "node-a"));
        assert!(
            plan_awaits_node(&plan, "node-b"),
            "a host left behind by the current revision is still owed a run"
        );
    }

    #[test]
    fn a_plan_without_a_status_awaits_nothing() {
        let plan = PlaybookPlan::new("web", PlaybookPlanSpec::default());

        assert!(!plan_awaits_node(&plan, "node-a"));
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
