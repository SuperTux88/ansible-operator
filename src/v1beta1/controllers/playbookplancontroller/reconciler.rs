use chrono::{DateTime, FixedOffset, TimeZone, Utc};
use futures_util::{Stream, StreamExt as _};
use k8s_openapi::api::{
    batch::v1::Job,
    coordination::v1::Lease,
    core::v1::{Pod, Secret},
    networking::v1::NetworkPolicyEgressRule,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::{
    Api,
    api::{ListParams, Patch, PatchParams, PostParams},
    runtime::{
        Controller,
        controller::Action,
        reflector::{ObjectRef, Store, store::Writer},
        watcher,
    },
};
use std::{collections::BTreeMap, sync::Arc};
use tracing::{debug, error, info, warn};

use crate::v1beta1::{
    ActiveRun, AnsibleInventory, ClusterInventory, ExecutionMode, GenericMap, NodeAccessPolicy,
    Phase, Play, PlaybookPlanStatus, ResolvedHosts, ResolvedInventoryGroup, StaticInventory,
    Toleration, ansible, flatten_hosts, labels,
    playbookplancontroller::{
        execution_evaluator::{ExecutionHash, find_all_hosts},
        locking, managed_ssh,
        triggers::{Timing, evaluate_schedule, forecast_next_run},
        workspace::{self, render_secret},
    },
};
use crate::{
    utils::create_or_update,
    v1beta1::{
        self, PlaybookPlan,
        ca::CertificateAuthority,
        controllers::reconcile_error::{ReconcileError, is_conflict, is_not_found},
        playbookplancontroller::{
            callback_output,
            execution_evaluator::{self, find_outdated_hosts},
            job_builder, mappers, node_access, play_history, status,
        },
    },
};

/// Default grace window after a scheduled tick during which a run may still start, when the plan
/// does not set `spec.startingDeadlineSeconds`. See that field's docs.
const DEFAULT_STARTING_DEADLINE_SECONDS: u32 = 30;

pub struct WorkloadEgressPolicies {
    pub playbook: Option<Vec<NetworkPolicyEgressRule>>,
    pub managed_ssh: Option<Vec<NetworkPolicyEgressRule>>,
}

struct ReconciliationContext {
    client: kube::Client,
    /// Namespace the operator itself runs in — where per-run Leases and managed-ssh proxy pods
    /// live (never the PlaybookPlan's namespace). Read from `POD_NAMESPACE` at operator startup
    /// (see `main.rs`).
    operator_namespace: String,
    /// The admin-authored enrollment allowlist: the only namespaces the operator is RBAC-permitted
    /// to read/write Secrets and create Jobs in (R1 / T-INFO-1). A PlaybookPlan whose namespace is
    /// not in here is refused with `Phase::UnauthorizedNamespace` before any Secret/Job call. Always
    /// includes the operator namespace. Derived from the Helm-rendered config at startup (`config`).
    enrolled_namespaces: Arc<std::collections::BTreeSet<String>>,
    /// The operator's ephemeral SSH certificate authority — generated in memory at startup and
    /// never persisted, so an operator restart rotates it (see `main.rs`/`ca.rs`).
    ca: Arc<CertificateAuthority>,
    /// Reflector-backed cache of the admin-authored, cluster-scoped `NodeAccessPolicy` resources,
    /// read by `node_access::enforce` to clamp managed-ssh nodes without a per-reconcile list.
    /// Populated + kept fresh by the reflector spawned in `new`; policy edits also re-trigger
    /// affected plans via `mappers::node_access_policy_to_playbookplans`.
    node_access_policies: Arc<Store<NodeAccessPolicy>>,
    /// Image for the managed-ssh proxy pods (the node-root primitive — THREAT_MODEL T-ESC-5). Set by
    /// the admin via the chart's `managedSsh.proxyImage` (rendered to `proxy_image`); there is **no
    /// built-in default** — the operator refuses to start without it (see `config::require_proxy_image`
    /// / `main.rs`), so by the time a reconcile runs this is always a real, admin-chosen image.
    proxy_image: String,
    /// How long to wait for a `NotReady` node's proxy pod to become Ready before treating the node as
    /// unreachable, scaled by the node's heartbeat age. From the chart's `managedSsh.readiness`.
    proxy_grace: managed_ssh::ProxyGracePolicy,
    workload_egress_policies: WorkloadEgressPolicies,
}

/// Per-tick identifiers shared by `try_start_run` and `advance_applying_run`: the resource's
/// namespace/name, which hosts this run targets (flat, plus the same set grouped as `run_groups`),
/// its execution hash, and the Lease holder identity derived from them. Kube `Api<T>` handles are
/// deliberately *not* here — those are plumbing built on demand from `ReconciliationContext::client`
/// plus `namespace`, not run identity.
struct RunContext<'a> {
    namespace: &'a str,
    name: &'a str,
    execution_hash: ExecutionHash,
    hosts_to_trigger: &'a [String],
    /// This run's resolved inventory filtered to `hosts_to_trigger`, preserving the user's groups.
    /// Shared so the Job/proxy/render path and the Play history record see the same grouped set.
    run_groups: &'a [ResolvedInventoryGroup],
    holder_identity: &'a str,
}

pub fn new(
    client: kube::Client,
    operator_namespace: String,
    enrolled_namespaces: std::collections::BTreeSet<String>,
    ca: Arc<CertificateAuthority>,
    proxy_image: String,
    proxy_grace: managed_ssh::ProxyGracePolicy,
    workload_egress_policies: WorkloadEgressPolicies,
) -> impl Stream<
    Item = Result<
        (ObjectRef<v1beta1::PlaybookPlan>, Action),
        kube::runtime::controller::Error<ReconcileError, kube::runtime::watcher::Error>,
    >,
> {
    // PlaybookPlans are still watched cluster-wide so a plan created in a *non*-enrolled namespace is
    // seen and reported (`Phase::UnauthorizedNamespace`) rather than silently ignored (CRD reads stay
    // cluster-wide — see R1). Secret/Job watches below, by contrast, are scoped to the enrolled set.
    let playbookplans_api: Api<v1beta1::PlaybookPlan> = Api::all(client.clone());
    // NodeAccessPolicy is cluster-scoped (admin-authored via cluster RBAC); cache/watch all of them.
    let node_access_policies_api: Api<NodeAccessPolicy> = Api::all(client.clone());

    let enrolled_namespaces = Arc::new(enrolled_namespaces);

    let playbookplan_reflector_reader = {
        let playbookplan_reflector_writer = Writer::<v1beta1::PlaybookPlan>::default();
        let playbookplan_reflector_reader = Arc::new(playbookplan_reflector_writer.as_reader());

        let playbookplan_reflector = kube::runtime::reflector(
            playbookplan_reflector_writer,
            watcher(playbookplans_api.clone(), watcher::Config::default()),
        );

        tokio::spawn(async move {
            playbookplan_reflector
                .for_each(|event| async {
                    match event {
                        Ok(_) => {}
                        Err(e) => error!("Reflector error: {e:?}"),
                    }
                })
                .await;
        });

        playbookplan_reflector_reader
    };

    let node_access_policy_reflector_reader = {
        let writer = Writer::<NodeAccessPolicy>::default();
        let reader = Arc::new(writer.as_reader());

        let reflector = kube::runtime::reflector(
            writer,
            watcher(node_access_policies_api.clone(), watcher::Config::default()),
        );

        tokio::spawn(async move {
            reflector
                .for_each(|event| async {
                    if let Err(e) = event {
                        error!("NodeAccessPolicy reflector error: {e:?}");
                    }
                })
                .await;
        });

        reader
    };

    let context = Arc::new(ReconciliationContext {
        client: client.clone(),
        operator_namespace,
        enrolled_namespaces: Arc::clone(&enrolled_namespaces),
        ca,
        node_access_policies: Arc::clone(&node_access_policy_reflector_reader),
        proxy_image,
        proxy_grace,
        workload_egress_policies,
    });

    let mut controller = Controller::new(playbookplans_api, watcher::Config::default()).watches(
        node_access_policies_api,
        watcher::Config::default(),
        mappers::node_access_policy_to_playbookplans(Arc::clone(&playbookplan_reflector_reader)),
    );

    // Owned-Job and referenced-Secret watches are set up per enrolled namespace instead of once
    // cluster-wide: the operator holds `jobs`/`secrets` RBAC only in these namespaces (R1), so a
    // cluster-wide `Api::all` watch would 403. A Secret edit in an enrolled namespace still promptly
    // re-triggers its plan (preserving "input changed -> reapply"); the merged effect is identical to
    // the old single cluster-wide watch, just bounded to the allowlist.
    for namespace in enrolled_namespaces.iter() {
        let jobs_api: Api<Job> = Api::namespaced(client.clone(), namespace);
        let secrets_api: Api<Secret> = Api::namespaced(client.clone(), namespace);
        controller = controller
            .owns(jobs_api, watcher::Config::default())
            .watches(
                secrets_api,
                watcher::Config::default(),
                mappers::secret_to_playbookplans(Arc::clone(&playbookplan_reflector_reader)),
            );
    }

    controller.run(
        reconcile,
        |_, _, _| Action::requeue(std::time::Duration::from_secs(15)),
        Arc::clone(&context),
    )
}

/// Reconciles one PlaybookPlan. Level-triggered/idempotent "ensure" style — every step re-derives
/// what's needed from observed cluster state and short-circuits with a short `Action::requeue`
/// rather than a persisted "current step" state machine. Pipeline (each step re-run every tick):
///   0. resolve inventory, 1. compute outdated hosts/evaluate schedule, 2-5. `try_start_run`
///   (locks, managed-ssh proxy infra, workspace secret, the one Job), 6-7. `advance_applying_run`
///   (once the Job is finished: parse+record results, cleanup). A single tick can walk through
///   both halves — e.g. Pending -> locks acquired -> proxy ready -> Job created -> immediately
///   checked for completion — since nothing here is gated on a persisted step, only on `Phase`.
async fn reconcile(
    object: Arc<v1beta1::PlaybookPlan>,
    context: Arc<ReconciliationContext>,
) -> Result<Action, ReconcileError> {
    if object.metadata.deletion_timestamp.is_some() {
        return Ok(Action::await_change());
    }

    let (namespace, name) = namespace_and_name(&object)?;

    let api = Api::<v1beta1::PlaybookPlan>::namespaced(context.client.clone(), namespace);

    // Enrollment guard (R1 / T-INFO-1): the operator holds no Secret/Job RBAC outside the enrolled
    // set, so a plan in a non-enrolled namespace can never run. Refuse it up front — before any
    // (would-be-403) Secret/Job call — and report why. `await_change()`, not a timed requeue: the
    // enrolled set only changes on operator restart (a ConfigMap edit rolls the pod), so there is
    // nothing to poll for and a requeue would just busy-loop blocked plans.
    if !context.enrolled_namespaces.contains(namespace) {
        warn!(
            "PlaybookPlan {namespace}/{name} is in a namespace not enrolled for ansible-operator; refusing to run (add it to the chart's watchNamespaces)"
        );
        if object.status.as_ref().map(|s| &s.phase) != Some(&Phase::UnauthorizedNamespace) {
            let mut status = object.status.clone().unwrap_or_default();
            status.phase = Phase::UnauthorizedNamespace;
            status.summary = Some(format!(
                "namespace '{namespace}' is not enrolled for ansible-operator (not in watchNamespaces); an administrator must enroll it"
            ));
            patch_status(&api, &object, status).await?;
        }
        return Ok(Action::await_change());
    }

    // Name guard: the plan's name becomes a label value on every object a run creates, so a name the
    // CRD rule should have refused would instead fail at the first of those creates, blaming a label
    // the user never wrote. Refused here for the same reason and in the same shape as the enrollment
    // guard above — before any Play/Job/NetworkPolicy call, with `await_change()`, since an object's
    // name never changes and there is nothing to poll for.
    if !plan_name_within_label_limit(name) {
        warn!(
            "PlaybookPlan {namespace}/{name} has a name longer than {} characters; refusing to run",
            v1beta1::MAX_PLAN_NAME_LEN
        );
        if object.status.as_ref().map(|s| &s.phase) != Some(&Phase::Failed) {
            let mut status = object.status.clone().unwrap_or_default();
            status.phase = Phase::Failed;
            status.summary = Some(format!(
                "name is {} characters; a PlaybookPlan name must be at most {} because it is used as a label value on the objects each run creates. Recreate the plan under a shorter name",
                name.chars().count(),
                v1beta1::MAX_PLAN_NAME_LEN
            ));
            patch_status(&api, &object, status).await?;
        }
        return Ok(Action::await_change());
    }

    let secrets_api = Api::<Secret>::namespaced(context.client.clone(), namespace);

    let mut requeue_after = std::time::Duration::from_secs(3600);
    let mut retry_prune = false;
    let mut resource_status = object.status.clone().unwrap_or_default();
    // An attempt recovered before its Job exists, with the phase it was found in. It is dispatched
    // after inventory resolution rather than here, because deciding whether it may still be resumed
    // needs the resolved, policy-clamped groups its fingerprint covers.
    let mut unlaunched_run: Option<UnlaunchedRun> = None;
    let mut finished_active_run: Option<RecordedRun> = None;
    // Recovery drives the privileged parts of a run (Job creation, proxy infra, locks), so a failure
    // here aborts the tick before the final `patch_status`. Report it on the plan first, otherwise a
    // run that can't be recovered — a rejected Job, a revoked node grant — is only ever visible in
    // the operator's log. History retention is separate and is retried below even when no run needs
    // recovery.
    let recovered = match recover_active_run(&context, &object).await {
        Ok(recovered) => recovered,
        Err(error) => {
            resource_status.summary = Some(format!("run recovery failed: {error}"));
            if let Err(patch_error) = patch_status(&api, &object, resource_status).await {
                warn!("Could not report the recovery failure on {namespace}/{name}: {patch_error}");
            }
            return Err(error);
        }
    };
    // Set when the tick drained a finished run's result but the plan still has a live attempt behind
    // it: the plan is emphatically not finished, so the terminal classification below is skipped,
    // and the schedule window that attempt holds is what the plan records.
    let mut surviving_attempt: Option<SurvivingAttempt> = None;
    let mut finalized_run = false;
    if let Some(recovered) = recovered {
        match recovered {
            RecoveredRun::Active(run) => {
                adopt_recovered_attempt(&mut resource_status, &run.mirror);
            }
            RecoveredRun::Unlaunched(unlaunched) => {
                adopt_recovered_attempt(&mut resource_status, &unlaunched.run.mirror);
                unlaunched_run = Some(unlaunched);
            }
            RecoveredRun::Aborted(run) => {
                abandon_run(
                    &context,
                    &object,
                    &api,
                    &run,
                    format!("released the abandoned run {}", run.mirror.job_name),
                    &mut resource_status,
                )
                .await?;
            }
            RecoveredRun::Finished {
                finished,
                status,
                surviving,
            } => {
                status::apply_terminal_play_status(
                    &finished.execution_hash,
                    &status,
                    &mut resource_status,
                );
                match finalize_finished_run(
                    &context,
                    &object,
                    &api,
                    &finished,
                    // Drained straight off its own record, which is therefore still there to
                    // acknowledge — that acknowledgement is what stops it being drained again.
                    TerminalRecord::Present,
                    &mut resource_status,
                )
                .await
                {
                    Ok(prune_failed) => retry_prune |= prune_failed,
                    Err(error) => {
                        return Err(report_failed_finalization(
                            &api,
                            &object,
                            &finished,
                            &mut resource_status,
                            error,
                        )
                        .await);
                    }
                }
                finalized_run = true;
                finished_active_run = Some(finished);
                surviving_attempt = surviving;
            }
        }
    }

    // Step 0: resolve inventory (kept separate per-resource, not flattened — connection
    // mechanism is implicit by which resource produced a group).
    let mut target_groups = resolve_inventory(&context, &object).await?;

    // Step 0b: NodeAccessPolicy enforcement — clamp managed-ssh (ClusterInventory) nodes to what
    // this namespace is permitted to target, before eligible_hosts and any proxy infra derive from
    // them. Fail-closed: an ungoverned namespace resolves to zero managed-ssh nodes.
    let excluded_nodes = node_access::enforce(
        &context.client,
        &context.node_access_policies,
        namespace,
        &mut target_groups,
    )
    .await?;
    if !excluded_nodes.is_empty() {
        warn!(
            "NodeAccessPolicy excluded nodes {excluded_nodes:?} from {namespace}/{name} \
             (not granted to this namespace)"
        );
    }

    resource_status.eligible_hosts = flatten_hosts(&target_groups);

    // Inventory-author group variables are part of the execution hash (a change re-applies the
    // playbook to otherwise-current hosts). Keyed by group name; groups without variables
    // contribute nothing, so inventories that set none hash exactly as before.
    let inventory_variables: Vec<(&str, &serde_json::Value)> = target_groups
        .iter()
        .filter_map(|group| {
            group
                .variables()
                .map(|vars| (group.hosts().name.as_str(), &vars.0))
        })
        .collect();

    let related_secrets = get_related_secrets(&object);
    let execution_hash = hash_playbook_inputs(
        &object.spec.template.playbook,
        &related_secrets,
        &secrets_api,
        &inventory_variables,
    )
    .await;

    if resource_status.current_hash != execution_hash.to_string() {
        resource_status.phase = Phase::Pending;
        resource_status.current_hash = execution_hash.to_string();
        // A new spec version starts retry counting over from scratch.
        resource_status.retry_count = 0;
        // ...and may legitimately need to run in the same slot the old version already used, so
        // forget which slot was last triggered.
        resource_status.last_triggered_run = None;
    }

    // Step 1: compute outdated hosts / evaluate schedule — unchanged from before.
    let tz = object.timezone().unwrap();
    let now = || Utc::now().with_timezone(&tz);
    let time_window = chrono::Duration::seconds(
        object
            .spec
            .starting_deadline_seconds
            .unwrap_or(DEFAULT_STARTING_DEADLINE_SECONDS)
            .into(),
    );
    let timing = evaluate_schedule(object.spec.schedule.as_deref(), now(), time_window);
    let outdated_hosts = find_outdated_hosts(&resource_status, &execution_hash);
    let all_hosts = find_all_hosts(&resource_status);

    let hosts_to_trigger = match object.spec.mode {
        ExecutionMode::OneShot => outdated_hosts.clone(),
        ExecutionMode::Recurring => all_hosts.clone(),
    };

    // Filter the resolved inventory to this run's hosts once, preserving the user's groups, so the
    // Job/proxy/render path and the Play history record share one grouped view.
    let run_groups = filter_groups_to_hosts(&target_groups, &hosts_to_trigger);

    let holder_identity = format!("{namespace}/{name}/{execution_hash}");
    let run = RunContext {
        namespace,
        name,
        execution_hash,
        hosts_to_trigger: &hosts_to_trigger,
        run_groups: &run_groups,
        holder_identity: &holder_identity,
    };

    let eligible_to_start = is_eligible_to_start(
        object.spec.suspend,
        &object.spec.mode,
        object.spec.schedule.is_some(),
        !hosts_to_trigger.is_empty(),
    );

    if eligible_to_start && resource_status.phase != Phase::Applying {
        match timing {
            Timing::Delayed(until) => {
                requeue_after = (until - now()).to_std().unwrap();
                resource_status.phase = Phase::Scheduled;
                resource_status.next_run = Some(until.fixed_offset());
            }
            Timing::Now(start) => {
                let this_slot = start.map(|s| s.fixed_offset());

                if slot_already_triggered(this_slot, resource_status.last_triggered_run) {
                    // A run for this scheduled slot already started within its grace window;
                    // `evaluate_schedule` keeps returning `Now` for the rest of that window, so
                    // don't start another — sleep until the next slot instead. Without this a run
                    // that finishes inside its own grace window is immediately re-triggered.
                    if let Some(schedule) = object.spec.schedule.as_deref() {
                        let next =
                            forecast_next_run(schedule, now(), Some(chrono::Duration::seconds(-5)));
                        requeue_after = (next - now()).to_std().unwrap_or_default();
                        resource_status.next_run = Some(next.fixed_offset());
                    }
                } else if let Some(d) =
                    try_start_run(&context, &run, &object, &mut resource_status).await?
                {
                    requeue_after = d;
                } else {
                    // `try_start_run` ran to completion (the Job was created or an active one
                    // adopted, so `phase` is now `Applying`). Record this slot so it can't
                    // re-trigger inside its grace window. `None` for unscheduled plans, which have
                    // no slot and are never suppressed.
                    resource_status.last_triggered_run = this_slot;
                }
            }
        };
    }

    if resource_status.phase == Phase::Applying
        && let Some(d) = advance_applying_run(&context, &run, &object, &mut resource_status).await?
    {
        requeue_after = d;
    }

    // While suspended, don't advertise a next run: the start gate above already blocks new runs, so
    // a `nextRun` pointing at a slot that won't fire would be misleading. Applied after the advance
    // step so it also clears the next slot a just-finished Recurring run would have set. A run still
    // in progress is untouched (it has no `nextRun` anyway) and is left to finish; the phase keeps
    // reflecting the plan's real state, with the `Suspended` printer column (from `.spec.suspend`)
    // signalling the pause. The schedule path recomputes `nextRun` once the plan resumes.
    if object.spec.suspend {
        resource_status.next_run = None;
    }

    patch_status(&api, &object, resource_status).await?;

    Ok(Action::requeue(requeue_after))
}

/// Whether the current schedule slot (`start`, the grace window's start) already had a run started
/// for it, per the persisted `last_triggered_run`. Unscheduled ticks carry no slot (`None`) and are
/// never suppressed — there is nothing to dedupe against. `DateTime` equality compares instants, so
/// the offset the two timestamps carry is irrelevant.
fn slot_already_triggered(
    start: Option<DateTime<FixedOffset>>,
    last_triggered_run: Option<DateTime<FixedOffset>>,
) -> bool {
    start.is_some() && start == last_triggered_run
}

/// Whether a run is eligible to *start* this tick, from whether the plan is suspended plus the mode,
/// whether a schedule is set, and whether any hosts still need triggering. Pure so the gating is
/// unit-testable — in particular the invariants that a suspended plan never starts and that a
/// schedule-less Recurring plan is never eligible.
///
///   - `suspend` is an operator override (`spec.suspend`, CronJob-style): while set, nothing starts,
///     regardless of mode/schedule/hosts. It only gates *starting* — an in-flight run finishes on
///     its own path (`advance_applying_run`), which is not routed through here.
///   - OneShot keeps applying until every host is on the current hash, then goes quiet — so it's
///     gated purely on there being outdated hosts left (which is exactly `has_hosts_to_trigger`).
///   - Recurring runs on every schedule tick regardless of host hashes (a successful run marks all
///     hosts up-to-date, so an outdated-based gate would fire once and never again). It's gated only
///     on having a schedule to tick on; slot dedup via `last_triggered_run` is what stops a single
///     tick from starting more than one run, and without a schedule there'd be no slot to dedup
///     against — it would busy-loop. That's why the schedule check lives here.
fn is_eligible_to_start(
    suspended: bool,
    mode: &ExecutionMode,
    has_schedule: bool,
    has_hosts_to_trigger: bool,
) -> bool {
    !suspended
        && has_hosts_to_trigger
        && match mode {
            ExecutionMode::OneShot => true,
            ExecutionMode::Recurring => has_schedule,
        }
}

/// Steps 2-5: acquire this run's per-host locks (all-or-nothing, renewed every tick for as long
/// as the run is in progress), ensure managed-ssh proxy infra is Ready, ensure the workspace
/// secret reflects this run, then ensure the one Job exists. Each guard clause returns early with
/// a short requeue the moment a precondition isn't met yet; `None` means it ran to completion
/// (the Job either already existed or was just created — see `spawn_ansible_job`).
async fn try_start_run(
    context: &ReconciliationContext,
    run: &RunContext<'_>,
    object: &PlaybookPlan,
    resource_status: &mut PlaybookPlanStatus,
) -> Result<Option<std::time::Duration>, ReconcileError> {
    let secrets_api = Api::<Secret>::namespaced(context.client.clone(), run.namespace);
    let jobs_api = Api::<Job>::namespaced(context.client.clone(), run.namespace);
    let leases_api = Api::<Lease>::namespaced(context.client.clone(), &context.operator_namespace);

    let run_groups = run.run_groups;

    if let Some(blocked) =
        locking::ensure_locks(&leases_api, run.hosts_to_trigger, run.holder_identity).await?
    {
        warn!(
            "PlaybookPlan {}/{} is blocked: host '{}' is locked by {}",
            run.namespace,
            run.name,
            blocked.host,
            blocked.holder.as_deref().unwrap_or("another run"),
        );
        status::set_blocked_condition(resource_status, Some(&blocked));
        return Ok(Some(std::time::Duration::from_secs(15)));
    }
    // Locks are ours this tick — clear any stale Blocked condition from a previous contended tick.
    status::set_blocked_condition(resource_status, None);

    let (managed_ssh_hosts, tolerations) = managed_ssh_hosts_and_tolerations(run_groups);

    // Owns the plan-namespace client-cert Secret so K8s GC reaps it if the plan is deleted before
    // cleanup runs (the explicit per-run delete in `cleanup_proxy_infra` is the primary path).
    let plan_owner = playbookplan_owner_ref(object)?;

    // This attempt's run ID — the identity every run-scoped resource is keyed on.
    let run_id = run_id(object, &run.execution_hash)?;

    let proxy_readiness = managed_ssh::ensure_proxy_infra(
        &context.client,
        &context.operator_namespace,
        run.namespace,
        &run.execution_hash,
        &run_id,
        &managed_ssh_hosts,
        tolerations.as_deref(),
        &context.proxy_grace,
        &context.ca,
        &context.proxy_image,
        context.workload_egress_policies.managed_ssh.clone(),
        &plan_owner,
    )
    .await?;

    let (proxy_infos, unreachable_hosts) = match proxy_readiness {
        managed_ssh::ProxyReadiness::Pending { waiting } => {
            debug!("Waiting for managed-ssh proxy pods to become Ready on {waiting:?}");
            status::set_waiting_for_nodes_condition(resource_status, Some(&waiting));
            return Ok(Some(std::time::Duration::from_secs(5)));
        }
        managed_ssh::ProxyReadiness::Ready { ready, unreachable } => {
            status::set_waiting_for_nodes_condition(resource_status, None);
            (ready, unreachable)
        }
    };

    if !unreachable_hosts.is_empty() {
        warn!(
            "PlaybookPlan {}/{}: proceeding without node(s) {:?} — their managed-ssh proxy pods never became Ready within the grace window; Ansible will report them unreachable, and they'll be retried on the next run",
            run.namespace, run.name, unreachable_hosts,
        );
    }

    let mut managed_ssh_hosts_map: BTreeMap<String, ansible::ManagedSshHostInfo> = proxy_infos
        .into_iter()
        .map(|p| {
            (
                p.host,
                ansible::ManagedSshHostInfo {
                    pod_ip: p.pod_ip,
                    port: p.port,
                    unreachable: false,
                },
            )
        })
        .collect();

    // Hosts whose proxy never became Ready in time have no pod IP; point Ansible at the unroutable
    // sentinel (with a short connect timeout, see inventory_renderer) so it records them unreachable.
    for host in unreachable_hosts {
        managed_ssh_hosts_map.insert(
            host,
            ansible::ManagedSshHostInfo {
                pod_ip: managed_ssh::UNREACHABLE_SENTINEL_IP.to_string(),
                port: managed_ssh::PROXY_SSH_PORT,
                unreachable: true,
            },
        );
    }

    // Proxy pod IPs are fresh every run even with an unchanged spec, so rendering is also
    // triggered on "a run is starting now", not generation alone.
    if workspace::is_missing(&secrets_api, run.name).await? || workspace::is_outdated(object, true)
    {
        debug!("Rendering playbook to secret");
        upsert_workspace_secret(
            &secrets_api,
            run.name,
            render_secret(object, run_groups, &managed_ssh_hosts_map)?,
        )
        .await?;
        resource_status.last_rendered_generation = object.metadata.generation;
    }

    if let Some(network_policy_egress) = context.workload_egress_policies.playbook.clone() {
        job_builder::ensure_job_network_policy(
            context.client.clone(),
            &context.operator_namespace,
            &run.execution_hash,
            &run_id,
            run_groups,
            object,
            network_policy_egress,
        )
        .await?;
    }

    spawn_ansible_job(
        &jobs_api,
        run.execution_hash,
        &run_id,
        run_groups,
        object,
        resource_status,
    )
    .await?;

    // Record this attempt as a Play (history), named after the Job spawn just settled on. The
    // attempt number is `retry_count`, which `spawn_ansible_job` set for exactly this Job.
    if let Some(job_name) = resource_status.current_job_name.as_deref() {
        let inventory = flatten_hosts(run.run_groups);
        play_history::record_running(
            &context.client,
            run.namespace,
            &play_history::PlayRef {
                plan: object,
                job_name,
                hash: &run.execution_hash,
                attempt: resource_status.retry_count,
                inventory: &inventory,
                hosts: run.hosts_to_trigger,
            },
        )
        .await?;
    }

    Ok(None)
}

/// Narrows what was found at a run's record name to what is actually *this run's* record.
///
/// A different object under the name is the same fact as no object at all — the recorded run is gone
/// — so both answer `None` and both reach `finalize_lost_run`, which reconstructs the result from the
/// plan's own copy of the run. Pure so the equivalence stays pinned: it is what keeps a replacement
/// attempt from being finalized, acknowledged or pruned as though it were the run it replaced.
fn own_record(found: Option<Play>, expected_uid: &str) -> Option<Play> {
    found.filter(|play| play.metadata.uid.as_deref() == Some(expected_uid))
}

/// Whether the plan's `activeRun` mirror is `run`'s — the question both paths that *stop* driving a
/// run have to answer before clearing it ([`finalize_finished_run`], [`abandon_run`]).
///
/// An absent mirror answers yes: the tick that finishes a run clears it before either path is reached
/// (`advance_active_run`), and that case still has to reset the phase. What the guard excludes is a mirror
/// describing a *different* attempt, which is genuinely in flight and is the only thing that would
/// bring it to [`finalize_lost_run`] if its `Play` were deleted. Clearing that would leave its host
/// Leases and node-root proxy pods with nothing pointing at them.
///
/// Pure, and shared, so the two paths cannot drift: the guard was only ever reasoned about on the
/// finalize side, while `abandon_run` reaches the same fields from `recover_active_run`'s `Aborted`
/// branch — the one path that adopts no attempt first.
fn mirrors_run(status: &PlaybookPlanStatus, run: &RecordedRun) -> bool {
    status
        .active_run
        .as_ref()
        .is_none_or(|mirrored| mirrored.play_uid == run.mirror.play_uid)
}

/// Whether this run's record has reached `Running`, the only phase that may enter Job finalization.
/// Earlier phases belong to absent-Job recovery, including when a tick just drained another run's
/// terminal result while the plan status mirrors this one.
///
/// The UID is checked by the caller rather than here, because a record that no longer carries it is
/// not a wrong *phase* — it is a different object at the same name, which says the recorded run is
/// gone.
fn play_is_running_attempt(play: &Play) -> Result<bool, ReconcileError> {
    let status = play
        .status
        .as_ref()
        .ok_or(ReconcileError::PreconditionFailed(
            "active Play has no status",
        ))?;
    Ok(status.phase == v1beta1::PlayPhase::Running)
}

/// Steps 6-7: once this run's Job (recorded as `current_job_name`) is `Complete`/`Failed`, parses
/// its logs for per-host outcomes, records them, tears down this run's locks/proxy infra, and
/// advances `phase` to whatever comes next for this `ExecutionMode`. Returns `None` if there's
/// nothing to do yet (no Job recorded, or it hasn't reached a terminal state) or if advancing
/// shouldn't change the requeue duration (e.g. a terminal `OneShot` outcome) — the caller only
/// overrides its requeue duration when this returns `Some`.
async fn advance_applying_run(
    context: &ReconciliationContext,
    run: &RunContext<'_>,
    object: &PlaybookPlan,
    resource_status: &mut PlaybookPlanStatus,
) -> Result<Option<std::time::Duration>, ReconcileError> {
    let jobs_api = Api::<Job>::namespaced(context.client.clone(), run.namespace);
    let leases_api = Api::<Lease>::namespaced(context.client.clone(), &context.operator_namespace);

    // Looked up by the exact recorded name, not the PLAYBOOKPLAN_HASH label — that label is
    // stable across every retry of an unchanged spec, so a label-only `list()` could return
    // an older, already-finished retry's Job instead of the one this run just created.
    let Some(job_name) = resource_status.current_job_name.clone() else {
        return Ok(None);
    };
    let job = jobs_api.get_opt(&job_name).await?;

    // Still running -> renew this run's host locks so a run that outlasts the lease duration keeps
    // them (they're acquired once at start and otherwise never touched again while Applying), then
    // keep waiting.
    if let Some(job) = &job
        && !status::job_finished(job)
    {
        let _outcome =
            locking::renew_locks(&leases_api, run.hosts_to_trigger, run.holder_identity).await?;
        status::evaluate_playbookplan_conditions(
            run.hosts_to_trigger,
            false,
            None,
            resource_status,
        );
        return Ok(Some(std::time::Duration::from_secs(15)));
    }

    // The Job either finished, or is already gone — reaped by Kubernetes' TTL controller (its result
    // outlived a long operator outage) or deleted out from under us. Both mean the run is over: read
    // the recap from the pod's termination message if the Job is still there, otherwise the outcome
    // is lost and every host falls to `Unknown`. Not returning early on a missing Job is what keeps
    // a reaped run from wedging in `Applying` forever. The recap comes from the container's
    // termination message (what the callback wrote to /dev/termination-log), not logs — a dedicated
    // channel that isn't interleaved with playbook output and needs no `pods/log` access.
    let parsed = match &job {
        Some(_) => {
            let pods_api: Api<Pod> = Api::namespaced(context.client.clone(), run.namespace);
            pods_api
                .list(&ListParams {
                    label_selector: Some(format!("job-name={job_name}")),
                    ..Default::default()
                })
                .await?
                .items
                .iter()
                .find_map(termination_message)
                .as_deref()
                .and_then(callback_output::parse_callback_output)
        }
        None => None,
    };

    status::evaluate_host_outcomes(
        run.hosts_to_trigger,
        parsed.as_ref(),
        &run.execution_hash,
        resource_status,
    );
    status::evaluate_playbookplan_conditions(
        run.hosts_to_trigger,
        true,
        parsed.as_ref(),
        resource_status,
    );

    // Stamp the terminal recap onto this attempt's Play (durable run history), then prune old ones.
    let inventory = flatten_hosts(run.run_groups);
    play_history::record_finished(
        &context.client,
        run.namespace,
        &play_history::PlayRef {
            plan: object,
            job_name: &job_name,
            hash: &run.execution_hash,
            attempt: resource_status.retry_count,
            inventory: &inventory,
            hosts: run.hosts_to_trigger,
        },
        parsed.as_ref(),
    )
    .await?;
    play_history::prune(&context.client, run.namespace, object).await?;

    // The attempt's run ID travels on the Job's labels for now; cleanup needs it to address this
    // attempt's proxy resources. A reaped Job takes the ID with it — that sweep is then a no-op and
    // the plan-owned client-cert Secret falls back to Kubernetes GC.
    let job_run_id = job
        .as_ref()
        .and_then(|job| job.metadata.labels.as_ref())
        .and_then(|job_labels| job_labels.get(labels::RUN_ID))
        .cloned()
        .unwrap_or_default();
    managed_ssh::cleanup_proxy_infra(
        &context.client,
        &context.operator_namespace,
        run.namespace,
        &run.execution_hash,
        &job_run_id,
        run.name,
    )
    .await?;
    locking::release_locks(&leases_api, run.hosts_to_trigger, run.holder_identity).await?;

    let total_count: usize = resource_status
        .eligible_hosts
        .iter()
        .map(|g| g.hosts.len())
        .sum();
    let outdated_count = find_outdated_hosts(resource_status, &run.execution_hash).len();

    // Recurring with no schedule can't reschedule; the eligibility gate normally stops such a plan
    // from ever starting, so reaching here means the schedule was removed mid-run. Log the anomaly —
    // `decide_terminal` deliberately leaves the plan in `Applying` for this case.
    if matches!(object.spec.mode, ExecutionMode::Recurring) && object.spec.schedule.is_none() {
        warn!("Mode is Recurring but schedule is not set!");
    }

    let outcome = decide_terminal(
        &object.spec.mode,
        object.spec.schedule.as_deref(),
        outdated_count,
        total_count,
        Utc::now().with_timezone(&object.timezone().unwrap()),
    );

    resource_status.summary = Some(outcome.summary);
    resource_status.phase = outcome.phase;
    resource_status.next_run = outcome.next_run;

    Ok(outcome.requeue)
}

/// The terminal-state decision for a finished run: what the plan's `phase`, `next_run`, `summary`,
/// and the caller's requeue duration become once this run's Job has reached a terminal state. Pure
/// (every wall-clock/inventory input is passed in) so the per-mode matrix is unit-testable without a
/// kube client:
///   - OneShot resolves to `Succeeded`/`Failed` solely by whether any host is still outdated and
///     never reschedules.
///   - Recurring with a schedule reschedules to the next slot and requeues until then.
///   - Recurring *without* a schedule is the dead-end the eligibility gate normally prevents (the
///     caller logs it): nothing to reschedule against, so the plan stays `Applying`.
struct TerminalOutcome {
    phase: Phase,
    next_run: Option<DateTime<FixedOffset>>,
    summary: String,
    requeue: Option<std::time::Duration>,
}

fn decide_terminal<Tz: TimeZone>(
    mode: &ExecutionMode,
    schedule: Option<&str>,
    outdated_count: usize,
    total_count: usize,
    now: DateTime<Tz>,
) -> TerminalOutcome {
    let summary = match outdated_count {
        0 => format!("{total_count}/{total_count} up-to-date"),
        n => format!("{n}/{total_count} outdated"),
    };

    match mode {
        ExecutionMode::OneShot => TerminalOutcome {
            phase: if outdated_count == 0 {
                Phase::Succeeded
            } else {
                Phase::Failed
            },
            next_run: None,
            summary,
            requeue: None,
        },
        ExecutionMode::Recurring => match schedule {
            Some(schedule) => {
                let next =
                    forecast_next_run(schedule, now.clone(), Some(chrono::Duration::seconds(-5)));
                let requeue = (next.clone() - now).to_std().ok();
                TerminalOutcome {
                    phase: Phase::Scheduled,
                    next_run: Some(next.fixed_offset()),
                    summary,
                    requeue,
                }
            }
            // Any prior forecast is now unreachable, so clear `next_run` and hold at `Applying`.
            None => TerminalOutcome {
                phase: Phase::Applying,
                next_run: None,
                summary,
                requeue: None,
            },
        },
    }
}

/// The `ansible-playbook` container's termination message — the recap the callback wrote to
/// `/dev/termination-log`, surfaced by the kubelet as `state.terminated.message`. `None` if the
/// pod has no such terminated container yet or it wrote nothing (hard crash before the stats hook).
fn termination_message(pod: &Pod) -> Option<String> {
    pod.status
        .as_ref()?
        .container_statuses
        .as_ref()?
        .iter()
        .find(|cs| cs.name == job_builder::ANSIBLE_CONTAINER_NAME)
        .and_then(|cs| cs.state.as_ref())
        .and_then(|state| state.terminated.as_ref())
        .and_then(|terminated| terminated.message.clone())
}

/// Filters a run's resolved groups down to only the hosts actually targeted this run
/// (`hosts_to_trigger`), preserving group membership so `serial:`/native grouping in the user's
/// playbook still means something — a single run's Job/inventory only ever targets this subset,
/// not the plan's full `eligible_hosts`.
fn filter_groups_to_hosts(
    groups: &[ResolvedInventoryGroup],
    hosts_to_trigger: &[String],
) -> Vec<ResolvedInventoryGroup> {
    let allowed: std::collections::HashSet<&str> =
        hosts_to_trigger.iter().map(String::as_str).collect();

    groups
        .iter()
        .filter_map(|group| {
            let hosts = group.hosts();
            let filtered_hostnames: Vec<String> = hosts
                .hosts
                .iter()
                .filter(|h| allowed.contains(h.as_str()))
                .cloned()
                .collect();

            if filtered_hostnames.is_empty() {
                return None;
            }

            let mut filtered_hosts = hosts.clone();
            filtered_hosts.hosts = filtered_hostnames;

            Some(match group {
                ResolvedInventoryGroup::ManagedSsh {
                    tolerations,
                    variables,
                    ..
                } => ResolvedInventoryGroup::ManagedSsh {
                    hosts: filtered_hosts,
                    tolerations: tolerations.clone(),
                    variables: variables.clone(),
                },
                ResolvedInventoryGroup::Ssh {
                    static_inventory_name,
                    config,
                    variables,
                    ..
                } => ResolvedInventoryGroup::Ssh {
                    hosts: filtered_hosts,
                    static_inventory_name: static_inventory_name.clone(),
                    config: config.clone(),
                    variables: variables.clone(),
                },
            })
        })
        .collect()
}

/// Flat list of managed-ssh-sourced hostnames in these groups, plus the tolerations to use for
/// their proxy pods. If a run spans multiple ClusterInventory resources with different
/// tolerations, only the first non-`None` one found is used for all of them.
fn managed_ssh_hosts_and_tolerations(
    groups: &[ResolvedInventoryGroup],
) -> (Vec<String>, Option<Vec<Toleration>>) {
    let mut hosts = Vec::new();
    let mut tolerations = None;

    for group in groups {
        if let ResolvedInventoryGroup::ManagedSsh {
            hosts: h,
            tolerations: t,
            ..
        } = group
        {
            hosts.extend(h.hosts.clone());
            if tolerations.is_none() {
                tolerations = t.clone();
            }
        }
    }

    (hosts, tolerations)
}

async fn upsert_workspace_secret(
    api: &Api<Secret>,
    secret_name: &str,
    secret: Secret,
) -> Result<(), ReconcileError> {
    Ok(create_or_update(
        api,
        "ansible-operator",
        secret_name,
        secret,
        |existing, desired_state| {
            desired_state.metadata.managed_fields = None;

            // `string_data` contains our new or updated keys. If they exist in `data`, remove them from there so that `string_data` can take precedence.
            desired_state.data = {
                const EMPTY: &BTreeMap<String, String> = &BTreeMap::new();
                let desired_data = desired_state.string_data.as_ref().unwrap_or(EMPTY);

                existing.data.map(|d| {
                    BTreeMap::from_iter(
                        d.into_iter()
                            .filter(|(key, _)| !desired_data.contains_key(key)),
                    )
                })
            };
        },
    )
    .await?)
}

/// Returns a list of all secret names that the given PlaybookPlan references (e.g. secrets used
/// as Ansible variables).
///
/// Deliberately excludes the workspace secret itself — its content legitimately differs on every
/// run even with an unchanged spec (managed-ssh proxy pod IPs are baked into inventory.yml), so
/// including it here would make `execution_hash` unstable across otherwise-identical runs and
/// break naming consistency for proxy infra/Job labels/lock identity mid-run. Workspace-secret
/// staleness is handled independently via `workspace::is_outdated`/`is_missing`.
fn get_related_secrets(playbookplan: &PlaybookPlan) -> Vec<&String> {
    job_builder::extract_secret_names_for_variables(playbookplan)
        .chain(job_builder::extract_secret_names_for_files(playbookplan))
        .collect()
}

/// Persists `status` via a JSON merge patch, not `Api::replace_status` (a PUT requiring
/// `resourceVersion` to exactly match the server's current one). This reconcile function spans
/// many async steps between reading `target` and this final write, long enough that a concurrent
/// write to the same object routinely lands first and would reject a version-checked PUT with a
/// 409. A merge patch carries no such precondition.
async fn patch_status(
    api: &Api<PlaybookPlan>,
    target: &PlaybookPlan,
    status: PlaybookPlanStatus,
) -> Result<(), ReconcileError> {
    use kube::runtime::reflector::Lookup as _;

    let name = target
        .name()
        .ok_or(ReconcileError::PreconditionFailed("name not set"))?;

    api.patch_status(
        &name,
        &PatchParams::default(),
        &Patch::Merge(serde_json::json!({ "status": status })),
    )
    .await?;

    Ok(())
}

async fn hash_playbook_inputs(
    playbook: &str,
    secret_names: &[&String],
    secrets_api: &Api<Secret>,
    inventory_variables: &[(&str, &serde_json::Value)],
) -> ExecutionHash {
    let secrets = futures::future::join_all(
        secret_names
            .iter()
            .map(|secret_name| secrets_api.get(secret_name)),
    )
    .await;

    let variables_secrets: Vec<BTreeMap<_, _>> = secrets
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .filter_map(|secret| secret.data.clone())
        .collect();

    execution_evaluator::calculate_execution_hash(playbook, variables_secrets.iter())
        .fold_inventory_variables(inventory_variables.iter().copied())
}

/// Resolves every inventory this PlaybookPlan references into `ResolvedInventoryGroup`s,
/// preserving which resource (and therefore which connection mechanism + config) each group of
/// hosts came from — `ClusterInventory` always implies managed-ssh, `StaticInventory` always
/// implies its own embedded SSH config. Not flattened into a single list, since downstream steps
/// (locking, proxy pods, inventory rendering, job building) need to know which mechanism applies
/// to which group.
async fn resolve_inventory(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
) -> Result<Vec<ResolvedInventoryGroup>, ReconcileError> {
    use kube::ResourceExt;

    let namespace = object
        .namespace()
        .ok_or(ReconcileError::PreconditionFailed("namespace not set"))?;

    let cluster_inventory_api: Api<ClusterInventory> =
        Api::namespaced(context.client.clone(), &namespace);
    let static_inventory_api: Api<StaticInventory> =
        Api::namespaced(context.client.clone(), &namespace);

    let inventory_refs = &object.spec.inventory_refs;

    let cluster_inventories = inventory_refs
        .iter()
        .filter_map(|inventory_ref| inventory_ref.cluster_inventory.as_ref())
        .map(|name| cluster_inventory_api.get(name));

    let (cluster_inventories, errors): (Vec<_>, Vec<_>) =
        futures::future::join_all(cluster_inventories)
            .await
            .into_iter()
            .partition(Result::is_ok);

    let cluster_inventory_errors: Vec<_> = errors.into_iter().map(Result::unwrap_err).collect();

    let static_inventories = inventory_refs
        .iter()
        .filter_map(|inventory_ref| inventory_ref.static_inventory.as_ref())
        .map(|name| static_inventory_api.get(name));

    let (static_inventories, errors): (Vec<_>, Vec<_>) =
        futures::future::join_all(static_inventories)
            .await
            .into_iter()
            .partition(Result::is_ok);

    let static_inventory_errors: Vec<_> = errors.into_iter().map(Result::unwrap_err).collect();

    let mut all_errors = cluster_inventory_errors
        .into_iter()
        .chain(static_inventory_errors);

    if let Some(first) = all_errors.next() {
        return Err(ReconcileError::KubeError(first));
    }

    let mut groups = Vec::new();

    for ci in cluster_inventories.into_iter().map(Result::unwrap) {
        let tolerations = ci.spec.tolerations.clone();
        // Group variables live on the spec's InventoryHosts, but get_hosts() returns the resolved
        // node lists from status; re-join them by group name.
        let variables_by_group: BTreeMap<&str, &GenericMap> = ci
            .spec
            .hosts
            .iter()
            .filter_map(|group| group.variables.as_ref().map(|v| (group.name.as_str(), v)))
            .collect();
        for hosts in ci.get_hosts() {
            let variables = variables_by_group
                .get(hosts.name.as_str())
                .copied()
                .cloned();
            reject_reserved_variables(&hosts.name, variables.as_ref())?;
            groups.push(ResolvedInventoryGroup::ManagedSsh {
                hosts,
                tolerations: tolerations.clone(),
                variables,
            });
        }
    }

    for si in static_inventories.into_iter().map(Result::unwrap) {
        let static_inventory_name = si.name_any();
        let config = si.spec.ssh.clone();
        for group in &si.spec.hosts {
            reject_reserved_variables(&group.name, group.variables.as_ref())?;
            groups.push(ResolvedInventoryGroup::Ssh {
                hosts: ResolvedHosts {
                    name: group.name.clone(),
                    hosts: group.hosts.clone(),
                },
                static_inventory_name: static_inventory_name.clone(),
                config: config.clone(),
                variables: group.variables.clone(),
            });
        }
    }

    Ok(groups)
}

/// Fails the reconcile if an inventory group sets a variable the operator manages for
/// connection/isolation (see [`ansible::RESERVED_HOST_VARS`]). Runs at resolve time, before any
/// proxy infra or hashing, so a bad inventory surfaces as a clear error rather than a silently
/// ignored setting or broken connection.
fn reject_reserved_variables(
    group_name: &str,
    variables: Option<&GenericMap>,
) -> Result<(), ReconcileError> {
    if let Some(variables) = variables
        && let Some(key) = ansible::first_reserved_var(&variables.0)
    {
        return Err(ReconcileError::ReservedInventoryVariable {
            group: group_name.to_string(),
            key: key.to_string(),
        });
    }
    Ok(())
}

/// Builds an `OwnerReference` to this PlaybookPlan for the plan-namespace resources it owns (the
/// per-run managed-ssh client-cert Secret), so Kubernetes GC reaps them if the plan is deleted
/// before explicit cleanup runs. Same pattern/namespace as the workspace secret
/// (`workspace::render_secret`); a cross-namespace ownerReference would be ignored by GC, which is
/// why the operator-namespace proxy infra uses label cleanup instead.
pub(crate) fn playbookplan_owner_ref(
    object: &PlaybookPlan,
) -> Result<OwnerReference, ReconcileError> {
    use kube::runtime::reflector::Lookup as _;
    Ok(OwnerReference {
        api_version: PlaybookPlan::api_version(&()).into(),
        kind: PlaybookPlan::kind(&()).into(),
        name: object
            .name()
            .ok_or(ReconcileError::PreconditionFailed("name not set"))?
            .into(),
        uid: object
            .uid()
            .ok_or(ReconcileError::PreconditionFailed("uid not set"))?
            .into(),
        ..Default::default()
    })
}

/// Puts a recovered attempt back onto the plan's status: the run itself, the `Applying` phase it
/// implies, and — only while the attempt applies the currently desired revision — the retry number
/// it reached, which is what stops a later attempt from reusing its name.
fn adopt_recovered_attempt(status: &mut PlaybookPlanStatus, active_run: &ActiveRun) {
    if status.current_hash == active_run.execution_hash {
        status.retry_count = status.retry_count.max(active_run.attempt);
    }
    status.current_job_name = Some(active_run.job_name.clone());
    status.phase = Phase::Applying;
    status.summary = Some(format!("applying run {}", active_run.job_name));
    status.active_run = Some(active_run.clone());
}

/// A run the operator is driving this tick: the mirror the plan's status carries for it, plus the
/// execution hash parsed back out of that mirror once.
///
/// `ActiveRun` is a status type, so it stores the hash as the canonical lowercase-hex string the CRD
/// holds, while every step that names a resource after the run wants the typed value. Parsing it
/// where a run *enters* the tick — out of its `Play`, or out of the status mirror — is what keeps
/// that conversion, and its single "the status was hand-edited" failure, in one place rather than at
/// each of the steps that consume it.
#[derive(Clone)]
struct RecordedRun {
    /// What the plan's status mirrors about this run — see [`ActiveRun`].
    mirror: ActiveRun,
    /// The revision this run applies, typed. Always round-trips: `ActiveRun` is only ever built
    /// from an `ExecutionHash`.
    execution_hash: ExecutionHash,
}

impl RecordedRun {
    /// Reconstructs a run from the plan status' mirror of it — the one path that does not start
    /// from a `Play`, and so the one place a hand-edited status is caught.
    fn from_mirror(mirror: ActiveRun) -> Result<Self, ReconcileError> {
        let execution_hash = ExecutionHash::from_hex(&mirror.execution_hash).ok_or(
            ReconcileError::PreconditionFailed("run has an invalid execution hash"),
        )?;
        Ok(Self {
            mirror,
            execution_hash,
        })
    }
}

/// Recovers only records created by the current Prepared-before-Job protocol. Statusless objects
/// never crossed the operator-owned status boundary and are deleted; old untracked Jobs and Plays
/// are deliberately ignored because this project has no released state to migrate.
///
/// A plan has at most one run *in flight*, so at most one record can describe one. That is an
/// invariant of the protocol rather than something this function tolerates: if a second one shows
/// up, the tick refuses to do anything instead of picking one and silently orphaning the other —
/// which would leave the loser's node-root proxy pods unswept with nothing left pointing at them.
/// (Their host Leases are renewed first, so refusing is safe; see `renew_contested_locks`.)
///
/// A terminal record whose result has not reached the plan yet does *not* count towards that
/// invariant and is drained ahead of it: it owns no cluster resources any more, and handing its
/// recap over is what allows the plan to move on at all.
async fn recover_active_run(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
) -> Result<Option<RecoveredRun>, ReconcileError> {
    let client = &context.client;
    let (namespace, plan_name) = namespace_and_name(object)?;
    let plays_api = Api::<Play>::namespaced(client.clone(), namespace);
    let plays = plays_api
        .list(&ListParams::default().labels(&format!("{}={plan_name}", labels::PLAYBOOKPLAN_NAME)))
        .await?;
    let recoverable = recoverable_plays_for_plan(&plays.items, object);

    // Sort the records by kind, so the one-run invariant below is checked over what is genuinely in
    // flight and nothing else.
    let mut live = Vec::new();
    let mut unacknowledged = Vec::new();
    for play in recoverable {
        match classify_record(play) {
            RecordKind::Uninitialized => {
                play_history::delete_uninitialized(client, namespace, play).await?
            }
            RecordKind::Unacknowledged => unacknowledged.push(play),
            RecordKind::InFlight => live.push(play),
        }
    }

    // Hand a finished result over before looking at anything in flight: it is the only copy of that
    // run's recap, the plan cannot start a replacement until it has been applied, and draining it is
    // a pure status write that never touches the cluster resources a live run owns. `recoverable`
    // comes back oldest-first, so several (if they ever do queue up) drain in the order they ran.
    if let Some(play) = unacknowledged.first() {
        let play_status = play
            .status
            .as_ref()
            .expect("a record needing recovery has a status");
        return Ok(Some(RecoveredRun::Finished {
            finished: recorded_run_from_play(play)?,
            status: play_status.clone(),
            // The one-run invariant is checked below, on the tick that goes on to advance what is
            // live; here the first record is enough to say the plan is still holding an attempt.
            surviving: live.first().map(|live| SurvivingAttempt {
                execution_hash: live.spec.execution_hash.clone(),
                triggered_slot: live.spec.triggered_slot,
            }),
        }));
    }

    let play = match sole_active_record(&live) {
        Ok(None) => return Ok(None),
        Ok(Some(play)) => play,
        Err(error) => {
            let names: Vec<&str> = live
                .iter()
                .filter_map(|play| play.metadata.name.as_deref())
                .collect();
            error!(
                "PlaybookPlan {namespace}/{plan_name} has {} recoverable Plays ({names:?}); refusing to recover any of them",
                live.len()
            );
            // Refusing must not also drop the node protection. Every one of these records may own a
            // live Job and node-root proxy pods, and none of them will be advanced this tick, so
            // their host Leases would otherwise lapse and let an unrelated plan start on the same
            // hosts while they are still running. Renew them all and *then* fail loudly.
            renew_contested_locks(context, object, &live).await;
            return Err(error);
        }
    };

    let play_status = play
        .status
        .as_ref()
        .expect("statusless records were filtered out above");
    let run = recorded_run_from_play(play)?;

    match play_status.phase.clone() {
        // Deferred rather than decided here: whether an absent-Job attempt may still be resumed
        // needs the resolved, policy-clamped inventory this step runs ahead of. The reconciler
        // resolves `Launching` Job existence and `suspend` before that dependency, and preserves
        // this record's locks if resolving the remaining inputs fails.
        phase @ (v1beta1::PlayPhase::Prepared
        | v1beta1::PlayPhase::Starting
        | v1beta1::PlayPhase::Launching) => Ok(Some(RecoveredRun::Unlaunched(UnlaunchedRun {
            run,
            phase,
            preparation_fingerprint: play.spec.preparation_fingerprint.clone(),
        }))),
        // `advance_active_run` owns Job validation because it can distinguish an unfinished foreign
        // Job (wait while renewing locks) from a finished one (finalize without trusting its recap).
        v1beta1::PlayPhase::Running => Ok(Some(RecoveredRun::Active(run))),
        // An acknowledged terminal record is filtered out by `recoverable_plays_for_plan`, and an
        // unacknowledged one was drained above — so reaching here means those two filters and
        // `classify_record` have drifted apart. That is a bug to fix, but a controller task is the
        // wrong place to assert it: failing the tick reports it on the plan and retries, while a
        // panic takes the whole reconcile loop down for every plan.
        v1beta1::PlayPhase::Succeeded
        | v1beta1::PlayPhase::Failed
        | v1beta1::PlayPhase::Unknown => Err(ReconcileError::PreconditionFailed(
            "a terminal Play was classified as in flight",
        )),
        v1beta1::PlayPhase::Aborted => Ok(Some(RecoveredRun::Aborted(run))),
    }
}

/// The distinct hosts a run's recorded inventory targets, in first-seen order.
///
/// Deduplicated because a host reachable through two inventory groups is still one host, and this
/// list is what the run's Leases are acquired, renewed and released against — leaving the repeat in
/// would spend an extra round of Lease calls on it every tick for as long as the run lasts. The
/// terminal recap counts distinctly for the same reason (see `play_history::terminal_status`).
fn host_names(inventory: &[ResolvedHosts]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    inventory
        .iter()
        .flat_map(|group| group.hosts.iter())
        .filter(|host| seen.insert(host.as_str()))
        .cloned()
        .collect()
}

/// What one reconcile found for a plan's run.
enum RecoveredRun {
    Active(RecordedRun),
    Unlaunched(UnlaunchedRun),
    Aborted(RecordedRun),
    Finished {
        finished: RecordedRun,
        status: v1beta1::PlayStatus,
        /// The attempt still in flight behind the drained result, if any. A terminal result is
        /// handed over ahead of anything live, so the plan is *not* finished when this is set, and
        /// the tick must not classify it as such — nor let the finished run's schedule window
        /// overwrite the one this attempt holds.
        surviving: Option<SurvivingAttempt>,
    },
}

/// What the tick that drains a finished result needs to know about the attempt that outlives it,
/// read off that attempt's own immutable record rather than off the plan status it may not have
/// reached yet.
struct SurvivingAttempt {
    execution_hash: String,
    triggered_slot: Option<DateTime<FixedOffset>>,
}

/// What a recoverable `Play` is to recovery. Pure so the one line that actually matters here stays
/// pinned: a terminal record whose result has not reached the plan is **not** in flight, so it can
/// never make a genuinely live run look like a second one and fail `sole_active_record` — which
/// would wedge the plan on the very record it needs to drain to move on.
#[derive(Debug, PartialEq, Eq)]
enum RecordKind {
    /// No status: it never crossed the operator-owned status boundary, so it describes nothing.
    Uninitialized,
    /// Terminal, but its result has not been folded into the plan yet.
    Unacknowledged,
    /// Somewhere between `Prepared` and `Running`, or `Aborted` with cleanup outstanding.
    InFlight,
}

fn classify_record(play: &Play) -> RecordKind {
    if play.status.is_none() {
        RecordKind::Uninitialized
    } else if play_history::needs_recovery(play) {
        RecordKind::Unacknowledged
    } else {
        RecordKind::InFlight
    }
}

/// The one in-flight record that may describe this plan's run, or `None` when it has none.
///
/// Pure so the invariant is testable: a plan runs at most one attempt at a time, and every path
/// that creates a record does so only when no other is in flight. Two therefore means something
/// outside this protocol wrote one, and picking either would leave the other's node-root proxy pods
/// unswept with nothing left pointing at them. Refusing is recoverable by an operator (delete the
/// stray record); silently choosing is not. The caller renews *every* candidate's host Leases before
/// it acts on the refusal, so failing this way never also unprotects the hosts those runs hold.
///
/// Terminal records awaiting acknowledgement are *not* in flight and are handled before this — they
/// can legitimately queue up behind a live run after an outage.
fn sole_active_record<'a>(live: &[&'a Play]) -> Result<Option<&'a Play>, ReconcileError> {
    match live {
        [] => Ok(None),
        [play] => Ok(Some(play)),
        _ => Err(ReconcileError::PreconditionFailed(
            "more than one Play claims to be this plan's active run",
        )),
    }
}

/// An attempt recovered before its Job exists, reduced to what deciding its fate needs: its
/// identity, the phase it was found in, and the fingerprint of the inputs it was prepared against.
///
/// The `Play` itself is deliberately not carried further: the fingerprint is the only thing about
/// the record that the resume decision consults, and everything else the attempt needs is re-derived
/// from live cluster state.
struct UnlaunchedRun {
    run: RecordedRun,
    phase: v1beta1::PlayPhase,
    preparation_fingerprint: String,
}

fn recoverable_plays_for_plan<'a>(plays: &'a [Play], plan: &PlaybookPlan) -> Vec<&'a Play> {
    let (Some(plan_name), Some(uid)) =
        (plan.metadata.name.as_deref(), plan.metadata.uid.as_deref())
    else {
        return Vec::new();
    };
    let mut recoverable: Vec<&Play> = plays
        .iter()
        .filter(|play| {
            play_belongs_to_plan(play, plan_name, uid)
                && (play.status.as_ref().is_none_or(|status| {
                    matches!(
                        status.phase,
                        v1beta1::PlayPhase::Prepared
                            | v1beta1::PlayPhase::Starting
                            | v1beta1::PlayPhase::Launching
                            | v1beta1::PlayPhase::Running
                            | v1beta1::PlayPhase::Aborted
                    )
                }) || play_history::needs_recovery(play))
        })
        .collect();
    recoverable.sort_by_key(|play| play.metadata.creation_timestamp.as_ref().map(|time| time.0));
    recoverable
}

fn recorded_run_from_play(play: &Play) -> Result<RecordedRun, ReconcileError> {
    let execution_hash = ExecutionHash::from_hex(&play.spec.execution_hash).ok_or(
        ReconcileError::PreconditionFailed("active Play has an invalid execution hash"),
    )?;
    let job_name = play
        .metadata
        .name
        .clone()
        .ok_or(ReconcileError::PreconditionFailed(
            "active Play has no name",
        ))?;
    let play_uid = play
        .metadata
        .uid
        .clone()
        .ok_or(ReconcileError::PreconditionFailed("active Play has no UID"))?;

    Ok(RecordedRun {
        mirror: ActiveRun {
            execution_hash: execution_hash.to_string(),
            run_id: play.spec.run_id.clone(),
            job_name,
            play_uid,
            hosts: host_names(&play.spec.inventory),
            attempt: play.spec.attempt,
            triggered_slot: play.spec.triggered_slot,
        },
        execution_hash,
    })
}

fn play_belongs_to_plan(play: &Play, plan_name: &str, plan_uid: &str) -> bool {
    play.spec.playbook_plan == plan_name && play.spec.playbook_plan_uid == plan_uid
}

fn job_belongs_to_plan(job: &Job, plan_name: &str, plan_uid: &str) -> bool {
    owner_references_plan(&job.metadata.owner_references, plan_name, plan_uid)
}

fn owner_references_plan(
    owners: &Option<Vec<OwnerReference>>,
    plan_name: &str,
    plan_uid: &str,
) -> bool {
    owners.as_ref().is_some_and(|owners| {
        owners.iter().any(|owner| {
            owner.kind == "PlaybookPlan" && owner.name == plan_name && owner.uid == plan_uid
        })
    })
}

fn job_label<'a>(job: &'a Job, key: &str) -> Option<&'a str> {
    job.metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(key))
        .map(String::as_str)
}

fn job_execution_hash(job: &Job) -> Result<ExecutionHash, ReconcileError> {
    job_label(job, labels::PLAYBOOKPLAN_HASH)
        .and_then(ExecutionHash::from_hex)
        .ok_or(ReconcileError::PreconditionFailed(
            "active Job has no valid execution hash",
        ))
}

fn job_run_id(job: &Job) -> Result<&str, ReconcileError> {
    job_label(job, labels::RUN_ID).ok_or(ReconcileError::PreconditionFailed(
        "active Job has no run ID",
    ))
}

fn retry_count_from_job_name(job_name: &str) -> Option<u32> {
    job_name.rsplit('-').next()?.parse().ok()
}

/// Whether a plan's name fits where the run protocol has to put it: a Kubernetes **label value**, on
/// its `Play`, its Job, that Job's pod template and the run's egress NetworkPolicy — and the
/// selectors that later find them again (`recover_active_run`, `select_job`, `play_history::prune`).
///
/// The cap is the label value's, not the object name's: a custom resource may carry a full DNS
/// subdomain, so a plan can legitimately be named far longer than any object derived from it can
/// record. Generated *names* handle that by truncating (`job_builder::job_name`), which a label value
/// cannot do — truncating it would break the selectors that have to match it exactly.
///
/// Counted in characters rather than bytes to match the message the user is shown; a name is a DNS
/// subdomain, so the two are the same anyway.
fn plan_name_within_label_limit(name: &str) -> bool {
    name.chars().count() <= v1beta1::MAX_PLAN_NAME_LEN
}

/// The plan's namespace and name — the two things almost every step needs to address its resources.
/// One helper so the pair is read (and refused) identically everywhere rather than being re-derived
/// with slightly different error handling at each site.
fn namespace_and_name(object: &PlaybookPlan) -> Result<(&str, &str), ReconcileError> {
    let namespace = object
        .metadata
        .namespace
        .as_deref()
        .ok_or(ReconcileError::PreconditionFailed("namespace not set"))?;

    let name = object
        .metadata
        .name
        .as_deref()
        .ok_or(ReconcileError::PreconditionFailed("name not set"))?;

    Ok((namespace, name))
}

/// How many characters [`run_id`] mints.
///
/// Long enough that concurrent attempts cannot collide on it, short enough to leave room for a node
/// name inside the object names it feeds. Every name budget that depends on it — the proxy pods and
/// Secrets in `managed_ssh::resource_name`, the egress policy in
/// `job_builder::job_network_policy_name` — is pinned by a test that mints an ID of exactly this
/// length, so raising it fails in all of them at once rather than at the apiserver.
pub(super) const RUN_ID_LENGTH: usize = 10;

/// Mints this attempt's run ID — the identity that scopes its Leases, proxy resources, client
/// certificate principal and cleanup.
///
/// Deliberately *not* a function of (plan, hash, attempt): an aborted attempt frees its number
/// again, so a derived ID would be reused by the retry while the aborted attempt's proxy pods are
/// still terminating, and the retry would adopt those dying pods under the same names. A counter
/// separates the IDs minted by one process and the clock separates them across restarts; the run ID
/// never has to be recomputed, since it is recorded in the `Play` before anything is named after it.
fn run_id(plan: &PlaybookPlan, execution_hash: &ExecutionHash) -> Result<String, ReconcileError> {
    use kube::runtime::reflector::Lookup as _;
    use std::hash::{Hash as _, Hasher as _};
    static MINTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    let mut hasher = twox_hash::XxHash3_64::new();
    plan.uid()
        .ok_or(ReconcileError::PreconditionFailed("uid not set"))?
        .hash(&mut hasher);
    execution_hash.to_string().hash(&mut hasher);
    MINTED
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .hash(&mut hasher);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ReconcileError::PreconditionFailed("system clock is before the epoch"))?
        .as_nanos()
        .hash(&mut hasher);
    Ok(crate::utils::generate_id_with_length(
        hasher.finish(),
        RUN_ID_LENGTH,
    ))
}

struct SelectedJob {
    job_name: String,
    attempt: u32,
}

/// One past the highest attempt number any of `claimed` occupies. Pure so the "never reuse a name
/// something still on the cluster claims" rule is unit-testable without a kube client.
fn next_attempt_number(claimed: &[u32]) -> Result<u32, ReconcileError> {
    claimed
        .iter()
        .copied()
        .max()
        .unwrap_or_default()
        .checked_add(1)
        .ok_or(ReconcileError::PreconditionFailed(
            "run attempt number overflowed",
        ))
}

/// Names the next attempt of `hash`, one past every attempt number anything still on the cluster
/// claims: **all** of this plan's Jobs, and **all** of its retained `Play` records (which reserve
/// their number even after the Job has been reaped, and even before their status exists — an
/// uninitialized record still occupies its name until recovery deletes it).
///
/// Deliberately counted across every revision rather than only `hash`'s own. The short id in
/// `job_builder::job_name` is ten symbols of a hash over the plan's UID and the revision, so it
/// makes different plans unlikely to share a name but cannot guarantee that, and two revisions of
/// one plan can still produce the same `apply-{plan}-{shortid}-{n}` — which is also the `Play`'s.
/// Numbering per hash would let a new revision pick a number a retained record of the colliding one
/// still holds, and `record_prepared` would then reject it as somebody else's run on every tick
/// until history pruning happened to remove it. Numbering per plan makes the name unique by
/// construction instead, at the cost of numbers that no longer restart at 1 for a new revision.
///
/// Deliberately never adopts an already-active Job. `try_start_run` only reaches here with no
/// recovered `Play`, and under the write-ahead protocol every Job this plan created has a `Play`
/// recorded *before* it — so an active Job with no recoverable record is not this run's, and
/// adopting it would mint a fresh `run_id` for a Job whose own record claims a different one,
/// wedging the attempt on an unrepairable `PreconditionFailed`. Resuming a genuinely in-flight run
/// is `recover_active_run`'s job; same-run idempotency within a tick is `spawn_ansible_job`'s.
async fn select_job(
    client: &kube::Client,
    api: &Api<Job>,
    hash: ExecutionHash,
    playbookplan: &PlaybookPlan,
    current_retry_count: u32,
) -> Result<SelectedJob, ReconcileError> {
    use kube::runtime::reflector::Lookup as _;

    let plan_name = playbookplan
        .name()
        .ok_or(ReconcileError::PreconditionFailed("name not set"))?;
    let plan_uid = playbookplan
        .uid()
        .ok_or(ReconcileError::PreconditionFailed("uid not set"))?;
    let namespace = playbookplan
        .namespace()
        .ok_or(ReconcileError::PreconditionFailed("namespace not set"))?;

    let jobs = api
        .list(&ListParams::default().labels(&format!("{}={plan_name}", labels::PLAYBOOKPLAN_NAME)))
        .await?;
    let max_job_attempt = jobs
        .items
        .iter()
        .filter(|job| job_belongs_to_plan(job, plan_name.as_ref(), plan_uid.as_ref()))
        .filter_map(|job| job.metadata.name.as_deref())
        .filter_map(retry_count_from_job_name)
        .max()
        .unwrap_or_default();

    let plays = Api::<Play>::namespaced(client.clone(), namespace.as_ref())
        .list(&ListParams::default().labels(&format!("{}={plan_name}", labels::PLAYBOOKPLAN_NAME)))
        .await?;
    let max_recorded_attempt = plays
        .items
        .iter()
        .filter(|play| play_belongs_to_plan(play, plan_name.as_ref(), plan_uid.as_ref()))
        .map(|play| play.spec.attempt)
        .max()
        .unwrap_or_default();

    let attempt =
        next_attempt_number(&[current_retry_count, max_job_attempt, max_recorded_attempt])?;

    Ok(SelectedJob {
        job_name: job_builder::job_name(plan_name.as_ref(), plan_uid.as_ref(), &hash, attempt),
        attempt,
    })
}

/// Creates this attempt's Job, tolerating the fact that it may already exist.
///
/// Same-run idempotency, and nothing wider: which attempt gets to run is decided long before this by
/// `select_job` (which never adopts a Job it has no record for) and `recover_active_run`. What is
/// left here is that the *same* attempt can reach this point more than once — several reconciles
/// fired in quick succession all read `phase` from the reflector cache, which lags this controller's
/// own `patch_status` writes, and a `create` whose response was lost still left a real Job behind.
/// So the Job is looked up by its exact name and, either way, `validate_selected_job` has to confirm
/// it carries this attempt's identity before it is adopted.
async fn spawn_ansible_job(
    api: &Api<Job>,
    playbookplan: &PlaybookPlan,
    selected: &SelectedJob,
    play_uid: &str,
    expected_job: Job,
) -> Result<(), ReconcileError> {
    let job_name = &selected.job_name;
    let retry_count = selected.attempt;
    let hash = job_execution_hash(&expected_job)?;
    let run_id = job_run_id(&expected_job)?.to_string();
    if let Some(existing) = api.get_opt(job_name).await? {
        validate_selected_job(
            &existing,
            playbookplan,
            hash,
            retry_count,
            &run_id,
            play_uid,
        )?;
        debug!("Adopting already-active job {job_name} for this run");
        return Ok(());
    }

    info!("Creating job {job_name}");
    match api
        .create(
            &PostParams {
                field_manager: Some("ansible-operator".into()),
                ..Default::default()
            },
            &expected_job,
        )
        .await
    {
        Ok(_) => {}
        Err(err) if is_conflict(&err) => {
            let existing = api.get(job_name).await?;
            validate_selected_job(
                &existing,
                playbookplan,
                hash,
                retry_count,
                &run_id,
                play_uid,
            )?;
            debug!("Adopting already-active job {job_name} for this run");
        }
        Err(err) => return Err(err.into()),
    }

    Ok(())
}

/// Whether `job` is the exact Job this run committed to. Identity, not content: the run's `Play` UID
/// (unique per attempt) has to be on both the Job and its pod template, alongside the plan's owner
/// reference, the execution hash, the per-attempt run ID and the attempt number in the name.
///
/// Deliberately *not* a comparison against the stored blueprint. A Job's pod template is immutable
/// once created, so a Job carrying this attempt's `Play` UID can only have been created from that
/// blueprint — while a field-by-field comparison would have to model every server-side default and
/// mutating webhook, and each field it failed to predict would disown a healthy run: the operator
/// would sit out the whole run holding this plan's host Leases against every other plan targeting
/// those hosts, and then write the run off as `Unknown` once its Job finished.
fn validate_selected_job(
    job: &Job,
    plan: &PlaybookPlan,
    expected_hash: ExecutionHash,
    expected_attempt: u32,
    expected_run_id: &str,
    expected_play_uid: &str,
) -> Result<(), ReconcileError> {
    use kube::runtime::reflector::Lookup as _;

    let plan_name = plan
        .name()
        .ok_or(ReconcileError::PreconditionFailed("name not set"))?;
    let plan_uid = plan
        .uid()
        .ok_or(ReconcileError::PreconditionFailed("uid not set"))?;
    let actual_attempt = job
        .metadata
        .name
        .as_deref()
        .and_then(retry_count_from_job_name);
    let expected_hash_string = expected_hash.to_string();
    if !job_belongs_to_plan(job, plan_name.as_ref(), plan_uid.as_ref())
        || job_label(job, labels::PLAYBOOKPLAN_NAME) != Some(plan_name.as_ref())
        || job_label(job, labels::COMPONENT) != Some(labels::PLAYBOOK_COMPONENT)
        || job_execution_hash(job)? != expected_hash
        || actual_attempt != Some(expected_attempt)
        || job_label(job, labels::RUN_ID) != Some(expected_run_id)
        || job_template_label(job, labels::RUN_ID) != Some(expected_run_id)
        || annotation_value(&job.metadata, labels::PLAY_UID_ANNOTATION) != Some(expected_play_uid)
        || job_template_annotation(job, labels::PLAY_UID_ANNOTATION) != Some(expected_play_uid)
        || job_template_label(job, labels::PLAYBOOKPLAN_HASH) != Some(expected_hash_string.as_str())
        || job_template_label(job, labels::PLAYBOOKPLAN_NAME) != Some(plan_name.as_ref())
        || job_template_label(job, labels::COMPONENT) != Some(labels::PLAYBOOK_COMPONENT)
    {
        return Err(ReconcileError::PreconditionFailed(
            "existing Job does not belong to the selected run",
        ));
    }

    Ok(())
}

fn job_template_annotation<'a>(job: &'a Job, key: &str) -> Option<&'a str> {
    job.spec
        .as_ref()
        .and_then(|spec| spec.template.metadata.as_ref())
        .and_then(|metadata| annotation_value(metadata, key))
}

fn job_template_label<'a>(job: &'a Job, key: &str) -> Option<&'a str> {
    job.spec
        .as_ref()
        .and_then(|spec| spec.template.metadata.as_ref())
        .and_then(|metadata| metadata.labels.as_ref())
        .and_then(|labels| labels.get(key))
        .map(String::as_str)
}

fn pod_belongs_to_job(pod: &Pod, job: &Job) -> bool {
    let (Some(job_name), Some(job_uid)) =
        (job.metadata.name.as_deref(), job.metadata.uid.as_deref())
    else {
        return false;
    };
    pod.metadata
        .owner_references
        .as_ref()
        .is_some_and(|owners| {
            owners
                .iter()
                .any(|owner| owner.kind == "Job" && owner.name == job_name && owner.uid == job_uid)
        })
}

fn annotation_value<'a>(
    metadata: &'a k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
    key: &str,
) -> Option<&'a str> {
    metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(key))
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1beta1::{PlaySpec, PlaybookPlanSpec, ResolvedHosts, SecretRef, SshConfig};

    fn managed_ssh_group(
        name: &str,
        hosts: &[&str],
        tolerations: Option<Vec<Toleration>>,
    ) -> ResolvedInventoryGroup {
        ResolvedInventoryGroup::ManagedSsh {
            hosts: ResolvedHosts {
                name: name.into(),
                hosts: hosts.iter().map(|h| h.to_string()).collect(),
            },
            tolerations,
            variables: None,
        }
    }

    fn ssh_group(
        name: &str,
        hosts: &[&str],
        static_inventory_name: &str,
    ) -> ResolvedInventoryGroup {
        ResolvedInventoryGroup::Ssh {
            hosts: ResolvedHosts {
                name: name.into(),
                hosts: hosts.iter().map(|h| h.to_string()).collect(),
            },
            static_inventory_name: static_inventory_name.into(),
            config: SshConfig {
                user: "root".into(),
                secret_ref: SecretRef {
                    name: "ssh-key".into(),
                },
            },
            variables: None,
        }
    }

    #[test]
    fn filter_groups_to_hosts_keeps_only_triggered_hosts_and_drops_empty_groups() {
        let groups = vec![
            managed_ssh_group("controlplanes", &["worker-1", "worker-2"], None),
            ssh_group("external", &["ccu.fritz.box"], "ccu"),
        ];

        let filtered = filter_groups_to_hosts(&groups, &["worker-1".to_string()]);

        assert_eq!(
            filtered.len(),
            1,
            "the ssh group has no triggered hosts and should be dropped entirely"
        );
        let ResolvedInventoryGroup::ManagedSsh { hosts, .. } = &filtered[0] else {
            panic!("expected the managed-ssh group to survive");
        };
        assert_eq!(hosts.hosts, vec!["worker-1".to_string()]);
    }

    #[test]
    fn filter_groups_to_hosts_preserves_group_specific_config() {
        let tolerations = Some(vec![Toleration {
            key: Some("dedicated".into()),
            ..Default::default()
        }]);
        let groups = vec![managed_ssh_group(
            "controlplanes",
            &["worker-1"],
            tolerations.clone(),
        )];

        let filtered = filter_groups_to_hosts(&groups, &["worker-1".to_string()]);

        let ResolvedInventoryGroup::ManagedSsh { tolerations: t, .. } = &filtered[0] else {
            panic!("expected a ManagedSsh group");
        };
        assert_eq!(t, &tolerations);
    }

    #[test]
    fn managed_ssh_hosts_and_tolerations_flattens_only_managed_ssh_groups() {
        let groups = vec![
            managed_ssh_group("controlplanes", &["worker-1"], None),
            ssh_group("external", &["ccu.fritz.box"], "ccu"),
            managed_ssh_group("workers", &["worker-2"], None),
        ];

        let (hosts, _) = managed_ssh_hosts_and_tolerations(&groups);

        assert_eq!(hosts, vec!["worker-1".to_string(), "worker-2".to_string()]);
    }

    #[test]
    fn managed_ssh_hosts_and_tolerations_uses_first_non_none_toleration() {
        let first = vec![Toleration {
            key: Some("first".into()),
            ..Default::default()
        }];
        let second = vec![Toleration {
            key: Some("second".into()),
            ..Default::default()
        }];
        let groups = vec![
            managed_ssh_group("a", &["worker-1"], None),
            managed_ssh_group("b", &["worker-2"], Some(first.clone())),
            managed_ssh_group("c", &["worker-3"], Some(second)),
        ];

        let (_, tolerations) = managed_ssh_hosts_and_tolerations(&groups);

        assert_eq!(tolerations, Some(first));
    }

    /// The run-identity predicates recovery and Job validation are built from. Each one answers
    /// "is this object part of *this* attempt?", and each is deliberately proof rather than a label
    /// match — a name or a label can be reused by a later attempt or a recreated plan.
    #[test]
    fn ownership_predicates_require_the_plan_uid_not_just_its_name() {
        let owner = |kind: &str, name: &str, uid: &str| OwnerReference {
            kind: kind.into(),
            name: name.into(),
            uid: uid.into(),
            ..Default::default()
        };

        let owners = Some(vec![owner("PlaybookPlan", "web", "uid-1")]);
        assert!(owner_references_plan(&owners, "web", "uid-1"));
        // A plan deleted and recreated under the same name is a different plan.
        assert!(!owner_references_plan(&owners, "web", "uid-2"));
        assert!(!owner_references_plan(&owners, "other", "uid-1"));
        // A same-named owner of another kind must not satisfy it.
        assert!(!owner_references_plan(
            &Some(vec![owner("Job", "web", "uid-1")]),
            "web",
            "uid-1"
        ));
        assert!(!owner_references_plan(&None, "web", "uid-1"));

        // `Play` ownership is decided on its immutable spec, not its ownerReference or label, so a
        // hand-edited label cannot make a foreign record look recoverable.
        let mut play = Play::new("apply-web-abc-1", PlaySpec::default());
        play.spec.playbook_plan = "web".into();
        play.spec.playbook_plan_uid = "uid-1".into();
        assert!(play_belongs_to_plan(&play, "web", "uid-1"));
        assert!(!play_belongs_to_plan(&play, "web", "uid-2"));
        assert!(!play_belongs_to_plan(&play, "other", "uid-1"));
    }

    #[test]
    fn pod_belongs_to_job_requires_the_jobs_uid() {
        let mut job = Job::default();
        job.metadata.name = Some("apply-web-abc-1".into());
        job.metadata.uid = Some("job-uid".into());

        let pod_owned_by = |name: &str, uid: &str, kind: &str| {
            let mut pod = Pod::default();
            pod.metadata.owner_references = Some(vec![OwnerReference {
                kind: kind.into(),
                name: name.into(),
                uid: uid.into(),
                ..Default::default()
            }]);
            pod
        };

        assert!(pod_belongs_to_job(
            &pod_owned_by("apply-web-abc-1", "job-uid", "Job"),
            &job
        ));
        // A Job recreated under the same name has a new UID; its predecessor's pods are not ours.
        assert!(!pod_belongs_to_job(
            &pod_owned_by("apply-web-abc-1", "older-job-uid", "Job"),
            &job
        ));
        assert!(!pod_belongs_to_job(
            &pod_owned_by("apply-web-abc-1", "job-uid", "ReplicaSet"),
            &job
        ));
        assert!(!pod_belongs_to_job(&Pod::default(), &job));

        // A Job that has not been created yet has no UID, so nothing can belong to it.
        let mut uidless = job.clone();
        uidless.metadata.uid = None;
        assert!(!pod_belongs_to_job(
            &pod_owned_by("apply-web-abc-1", "job-uid", "Job"),
            &uidless
        ));
    }

    #[test]
    fn job_run_id_is_read_from_the_label_and_required() {
        let mut job = Job::default();
        assert!(
            job_run_id(&job).is_err(),
            "a Job with no run ID cannot be matched to an attempt"
        );

        job.metadata.labels = Some(BTreeMap::from([(
            labels::RUN_ID.to_string(),
            "run-1".to_string(),
        )]));
        assert_eq!(job_run_id(&job).unwrap(), "run-1");
    }

    /// The attempt number is carried in the Job name, so recovering it has to survive plan names
    /// that themselves contain dashes and digits.
    #[test]
    fn retry_count_is_read_from_the_trailing_segment_of_a_job_name() {
        assert_eq!(retry_count_from_job_name("apply-web-abc-7"), Some(7));
        assert_eq!(
            retry_count_from_job_name("apply-web-2-config-abc-12"),
            Some(12),
            "a plan name containing digits must not confuse the attempt number"
        );
        assert_eq!(retry_count_from_job_name("apply-web-abc-notanumber"), None);
        assert_eq!(retry_count_from_job_name(""), None);
    }

    /// The run's lock set. Group order is preserved so the list reads like the inventory, and a host
    /// two groups both reach appears once — it is one host to Ansible and one Lease to the operator,
    /// so repeating it would only buy an extra round of Lease calls per tick.
    #[test]
    fn host_names_lists_each_targeted_host_once_in_inventory_order() {
        let inventory = vec![
            ResolvedHosts {
                name: "nodes".into(),
                hosts: vec!["a".into(), "b".into()],
            },
            ResolvedHosts {
                name: "external".into(),
                hosts: vec!["c".into()],
            },
        ];

        assert_eq!(host_names(&inventory), vec!["a", "b", "c"]);
        assert!(host_names(&[]).is_empty());

        let overlapping = vec![
            ResolvedHosts {
                name: "workers".into(),
                hosts: vec!["a".into(), "b".into()],
            },
            ResolvedHosts {
                name: "database".into(),
                hosts: vec!["b".into(), "c".into()],
            },
        ];

        assert_eq!(host_names(&overlapping), vec!["a", "b", "c"]);
    }

    /// Every attempt number anything still on the cluster claims — this plan's Jobs for the hash
    /// and its retained `Play` records — is skipped, so a new attempt can never land on a name an
    /// existing object already occupies.
    #[test]
    fn next_attempt_number_starts_past_everything_still_claiming_a_name() {
        // First run: nothing claims a number yet.
        assert_eq!(next_attempt_number(&[0, 0, 0]).unwrap(), 1);

        // A retained Play reserves its number even after its Job has been reaped.
        assert_eq!(next_attempt_number(&[0, 0, 7]).unwrap(), 8);

        // A surviving Job past the plan's own retry count still wins.
        assert_eq!(next_attempt_number(&[3, 5, 0]).unwrap(), 6);

        assert!(next_attempt_number(&[u32::MAX]).is_err());
    }

    /// Why `select_job` reserves names across *every* revision instead of only the one it is naming.
    ///
    /// A run name's short id is ten symbols, so it cannot separate an unbounded number of revisions:
    /// two of them eventually produce the same `apply-{plan}-{shortid}-{n}` — which is also the
    /// `Play`'s name. If numbering restarted per hash, the second revision would claim a name a
    /// retained record of the first still holds, and `record_prepared` would reject it as another
    /// run's on every tick until history pruning happened to remove it. Widening the short id would
    /// only move the collision, so the number, not the hash, carries the uniqueness.
    ///
    /// Asserted structurally rather than by exhibiting a colliding pair. Searching for one would
    /// have to brute-force the digest, which is only feasible while the digest is small — so the
    /// test would quietly become a several-minute loop the moment it was widened, and would be
    /// testing the width rather than the rule that survives it.
    #[test]
    fn two_revisions_can_share_a_run_name_so_numbers_are_reserved_plan_wide() {
        /// Splits `apply-{plan}-{digest}-{attempt}` on its last two separators.
        fn parts(name: &str) -> (&str, &str, &str) {
            let (head, attempt) = name.rsplit_once('-').unwrap();
            let (plan, digest) = head.rsplit_once('-').unwrap();
            (plan, digest, attempt)
        }

        let a = ExecutionHash::from_hex("1").unwrap();
        let b = ExecutionHash::from_hex("2").unwrap();
        let name_a = job_builder::job_name("web", "plan-uid", &a, 1);
        let name_b = job_builder::job_name("web", "plan-uid", &b, 1);
        let (plan_a, digest_a, attempt_a) = parts(&name_a);
        let (plan_b, digest_b, attempt_b) = parts(&name_b);

        // Two revisions of one plan are separated by the digest and nothing else...
        assert_ne!(name_a, name_b);
        assert_eq!((plan_a, attempt_a), (plan_b, attempt_b));
        assert_ne!(digest_a, digest_b);

        // ...and that digest is a fixed width, so it cannot keep an unbounded number of revisions
        // apart: some pair eventually lands on the same one, and then the whole name matches — which
        // is also the `Play`'s name. Numbering per hash would let the second revision claim a name a
        // retained record of the first still holds.
        assert_eq!(digest_a.len(), digest_b.len());
        assert_eq!(
            digest_a.len(),
            job_builder::job_name("web", "other-plan-uid", &a, 1)
                .rsplit_once('-')
                .unwrap()
                .0
                .rsplit_once('-')
                .unwrap()
                .1
                .len(),
            "the digest is fixed width, whatever it is derived from"
        );

        // The attempt number is the part that is guaranteed to differ, which is why it is reserved
        // across every revision of the plan rather than per hash.
        assert_ne!(name_a, job_builder::job_name("web", "plan-uid", &a, 2));
    }

    /// The one-run-at-a-time invariant the whole protocol rests on. Two in-flight records mean
    /// something outside this operator wrote one; recovering either would silently orphan the other
    /// — nothing would renew its host Leases or sweep its node-root proxy pods — so the tick refuses
    /// instead, which an operator can resolve by deleting the stray record.
    /// A finished run whose recap has not reached the plan yet must not be mistaken for a second
    /// live run: it owns nothing on the cluster any more, and it is exactly the record the plan has
    /// to drain before it can start anything else. Counting it would make the pair wedge the plan on
    /// `sole_active_record` forever.
    #[test]
    fn an_unacknowledged_result_is_not_in_flight() {
        let record = |phase: Option<v1beta1::PlayPhase>, acknowledged: bool| {
            let mut play = Play::new(
                "apply-web-abc-1",
                PlaySpec {
                    playbook_plan: "web".into(),
                    playbook_plan_uid: "plan-uid".into(),
                    ..PlaySpec::default()
                },
            );
            play.status = phase.map(|phase| v1beta1::PlayStatus {
                phase,
                plan_status_recorded: acknowledged,
                ..Default::default()
            });
            play
        };

        assert_eq!(
            classify_record(&record(None, false)),
            RecordKind::Uninitialized
        );
        assert_eq!(
            classify_record(&record(Some(v1beta1::PlayPhase::Succeeded), false)),
            RecordKind::Unacknowledged
        );
        assert_eq!(
            classify_record(&record(Some(v1beta1::PlayPhase::Unknown), false)),
            RecordKind::Unacknowledged
        );
        for phase in [
            v1beta1::PlayPhase::Prepared,
            v1beta1::PlayPhase::Starting,
            v1beta1::PlayPhase::Launching,
            v1beta1::PlayPhase::Running,
            v1beta1::PlayPhase::Aborted,
        ] {
            assert_eq!(
                classify_record(&record(Some(phase), false)),
                RecordKind::InFlight
            );
        }
    }

    #[test]
    fn only_the_recorded_running_play_enters_job_finalization() {
        let play = |phase| {
            let mut play = Play::new("apply-web-abc-1", PlaySpec::default());
            play.metadata.uid = Some("play-uid".into());
            play.status = Some(v1beta1::PlayStatus {
                phase,
                ..Default::default()
            });
            play
        };

        assert!(play_is_running_attempt(&play(v1beta1::PlayPhase::Running)).unwrap());
        for phase in [
            v1beta1::PlayPhase::Prepared,
            v1beta1::PlayPhase::Starting,
            v1beta1::PlayPhase::Launching,
            v1beta1::PlayPhase::Aborted,
            v1beta1::PlayPhase::Succeeded,
        ] {
            assert!(!play_is_running_attempt(&play(phase)).unwrap());
        }

        // A statusless record never crossed the operator-owned boundary, so it describes no phase to
        // act on — distinct from a record whose UID says it is not this run at all, which the caller
        // filters out before ever getting here.
        let mut statusless = play(v1beta1::PlayPhase::Running);
        statusless.status = None;
        assert!(play_is_running_attempt(&statusless).is_err());
    }

    /// A replacement `Play` at the same name is not this run's record, and has to be indistinguishable
    /// from finding nothing there. Both send the run to `finalize_lost_run`, which reports it
    /// `TerminalRecord::Lost` — and that is what stops finalization from acknowledging the
    /// replacement object, a version-checked write that would fail as "Play UID changed" and report a
    /// teardown problem for a run that is complete.
    #[test]
    fn a_replacement_play_at_the_same_name_is_not_this_runs_record() {
        let play = |uid: &str| {
            let mut play = Play::new("apply-web-abc-1", PlaySpec::default());
            play.metadata.uid = Some(uid.into());
            play
        };

        assert!(own_record(Some(play("play-uid")), "play-uid").is_some());
        assert!(own_record(Some(play("other-uid")), "play-uid").is_none());
        assert!(own_record(None, "play-uid").is_none());

        // A record with no UID at all is nobody's, least of all this run's.
        let mut anonymous = play("play-uid");
        anonymous.metadata.uid = None;
        assert!(own_record(Some(anonymous), "play-uid").is_none());

        // Only `Present` acknowledges; the lost path must never reach that write.
        assert_ne!(TerminalRecord::Lost, TerminalRecord::Present);
    }

    /// The guard both `finalize_finished_run` and `abandon_run` clear the mirror behind. A mirror
    /// naming a *different* attempt is the one thing that must survive: it is genuinely in flight,
    /// and it is the only handle `finalize_lost_run` has for releasing its host Leases and node-root
    /// proxy pods if its `Play` is deleted. An absent mirror still answers yes, because the tick that
    /// finishes a run clears it before either path runs and the phase reset still has to happen.
    #[test]
    fn only_the_mirror_describing_this_run_is_given_up_with_it() {
        let run = |play_uid: &str| RecordedRun {
            execution_hash: ExecutionHash::from_hex("1").unwrap(),
            mirror: ActiveRun {
                execution_hash: "1".into(),
                run_id: "run-1".into(),
                job_name: "apply-web-abc-1".into(),
                play_uid: play_uid.into(),
                hosts: vec!["worker-1".into()],
                attempt: 1,
                triggered_slot: None,
            },
        };
        let mirroring = |mirrored: Option<&RecordedRun>| PlaybookPlanStatus {
            active_run: mirrored.map(|run| run.mirror.clone()),
            ..Default::default()
        };

        let this_run = run("play-uid");
        assert!(mirrors_run(&mirroring(Some(&this_run)), &this_run));
        assert!(
            mirrors_run(&mirroring(None), &this_run),
            "an already-cleared mirror still has to reach the phase reset"
        );
        assert!(
            !mirrors_run(&mirroring(Some(&run("other-play-uid"))), &this_run),
            "a mirror describing another attempt is that attempt's only recovery handle"
        );
    }

    #[test]
    fn sole_active_record_refuses_to_pick_between_two_in_flight_runs() {
        let play = |name: &str| Play::new(name, PlaySpec::default());
        let (first, second) = (play("apply-web-abc-1"), play("apply-web-abc-2"));

        assert!(sole_active_record(&[]).unwrap().is_none());
        assert_eq!(
            sole_active_record(&[&first])
                .unwrap()
                .and_then(|play| play.metadata.name.as_deref()),
            Some("apply-web-abc-1")
        );
        assert!(sole_active_record(&[&first, &second]).is_err());
    }

    #[test]
    fn slot_already_triggered_suppresses_only_a_repeat_of_the_same_slot() {
        let slot = |s: &str| Some(s.parse::<DateTime<FixedOffset>>().unwrap());

        // Unscheduled ticks (no slot) are never suppressed.
        assert!(!slot_already_triggered(None, None));
        assert!(!slot_already_triggered(None, slot("2025-08-12T20:00:00Z")));

        // The first time a slot is seen it hasn't been triggered yet.
        assert!(!slot_already_triggered(slot("2025-08-12T20:00:00Z"), None));

        // The same slot already recorded -> suppress the re-trigger inside its grace window.
        assert!(slot_already_triggered(
            slot("2025-08-12T20:00:00Z"),
            slot("2025-08-12T20:00:00Z"),
        ));

        // Equality is by instant, so an equivalent moment in another offset still matches.
        assert!(slot_already_triggered(
            slot("2025-08-12T22:00:00+02:00"),
            slot("2025-08-12T20:00:00Z"),
        ));

        // A later slot than the recorded one -> a genuinely new run.
        assert!(!slot_already_triggered(
            slot("2025-08-13T20:00:00Z"),
            slot("2025-08-12T20:00:00Z"),
        ));
    }

    #[test]
    fn namespace_and_name_requires_both() {
        let mut pp = PlaybookPlan::new("placeholder", PlaybookPlanSpec::default());
        pp.metadata.name = None;

        assert!(matches!(
            namespace_and_name(&pp),
            Err(ReconcileError::PreconditionFailed("namespace not set"))
        ));

        pp.metadata.namespace = Some("default".into());
        assert!(matches!(
            namespace_and_name(&pp),
            Err(ReconcileError::PreconditionFailed("name not set"))
        ));

        pp.metadata.name = Some("an-example".into());
        assert_eq!(namespace_and_name(&pp).unwrap(), ("default", "an-example"));
    }

    /// Every object a run creates records the plan's name as a **label value**, and the selectors
    /// that find them again match on it exactly — so unlike a generated object name it cannot be
    /// truncated to fit. The guard is what keeps an over-long name from being accepted and then
    /// failing at the first create, blaming a label the user never wrote.
    ///
    /// The label value's own limit is what the boundary has to be, so it is asserted against
    /// `MAX_DNS_LABEL_LEN` rather than against the constant the guard uses — the two agreeing is the
    /// point.
    #[test]
    fn a_plan_name_is_bounded_by_what_a_label_value_can_hold() {
        use crate::utils::{MAX_DNS_LABEL_LEN, MAX_DNS_SUBDOMAIN_LEN};

        assert_eq!(v1beta1::MAX_PLAN_NAME_LEN, MAX_DNS_LABEL_LEN);

        assert!(plan_name_within_label_limit("web"));
        assert!(plan_name_within_label_limit(&"a".repeat(MAX_DNS_LABEL_LEN)));
        assert!(!plan_name_within_label_limit(
            &"a".repeat(MAX_DNS_LABEL_LEN + 1)
        ));
        // A name Kubernetes accepts for the custom resource itself, but no label value can carry.
        assert!(!plan_name_within_label_limit(
            &"a".repeat(MAX_DNS_SUBDOMAIN_LEN)
        ));
    }

    /// Every label an accepted plan name is written into, and every selector that matches on it, has
    /// to stay valid at the boundary — this is the case the guard exists to make safe, so it is
    /// asserted on the real objects rather than on the guard alone.
    #[test]
    fn a_maximum_length_plan_name_still_builds_valid_labels_and_selectors() {
        use crate::utils::MAX_DNS_LABEL_LEN;

        let plan_name = "a".repeat(v1beta1::MAX_PLAN_NAME_LEN);
        let hash = ExecutionHash::from_hex("1").unwrap();
        let mut plan = PlaybookPlan::new(&plan_name, PlaybookPlanSpec::default());
        plan.metadata.namespace = Some("team".into());
        plan.metadata.uid = Some("plan-uid".into());

        let job = job_builder::create_job_blueprint(&hash, 1, "run-1", &[], &plan).unwrap();
        let template_labels = job
            .spec
            .as_ref()
            .unwrap()
            .template
            .metadata
            .as_ref()
            .unwrap()
            .labels
            .clone()
            .unwrap();

        for labels in [job.metadata.labels.clone().unwrap(), template_labels] {
            for (key, value) in labels {
                assert!(
                    value.len() <= MAX_DNS_LABEL_LEN,
                    "label {key} is {} characters",
                    value.len()
                );
            }
        }

        // The selector every recovery and retention pass narrows on carries the same value.
        let selector = format!("{}={plan_name}", labels::PLAYBOOKPLAN_NAME);
        assert_eq!(
            job.metadata.labels.as_ref().unwrap()[labels::PLAYBOOKPLAN_NAME],
            plan_name
        );
        assert!(selector.ends_with(&plan_name));
    }

    /// A recovered attempt is put back onto the plan whole, but its retry number only counts towards
    /// the revision it belongs to — carrying it onto a plan that has since moved on would make the
    /// replacement's first attempt skip numbers for no reason.
    #[test]
    fn a_recovered_attempt_is_readopted_and_keeps_its_number_only_for_its_own_revision() {
        let active_run = ActiveRun {
            execution_hash: "1".into(),
            run_id: "run-1".into(),
            job_name: "apply-plan-1-4".into(),
            play_uid: "play-uid".into(),
            hosts: vec!["worker-1".into()],
            attempt: 4,
            triggered_slot: None,
        };
        let mut matching = PlaybookPlanStatus {
            current_hash: "1".into(),
            retry_count: 1,
            ..Default::default()
        };
        adopt_recovered_attempt(&mut matching, &active_run);
        assert_eq!(matching.retry_count, 4);
        assert_eq!(matching.phase, Phase::Applying);
        assert_eq!(matching.current_job_name.as_deref(), Some("apply-plan-1-4"));
        assert_eq!(
            matching
                .active_run
                .as_ref()
                .map(|run| run.play_uid.as_str()),
            Some("play-uid")
        );

        let mut replacement = PlaybookPlanStatus {
            current_hash: "2".into(),
            retry_count: 0,
            ..Default::default()
        };
        adopt_recovered_attempt(&mut replacement, &active_run);
        assert_eq!(replacement.retry_count, 0);
        assert!(replacement.active_run.is_some());
    }

    #[test]
    fn run_ids_are_minted_fresh_and_stay_short_enough_for_resource_names() {
        let mut plan = PlaybookPlan::new("plan", PlaybookPlanSpec::default());
        plan.metadata.uid = Some("plan-uid".into());
        let hash = ExecutionHash::from_hex("1a").unwrap();

        let first = run_id(&plan, &hash).unwrap();
        let second = run_id(&plan, &hash).unwrap();

        // Same plan, same revision, same attempt number: an aborted attempt's retry must still not
        // land on the identity whose proxy pods may still be terminating.
        assert_ne!(first, second);
        assert_eq!(first.len(), RUN_ID_LENGTH);
        assert!(first.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn recoverable_plays_use_immutable_plan_identity_and_operator_status() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference, Time};
        use k8s_openapi::jiff::Timestamp;

        fn play(
            name: &str,
            owner_uid: &str,
            created_secs: i64,
            phase: Option<v1beta1::PlayPhase>,
        ) -> Play {
            let mut play = Play::new(
                name,
                v1beta1::PlaySpec {
                    playbook_plan: "plan".into(),
                    playbook_plan_uid: owner_uid.into(),
                    execution_hash: "1a".into(),
                    run_id: "run-1".into(),
                    preparation_fingerprint: "fingerprint".into(),
                    attempt: 1,
                    inventory: vec![ResolvedHosts {
                        name: "workers".into(),
                        hosts: vec!["worker-1".into()],
                    }],
                    triggered_slot: None,
                },
            );
            play.metadata = ObjectMeta {
                name: Some(name.into()),
                creation_timestamp: Some(Time(Timestamp::from_second(created_secs).unwrap())),
                owner_references: Some(vec![OwnerReference {
                    kind: "PlaybookPlan".into(),
                    name: "plan".into(),
                    uid: owner_uid.into(),
                    ..Default::default()
                }]),
                ..Default::default()
            };
            play.status = phase.map(|phase| v1beta1::PlayStatus {
                phase,
                ..Default::default()
            });
            play
        }

        let mut plan = PlaybookPlan::new("plan", PlaybookPlanSpec::default());
        plan.metadata.uid = Some("plan-uid".into());
        plan.metadata.namespace = Some("default".into());
        let mut acknowledged = play(
            "acknowledged",
            "plan-uid",
            350,
            Some(v1beta1::PlayPhase::Succeeded),
        );
        acknowledged.status.as_mut().unwrap().plan_status_recorded = true;
        let plays = vec![
            play("legacy", "plan-uid", 100, Some(v1beta1::PlayPhase::Running)),
            play(
                "other-owner",
                "other-uid",
                200,
                Some(v1beta1::PlayPhase::Running),
            ),
            play(
                "finished",
                "plan-uid",
                300,
                Some(v1beta1::PlayPhase::Succeeded),
            ),
            acknowledged,
            play("prepared", "plan-uid", 400, None),
            play(
                "running",
                "plan-uid",
                500,
                Some(v1beta1::PlayPhase::Running),
            ),
        ];

        let names: Vec<&str> = recoverable_plays_for_plan(&plays, &plan)
            .into_iter()
            .filter_map(|play| play.metadata.name.as_deref())
            .collect();

        assert_eq!(names, vec!["legacy", "finished", "prepared", "running"]);
    }

    /// Recovery reads a run's revision back out of two persisted, hand-editable places — the `Play`
    /// spec and the Job's hash label — and both go through `ExecutionHash::from_hex`. Each has to
    /// canonicalize what it accepts, so the value compares equal to a freshly computed hash however
    /// it was written down, and each has to refuse a value that is not a hash at all rather than
    /// silently scoping a run's resources to something else.
    #[test]
    fn a_persisted_execution_hash_is_canonicalized_or_refused() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

        let mut play = Play::new(
            "apply-plan-abc-2",
            v1beta1::PlaySpec {
                playbook_plan: "plan".into(),
                playbook_plan_uid: "plan-uid".into(),
                execution_hash: "00001A".into(),
                run_id: "run-2".into(),
                preparation_fingerprint: "fingerprint".into(),
                attempt: 2,
                inventory: vec![ResolvedHosts {
                    name: "workers".into(),
                    hosts: vec!["worker-1".into(), "worker-2".into()],
                }],
                triggered_slot: None,
            },
        );
        play.metadata.uid = Some("play-uid".into());

        let run = recorded_run_from_play(&play).unwrap();

        // Parsed once on the way in, and mirrored in the canonical form the status stores.
        assert_eq!(run.execution_hash, ExecutionHash::from_hex("1a").unwrap());
        assert_eq!(run.mirror.execution_hash, "1a");
        assert_eq!(run.mirror.job_name, "apply-plan-abc-2");
        assert_eq!(run.mirror.play_uid, "play-uid");
        assert_eq!(run.mirror.hosts, vec!["worker-1", "worker-2"]);
        assert_eq!(run.mirror.attempt, 2);

        // The record is only a run's identity if it can be tied back to a specific object.
        let mut uidless = play.clone();
        uidless.metadata.uid = None;
        assert!(recorded_run_from_play(&uidless).is_err());

        play.spec.execution_hash = "not-a-hash".into();
        assert!(matches!(
            recorded_run_from_play(&play),
            Err(ReconcileError::PreconditionFailed(
                "active Play has an invalid execution hash"
            ))
        ));

        let mut job = Job {
            metadata: ObjectMeta {
                labels: Some(BTreeMap::from([(
                    labels::PLAYBOOKPLAN_HASH.into(),
                    "00001A".into(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(job_execution_hash(&job).unwrap().to_string(), "1a");

        job.metadata
            .labels
            .as_mut()
            .unwrap()
            .insert(labels::PLAYBOOKPLAN_HASH.into(), "not-a-hash".into());
        assert!(matches!(
            job_execution_hash(&job),
            Err(ReconcileError::PreconditionFailed(
                "active Job has no valid execution hash"
            ))
        ));
    }

    #[test]
    fn selected_job_requires_the_prepared_play_uid() {
        let mut plan = PlaybookPlan::new("plan", PlaybookPlanSpec::default());
        plan.metadata.uid = Some("plan-uid".into());
        plan.metadata.namespace = Some("default".into());
        let hash = ExecutionHash::from_hex("1a").unwrap();
        let mut job = job_builder::create_job_blueprint(&hash, 1, "run-1", &[], &plan).unwrap();
        job_builder::correlate_job_to_play(&mut job, "play-uid");

        assert!(validate_selected_job(&job, &plan, hash, 1, "run-1", "play-uid").is_ok());

        // A Job created for a different attempt of the same revision is not this run's Job, even
        // though it shares the plan, the execution hash and the attempt number.
        assert!(matches!(
            validate_selected_job(&job, &plan, hash, 1, "run-2", "play-uid"),
            Err(ReconcileError::PreconditionFailed(
                "existing Job does not belong to the selected run"
            ))
        ));

        // The pod template's correlation has to hold too: a Job whose pods aren't tied to this Play
        // can't have its termination message trusted as this run's recap.
        let mut tampered = job.clone();
        tampered
            .spec
            .as_mut()
            .unwrap()
            .template
            .metadata
            .as_mut()
            .unwrap()
            .annotations
            .as_mut()
            .unwrap()
            .insert(labels::PLAY_UID_ANNOTATION.into(), "another-play".into());
        assert!(matches!(
            validate_selected_job(&tampered, &plan, hash, 1, "run-1", "play-uid"),
            Err(ReconcileError::PreconditionFailed(
                "existing Job does not belong to the selected run"
            ))
        ));

        job.metadata
            .annotations
            .as_mut()
            .unwrap()
            .insert(labels::PLAY_UID_ANNOTATION.into(), "another-play".into());
        assert!(matches!(
            validate_selected_job(&job, &plan, hash, 1, "run-1", "play-uid"),
            Err(ReconcileError::PreconditionFailed(
                "existing Job does not belong to the selected run"
            ))
        ));
    }

    #[test]
    fn get_related_secrets_collects_variable_and_file_secrets_but_not_inline_or_image_sources() {
        let yaml = r#"
apiVersion: ansible.cloudbending.dev/v1beta1
kind: PlaybookPlan
metadata:
  name: an-example
spec:
  image: docker.io/serversideup/ansible-core:2.18
  mode: OneShot
  inventoryRefs: []
  template:
    variables:
      - inline:
          key: value
      - secretRef:
          name: secret-with-variables
    files:
      - name: binary-assets
        image:
          reference: my.registry.tld/the-image:v2
          pullPolicy: IfNotPresent
      - name: some-configs
        secretRef:
          name: secret-with-config-files
    playbook: |
      - hosts: all
        tasks: []
        "#;
        let pp = serde_yaml::from_str::<PlaybookPlan>(yaml).unwrap();

        let secrets: Vec<&str> = get_related_secrets(&pp)
            .into_iter()
            .map(String::as_str)
            .collect();

        assert_eq!(
            secrets,
            vec!["secret-with-variables", "secret-with-config-files"]
        );
    }

    #[test]
    fn is_eligible_to_start_oneshot_gates_only_on_outdated_hosts() {
        // OneShot with work to do starts whether or not a schedule is set.
        assert!(is_eligible_to_start(
            false,
            &ExecutionMode::OneShot,
            false,
            true
        ));
        assert!(is_eligible_to_start(
            false,
            &ExecutionMode::OneShot,
            true,
            true
        ));
        // Nothing outdated -> goes quiet.
        assert!(!is_eligible_to_start(
            false,
            &ExecutionMode::OneShot,
            true,
            false
        ));
    }

    #[test]
    fn is_eligible_to_start_recurring_requires_a_schedule() {
        // The busy-loop guard: Recurring with hosts but no schedule must NOT start — there's no
        // slot to dedup against, so it would re-trigger on every tick.
        assert!(!is_eligible_to_start(
            false,
            &ExecutionMode::Recurring,
            false,
            true
        ));
        // With a schedule it's eligible...
        assert!(is_eligible_to_start(
            false,
            &ExecutionMode::Recurring,
            true,
            true
        ));
        // ...but still only when there are hosts to trigger.
        assert!(!is_eligible_to_start(
            false,
            &ExecutionMode::Recurring,
            true,
            false
        ));
    }

    #[test]
    fn is_eligible_to_start_suspended_never_starts() {
        // `spec.suspend` overrides everything else: whatever the mode/schedule/host state would
        // otherwise permit, a suspended plan starts nothing.
        assert!(!is_eligible_to_start(
            true,
            &ExecutionMode::OneShot,
            true,
            true
        ));
        assert!(!is_eligible_to_start(
            true,
            &ExecutionMode::Recurring,
            true,
            true
        ));
        // Sanity: identical inputs with suspend cleared *would* be eligible, so it's the flag doing
        // the gating here and nothing else.
        assert!(is_eligible_to_start(
            false,
            &ExecutionMode::OneShot,
            true,
            true
        ));
    }

    /// The identity check that classifies what holds a run's name, exercised at the boundary that
    /// used to trust the name alone. A colliding name is not evidence of ownership: the Job has to
    /// carry this attempt's own run ID, `Play` UID, hash, attempt number and owner reference — on the
    /// Job *and* on the pod template that actually does the work.
    #[test]
    fn a_job_at_the_expected_name_is_only_this_runs_if_it_carries_its_identity() {
        let hash = ExecutionHash::from_hex("1").unwrap();
        let mut plan = PlaybookPlan::new("web", PlaybookPlanSpec::default());
        plan.metadata.namespace = Some("team".into());
        plan.metadata.uid = Some("plan-uid".into());

        let own = || {
            let mut job = job_builder::create_job_blueprint(&hash, 7, "run-1", &[], &plan).unwrap();
            job_builder::correlate_job_to_play(&mut job, "play-uid");
            job.metadata.owner_references = Some(vec![playbookplan_owner_ref(&plan).unwrap()]);
            job
        };
        let validate = |job: &Job| validate_selected_job(job, &plan, hash, 7, "run-1", "play-uid");

        assert!(validate(&own()).is_ok(), "the run's own Job is recognized");

        // Another plan's Job that happened to land on the same name: same shape, different owner.
        let mut other_plan = PlaybookPlan::new("web", PlaybookPlanSpec::default());
        other_plan.metadata.namespace = Some("team".into());
        other_plan.metadata.uid = Some("other-plan-uid".into());
        let mut foreign =
            job_builder::create_job_blueprint(&hash, 7, "run-1", &[], &other_plan).unwrap();
        job_builder::correlate_job_to_play(&mut foreign, "play-uid");
        foreign.metadata.owner_references =
            Some(vec![playbookplan_owner_ref(&other_plan).unwrap()]);
        assert!(
            validate(&foreign).is_err(),
            "another plan's Job must never pass as this run's"
        );

        // A retry of this same plan, which shares the name's readable half but not the attempt.
        let mut retry = job_builder::create_job_blueprint(&hash, 8, "run-2", &[], &plan).unwrap();
        job_builder::correlate_job_to_play(&mut retry, "other-play-uid");
        retry.metadata.owner_references = Some(vec![playbookplan_owner_ref(&plan).unwrap()]);
        assert!(validate(&retry).is_err());

        // The pod template is checked as well as the Job, because the pod is what reaches the hosts.
        // A Job whose own metadata is impeccable but whose template lost the correlation fails —
        // this is the `create_job_blueprint`/`correlate_job_to_play` ordering hazard, caught here
        // rather than by adopting a Job whose pods carry no run identity at all.
        let mut uncorrelated = own();
        uncorrelated
            .spec
            .as_mut()
            .unwrap()
            .template
            .metadata
            .as_mut()
            .unwrap()
            .annotations = None;
        assert!(
            validate(&uncorrelated).is_err(),
            "a matching Job metadata alone must not be enough"
        );

        let mut missing_plan_label = own();
        missing_plan_label
            .metadata
            .labels
            .as_mut()
            .unwrap()
            .remove(labels::PLAYBOOKPLAN_NAME);
        assert!(
            validate(&missing_plan_label).is_err(),
            "the Job metadata must carry the plan label"
        );

        let mut missing_component_label = own();
        missing_component_label
            .metadata
            .labels
            .as_mut()
            .unwrap()
            .remove(labels::COMPONENT);
        assert!(
            validate(&missing_component_label).is_err(),
            "the Job metadata must carry the component label"
        );
    }

    #[test]
    fn decide_terminal_oneshot_all_current_succeeds() {
        let now = "2025-08-12T20:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let outcome = decide_terminal(&ExecutionMode::OneShot, None, 0, 3, now);

        assert_eq!(outcome.phase, Phase::Succeeded);
        assert_eq!(outcome.next_run, None);
        assert_eq!(outcome.summary, "3/3 up-to-date");
        assert_eq!(outcome.requeue, None);
    }

    #[test]
    fn decide_terminal_oneshot_with_outdated_fails_and_never_reschedules() {
        let now = "2025-08-12T20:00:00Z".parse::<DateTime<Utc>>().unwrap();
        // A schedule is irrelevant in OneShot — even with one set it must resolve terminally and
        // never reschedule.
        let outcome = decide_terminal(&ExecutionMode::OneShot, Some("0 3 * * *"), 1, 3, now);

        assert_eq!(outcome.phase, Phase::Failed);
        assert_eq!(outcome.next_run, None);
        assert_eq!(outcome.summary, "1/3 outdated");
        assert_eq!(outcome.requeue, None);
    }

    #[test]
    fn decide_terminal_recurring_with_schedule_reschedules_to_next_slot() {
        let now = "2025-08-12T20:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let outcome = decide_terminal(&ExecutionMode::Recurring, Some("0 3 * * *"), 0, 2, now);

        assert_eq!(outcome.phase, Phase::Scheduled);
        assert_eq!(
            outcome.next_run,
            Some(
                "2025-08-13T03:00:00Z"
                    .parse::<DateTime<FixedOffset>>()
                    .unwrap()
            )
        );
        // Overrides the caller's default requeue so the plan wakes up at the next slot.
        assert!(outcome.requeue.is_some());
    }

    #[test]
    fn decide_terminal_recurring_without_schedule_is_a_dead_end() {
        let now = "2025-08-12T20:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let outcome = decide_terminal(&ExecutionMode::Recurring, None, 0, 2, now);

        // Nothing to reschedule against, so the plan holds at Applying (the eligibility gate
        // normally prevents a schedule-less Recurring plan from ever starting a run).
        assert_eq!(outcome.phase, Phase::Applying);
        assert_eq!(outcome.next_run, None);
        assert_eq!(outcome.requeue, None);
    }
}
