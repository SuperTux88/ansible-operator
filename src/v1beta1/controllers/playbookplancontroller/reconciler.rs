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
    api::{DeleteParams, ListParams, Patch, PatchParams, PostParams, Preconditions},
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
        execution_evaluator::{ExecutionHash, distinct_host_count, find_all_hosts},
        locking, managed_ssh,
        triggers::{Timing, evaluate_schedule, forecast_next_run},
        workspace::render_secret,
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

/// What `try_start_run` needs to name and record a new run: the resource's namespace/name, the
/// execution hash, the schedule slot being consumed, and the run's resolved inventory. Kube `Api<T>`
/// handles are deliberately *not* here — those are plumbing built on demand from
/// `ReconciliationContext::client` plus `namespace`, not run identity.
struct RunContext<'a> {
    namespace: &'a str,
    name: &'a str,
    execution_hash: ExecutionHash,
    /// This run's resolved inventory filtered to the hosts being triggered, preserving the user's
    /// groups. The single source of the run's host set: the Job, the proxy pods, the rendered
    /// inventory and the `Play` record all derive from this one value, so they cannot disagree.
    run_groups: &'a [ResolvedInventoryGroup],
    /// The fingerprint of `run_groups` plus the live plan spec, computed once per tick by the
    /// caller — which also compares it against a recovered run's recorded one. Passed in rather
    /// than recomputed here so the value a fresh run records is provably the same one a resume
    /// is later judged against.
    preparation_fingerprint: &'a str,
    triggered_slot: Option<DateTime<FixedOffset>>,
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
///   0a. `recover_active_run` (what the plan's `Play` records say is in flight), 0/0b.
///   `resolve_authorized_inventory` (resolve the inventories, then clamp them to what
///   `NodeAccessPolicy` grants), 1. compute outdated hosts/evaluate
///   schedule, 2-5. `try_start_run` (locks, managed-ssh proxy infra, workspace secret, the one Job),
///   6-7. `advance_active_run` (once the Job is finished: read+record the recap, cleanup). A single
///   tick can walk through both halves — e.g. Pending -> locks acquired -> proxy ready -> Job
///   created -> immediately checked for completion — since the only persisted step is the run
///   record's own phase, which exists to make the privileged steps crash-recoverable.
async fn reconcile(
    object: Arc<v1beta1::PlaybookPlan>,
    context: Arc<ReconciliationContext>,
) -> Result<Action, ReconcileError> {
    if object.metadata.deletion_timestamp.is_some() {
        return release_deleted_plan(&context, &object).await;
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
    // A run recovered before its Job exists, with the phase it was found in. It is dispatched
    // after inventory resolution rather than here, because deciding whether it may still be resumed
    // needs the resolved, policy-clamped groups its fingerprint covers.
    let mut unlaunched_run: Option<UnlaunchedRun> = None;
    let mut finished_active_run: Option<FinishedRun> = None;
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
    // Set when the tick drained a finished run's result but the plan still has a live run behind
    // it: the plan is emphatically not finished, so the terminal classification below is skipped,
    // and the schedule window that run holds is what the plan records.
    let mut surviving_run: Option<Box<SurvivingRun>> = None;
    let mut finalized_run = false;
    // Whether this tick found the plan holding a run at all. Recovery is the only complete answer:
    // a record whose result has not been drained, or one being given up, owns resources while the
    // status mirror may already have moved on — so the finalizer is kept until a tick finds neither.
    let recovered_a_run = recovered.is_some();
    if recovered_a_run {
        // Re-asserted rather than assumed: a plan that lost the finalizer — stripped by hand, or
        // adopted from a release that predates it — would otherwise keep the run it is holding
        // outside the contract for as long as that run lasts.
        ensure_run_cleanup_finalizer(&api, &object).await?;
    }
    if let Some(recovered) = recovered {
        match recovered {
            RecoveredRun::Active(run) => {
                adopt_recovered_run(&mut resource_status, &run.mirror);
            }
            RecoveredRun::Unlaunched(unlaunched) => {
                adopt_recovered_run(&mut resource_status, &unlaunched.run.mirror);
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
                // Adopted *before* the result is persisted, so the plan never goes a tick describing
                // a run it is holding with no `activeRun` to reach it by: the mirror is the only
                // handle `finalize_lost_run` has if that run's record is deleted while it runs.
                // It also settles what `finalize_finished_run` may give up — the mirror now names a
                // different run than the one finishing, which is exactly when it keeps it.
                if let Some(surviving) = &surviving {
                    adopt_recovered_run(&mut resource_status, &surviving.run.mirror);
                }
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
                finished_active_run = Some(FinishedRun {
                    outcome: status.phase,
                    run: finished,
                });
                surviving_run = surviving;
            }
        }
    }

    let unlaunched_run = if let Some(unlaunched) = unlaunched_run {
        match resolve_unlaunched_before_inputs(
            &context,
            &object,
            &api,
            &unlaunched,
            &mut resource_status,
        )
        .await
        {
            Ok(true) => Some(unlaunched),
            Ok(false) => None,
            Err(error) => {
                preserve_unlaunched_run_after_error(
                    &context,
                    &object,
                    &api,
                    &unlaunched,
                    &mut resource_status,
                    &error,
                )
                .await;
                return Err(error);
            }
        }
    } else {
        None
    };

    if unlaunched_run.is_none()
        && let Some(mirror) = resource_status.active_run.clone()
    {
        let active_run = RecordedRun::from_mirror(mirror)?;
        // Reported on the plan before the tick aborts, like recovery above: this is where a finished
        // run's node-root proxy pods and host Leases are given back, so a teardown that will not
        // complete has to be readable on the resource and not only in the operator's log.
        let progress =
            match advance_active_run(&context, &active_run, &object, &mut resource_status).await {
                Ok(progress) => progress,
                Err(error) => {
                    return Err(report_failed_finalization(
                        &api,
                        &object,
                        &active_run,
                        &mut resource_status,
                        error,
                    )
                    .await);
                }
            };
        match progress {
            ActiveRunProgress::Running(requeue) => requeue_after = requeue,
            // The cached status was behind a tick that had already finished this run;
            // `advance_active_run` replaced it with what the apiserver actually holds, so there is
            // nothing left to advance and the refreshed status decides the rest of this tick.
            ActiveRunProgress::AlreadyFinalized => {
                requeue_after = std::time::Duration::from_secs(1);
            }
            ActiveRunProgress::Finished {
                run: finished,
                outcome,
                record,
            } => {
                resource_status.summary =
                    Some("previous run finished; evaluating desired revision".to_string());
                match finalize_finished_run(
                    &context,
                    &object,
                    &api,
                    &finished,
                    record,
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
                finished_active_run = Some(FinishedRun {
                    run: finished,
                    outcome,
                });
                // This *was* the run a drained result was still waiting behind, and it has now
                // finished too, so the plan may be classified on its own terms after all.
                surviving_run = None;
            }
        }
    }

    // After both finalization paths, because each ends in a retention pass of its own and running
    // one here as well would list and delete the same history twice on the tick a run completes.
    // Restricted to an *idle* plan for the reason in `prune_history`: retention only ever gains work
    // when a run finishes, and a plan with a run in flight is polled every few seconds, so
    // listing its history on each of those ticks is a steady apiserver cost that can find nothing to
    // do. A deletion that failed is retried on the first tick without a run, which is exactly the
    // state the standalone pass exists for.
    if !finalized_run && resource_status.active_run.is_none() {
        retry_prune = prune_history(&context, &object).await;
    }

    // Steps 0 and 0b: resolve the plan's inventories and clamp them to what NodeAccessPolicy grants
    // this namespace. One fallible step with one error site, because they fail the same way — the
    // desired inputs could not be read — and a recovered run's fate depends on which kind of
    // failure it was, not on which of the two calls produced it.
    let (target_groups, excluded_nodes) =
        match resolve_authorized_inventory(&context, &object).await {
            Ok(resolved) => resolved,
            Err(error) => {
                report_desired_input_error(
                    &context,
                    &object,
                    &api,
                    unlaunched_run.as_ref(),
                    &mut resource_status,
                    &error,
                    format!("cannot resolve the plan's inventories: {error}"),
                )
                .await?;
                return Err(error);
            }
        };
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
    let execution_hash = match hash_playbook_inputs(
        &object.spec.template.playbook,
        &related_secrets,
        &secrets_api,
        &inventory_variables,
    )
    .await
    {
        Ok(hash) => hash,
        Err(error) => {
            // A held run is holding *host Leases* by this point — the inventory resolved, so
            // its hosts are still known-authorized and the hold is safe, but it is not free: the
            // hold renews those Leases every tick, and an indefinite one starves every other plan
            // targeting the same hosts. That is what `input_error_supersedes_unlaunched` bounds.
            report_desired_input_error(
                &context,
                &object,
                &api,
                unlaunched_run.as_ref(),
                &mut resource_status,
                &error,
                format!("cannot read referenced Secrets: {error}"),
            )
            .await?;
            return Err(error);
        }
    };

    if let Some(finished) = &finished_active_run {
        sync_desired_hash_after_finished_run(
            &mut resource_status,
            &execution_hash,
            &finished.run,
            surviving_run.as_deref(),
        );
    } else {
        update_desired_hash(&mut resource_status, &execution_hash);
    }
    if resource_status.active_run.is_some() {
        resource_status.phase = Phase::Applying;
    }

    // Step 1: compute outdated hosts and evaluate the schedule.
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

    // Both desired-input reads got this far, so the readiness overlay they may have left behind is
    // stale. Retired here, after the hash has settled, because that is what decides which hosts are
    // current and therefore what the restated verdict is. A `Ready` written from a terminal `Play`
    // earlier in this tick is not the overlay and is left alone.
    status::clear_inputs_unavailable_condition(&mut resource_status, outdated_hosts.len());

    let hosts_to_trigger = match object.spec.mode {
        ExecutionMode::OneShot => outdated_hosts.clone(),
        ExecutionMode::Recurring => all_hosts.clone(),
    };

    // Filter the resolved inventory to this run's hosts once, preserving the user's groups, so the
    // Job/proxy/render path and the Play history record share one grouped view.
    let run_groups = filter_groups_to_hosts(&target_groups, &hosts_to_trigger);

    // Plain `?`, unlike the desired-input reads above: this hashes two already-deserialized values,
    // so it has no cluster state to fail against and nothing to hold a recovered run open for.
    // Computed once and used for both jobs it has: recording a fresh run's fingerprint, and
    // judging whether a recovered one's still matches.
    let live_preparation_fingerprint = preparation_fingerprint(&object, &run_groups)?;

    let base_run = RunContext {
        namespace,
        name,
        execution_hash,
        run_groups: &run_groups,
        preparation_fingerprint: &live_preparation_fingerprint,
        triggered_slot: None,
    };

    let has_work_to_start = has_work_to_start(
        &object.spec.mode,
        object.spec.schedule.is_some(),
        !hosts_to_trigger.is_empty(),
    );
    let eligible_to_start = may_start_new_run(object.spec.suspend, has_work_to_start);

    // Whether a recorded run's preparation inputs are still the desired ones. While this holds,
    // the plan spec, resolved groups and Job blueprint are re-derivable from live state; once it
    // stops holding, the absent-Job run is superseded.
    let inputs_unchanged = |unlaunched: &UnlaunchedRun| -> bool {
        unlaunched.run.mirror.execution_hash == execution_hash.to_string()
            && live_preparation_fingerprint == unlaunched.preparation_fingerprint
    };

    if let Some(unlaunched) = unlaunched_run {
        requeue_after = std::time::Duration::from_secs(15);
        let slot_is_current = matches!(
            timing,
            Timing::Now(start)
                if start.map(|slot| slot.fixed_offset()) == unlaunched.run.mirror.triggered_slot
        );
        match decide_unlaunched_action(
            &unlaunched.phase,
            inputs_unchanged(&unlaunched),
            has_work_to_start,
            slot_is_current,
        ) {
            UnlaunchedAction::Abandon => {
                info!(
                    "PlaybookPlan {namespace}/{name}: abandoning run {} — it may no longer start (the desired revision changed or it missed its schedule window)",
                    unlaunched.run.mirror.job_name
                );
                abandon_unlaunched_run(
                    &context,
                    &object,
                    &api,
                    &unlaunched.run,
                    unlaunched.phase,
                    "aborted the run: it may no longer start (the desired revision changed \
                     or it missed its schedule window)"
                        .to_string(),
                    &mut resource_status,
                )
                .await?;
                requeue_after = std::time::Duration::from_secs(1);
            }
            UnlaunchedAction::ResumeLaunching { may_proceed } => {
                let resume_with = may_proceed.then_some(run_groups.as_slice());
                let (_action, requeue) = resume_launching_run(
                    &context,
                    &object,
                    &api,
                    &unlaunched.run,
                    resume_with,
                    &mut resource_status,
                )
                .await?;
                if let Some(requeue) = requeue {
                    requeue_after = requeue;
                } else if resource_status.active_run.is_some()
                    // `resume_launching_run` returned without asking for another tick, so this
                    // run's Job exists — adopted or created just now — and its record has been
                    // marked `Running`. Whether that consumes the window is then the same question
                    // the drain path asks, and a superseded run adopted here answers it no.
                    && consumed_its_slot(
                        &v1beta1::PlayPhase::Running,
                        &unlaunched.run.execution_hash,
                        &execution_hash,
                    )
                {
                    record_triggered_slot(
                        &mut resource_status,
                        unlaunched.run.mirror.triggered_slot,
                    );
                }
            }
            UnlaunchedAction::ResumePreparing => {
                let resumed = RunContext {
                    triggered_slot: unlaunched.run.mirror.triggered_slot,
                    ..base_run
                };
                if let Some(requeue) = try_start_run(
                    &context,
                    &resumed,
                    &object,
                    &mut resource_status,
                    Some(&unlaunched),
                )
                .await?
                {
                    requeue_after = requeue;
                } else {
                    // The Job exists now, so this run has consumed its slot — recorded here and
                    // not only on the tick that first prepared it, since a run that spent
                    // several ticks waiting on locks or proxy pods never got that far.
                    record_triggered_slot(
                        &mut resource_status,
                        unlaunched.run.mirror.triggered_slot,
                    );
                }
            }
        }
    } else if let Some(finished) = &finished_active_run {
        if surviving_run.is_some() {
            // A terminal result is drained ahead of anything live (`recover_active_run`), so this
            // tick applied one run's recap while another run is still going. Reporting the drained
            // run's `Succeeded`/`Failed` here would publish a verdict over a plan that is still
            // applying; the next tick recovers that run and reports it properly.
            resource_status.phase = Phase::Applying;
            resource_status.summary =
                Some("recorded a finished run; another run is still in flight".to_string());
            requeue_after = std::time::Duration::from_secs(1);
        } else if finished.run.execution_hash != execution_hash {
            resource_status.phase = Phase::Pending;
            resource_status.next_run = None;
            resource_status.summary =
                Some("previous run finished; replacement revision is pending".to_string());
            requeue_after = std::time::Duration::from_secs(1);
        } else if matches!(
            timing,
            Timing::Now(Some(start))
                if Some(start.fixed_offset()) != finished.run.mirror.triggered_slot
                    && matches!(object.spec.mode, ExecutionMode::Recurring)
        ) {
            // The result stands even though the next run is already due: it is what the plan last
            // did, and `nextRun` is what says another one is coming.
            resource_status.phase = phase_for_finished_run(&finished.outcome);
            resource_status.next_run = match timing {
                Timing::Now(start) => start.map(|start| start.fixed_offset()),
                Timing::Delayed(_) => unreachable!("the guard only accepts Timing::Now"),
            };
            // The recovery path reaches here without having passed the `advance_active_run` branch
            // that reports a finished run, so this states it rather than leaving whatever the last
            // tick said standing over a plan whose next run is already due.
            resource_status.summary =
                Some("previous run finished; the next scheduled run is already due".to_string());
            requeue_after = std::time::Duration::from_secs(1);
        } else {
            let total_count = distinct_host_count(&resource_status.eligible_hosts);
            // Reaching here without a schedule means it was removed mid-run: the eligibility gate
            // normally stops such a plan from ever starting one. Log the anomaly — the run still
            // gets its verdict, it simply has no next slot to advertise.
            if matches!(object.spec.mode, ExecutionMode::Recurring)
                && object.spec.schedule.is_none()
            {
                warn!("Mode is Recurring but schedule is not set!");
            }
            let outcome = decide_terminal(
                &object.spec.mode,
                object.spec.schedule.as_deref(),
                &finished.outcome,
                outdated_hosts.len(),
                total_count,
                now(),
            );

            resource_status.summary = Some(outcome.summary);
            resource_status.phase = outcome.phase;
            resource_status.next_run = outcome.next_run;
            if let Some(requeue) = outcome.requeue {
                requeue_after = requeue;
            }
        }
    } else if resource_status.active_run.is_none()
        && matches!(object.spec.mode, ExecutionMode::OneShot)
        && outdated_hosts.is_empty()
        && resource_status.hosts_status.is_some()
        && resource_status.phase == Phase::Pending
    {
        // A failed input read clears the visible terminal state, but not the per-host results. Once
        // the inputs recover, restore the idle verdict instead of waiting for a hash change.
        let total_count = distinct_host_count(&resource_status.eligible_hosts);
        restore_idle_oneshot_status(&mut resource_status, total_count);
    } else if eligible_to_start && resource_status.active_run.is_none() {
        match timing {
            Timing::Delayed(until) => {
                requeue_after = (until - now()).to_std().unwrap();
                resource_status.phase = phase_while_waiting_for_schedule(&resource_status.phase);
                resource_status.next_run = Some(until.fixed_offset());
            }
            Timing::Now(start) => {
                let this_slot = start.map(|s| s.fixed_offset());

                // The marker first, because it answers from state this tick already holds; the
                // records only when it says the window is free, so the extra read happens once per
                // window rather than on every tick of it.
                let window_taken =
                    if slot_already_triggered(this_slot, resource_status.last_triggered_run) {
                        true
                    } else if let Some(slot) = this_slot {
                        schedule_window_already_taken(&context, &object, slot, &execution_hash)
                            .await?
                    } else {
                        false
                    };

                if window_taken {
                    // Writes the marker back when it was the records that answered, so the rest of
                    // the window is decided from the status again — and so a marker lost to a
                    // conflicting write is repaired rather than left to be re-derived every tick.
                    record_triggered_slot(&mut resource_status, this_slot);
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
                } else {
                    let run = RunContext {
                        triggered_slot: this_slot,
                        ..base_run
                    };
                    if let Some(d) =
                        try_start_run(&context, &run, &object, &mut resource_status, None).await?
                    {
                        requeue_after = d;
                    } else {
                        // `try_start_run` ran to completion (the Job was created or an active one
                        // adopted, so `phase` is now `Applying`). Record this slot so it can't
                        // re-trigger inside its grace window. `None` for unscheduled plans, which
                        // have no slot and are never suppressed.
                        record_triggered_slot(&mut resource_status, this_slot);
                    }
                }
            }
        };
    }

    if retry_prune {
        requeue_after = prune_retry_after(requeue_after);
    }

    // Given back the moment the plan holds nothing outside its own namespace, so deleting an idle
    // plan never waits on this operator. Deliberately conservative about *when* that is: a tick that
    // recovered anything keeps it, even if the run finished on this very tick, because the release
    // it just performed is the last thing that needed the finalizer and one extra tick costs nothing.
    let release_finalizer = !recovered_a_run && resource_status.active_run.is_none();

    patch_status(&api, &object, resource_status).await?;

    // After the plan has been told what this tick decided, and never at its expense. This is a
    // version-checked write (see `patch_finalizers`) against an object the operator has just written
    // the status of, so it loses that race routinely — and losing it must cost one more tick before
    // an idle plan can be deleted, not the whole tick's account of the plan. Doing it the other way
    // round is what left a plan advertising a `nextRun` it would never reach.
    if release_finalizer && let Err(error) = drop_run_cleanup_finalizer(&api, &object).await {
        if !error.is_conflict() {
            return Err(error);
        }
        debug!(
            "Could not give back the run-cleanup finalizer of {namespace}/{name}: the plan changed \
             underneath this tick; retrying shortly"
        );
        requeue_after = requeue_after.min(std::time::Duration::from_secs(5));
    }

    Ok(Action::requeue(requeue_after))
}

/// Whether the current schedule slot (`start`, the grace window's start) already had a run started
/// for it, per the persisted `last_triggered_run`. Unscheduled ticks carry no slot (`None`) and are
/// never suppressed — there is nothing to dedupe against. `DateTime` equality compares instants, so
/// the offset the two timestamps carry is irrelevant.
///
/// The slot alone is the whole dedupe key: `update_desired_hash` clears it whenever the desired
/// revision moves, so an edit takes effect inside the window it was made in, and reverting to an
/// earlier revision is a change like any other and runs again.
fn slot_already_triggered(
    start: Option<DateTime<FixedOffset>>,
    last_triggered_run: Option<DateTime<FixedOffset>>,
) -> bool {
    start.is_some() && start == last_triggered_run
}

/// The second half of the start gate: whether one of this plan's own `Play` records already took
/// this schedule window, read from the apiserver.
///
/// `status.lastTriggeredRun` is a *derived* view of that fact. It is written by whichever tick got
/// a run's Job created, onto a status this tick read from the reflector cache — which lags this
/// controller's own writes — and a merge patch of the whole status re-states it from that cached
/// value on every tick. So a tick running from a status that predates the marker's write, or one
/// whose write was lost to a conflicting write, sees a window nothing has taken and starts a second
/// run for it. That breaks the one property the window exists for: a recurring plan applies its
/// playbook at most once per slot, and a non-idempotent playbook applied twice is a real change to
/// the hosts.
///
/// The records cannot lag in that way — every run books its revision and its slot on its own
/// immutable record *before* anything is created for it — so they, not the marker, are what the gate
/// falls back to.
async fn schedule_window_already_taken(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    slot: DateTime<FixedOffset>,
    desired_hash: &ExecutionHash,
) -> Result<bool, ReconcileError> {
    let (namespace, plan_name) = namespace_and_name(object)?;
    let plays = Api::<Play>::namespaced(context.client.clone(), namespace)
        .list(&ListParams::default().labels(&format!("{}={plan_name}", labels::PLAYBOOKPLAN_NAME)))
        .await?;
    Ok(window_taken_by_a_record(
        &plays.items,
        object,
        slot,
        desired_hash,
    ))
}

/// Whether any record in `plays` describes a run that took `slot` at the desired revision.
///
/// Pure so the rule stays pinned beside [`consumed_its_slot`], which asks the same question of a
/// *live* run and must keep answering it the same way. The two differ in one place only: a
/// terminal record had a Job by definition, while there the terminal phases are excluded because the
/// tick draining the result re-records the window from the run it is finishing. `Prepared`,
/// `Starting` and `Aborted` never reached a Job and hand the window back, exactly as they do there.
/// `Launching` is left out for the same reason — `play_history::abort_unlaunched` accepts it only
/// once its Job is known to be absent — and cannot be seen here anyway: a record still in flight is
/// dispatched long before the start gate is reached.
fn window_taken_by_a_record(
    plays: &[Play],
    plan: &PlaybookPlan,
    slot: DateTime<FixedOffset>,
    desired_hash: &ExecutionHash,
) -> bool {
    let (Some(plan_name), Some(uid)) =
        (plan.metadata.name.as_deref(), plan.metadata.uid.as_deref())
    else {
        return false;
    };
    plays.iter().any(|play| {
        play_belongs_to_plan(play, plan_name, uid)
            && play.spec.triggered_slot == Some(slot)
            && play.spec.execution_hash == desired_hash.to_string()
            && play.status.as_ref().is_some_and(|status| {
                matches!(
                    status.phase,
                    v1beta1::PlayPhase::Running
                        | v1beta1::PlayPhase::Succeeded
                        | v1beta1::PlayPhase::Failed
                        | v1beta1::PlayPhase::Unknown
                )
            })
    })
}

/// Whether the plan has work a run could start this tick, from the mode, whether a schedule is set,
/// and whether any hosts still need triggering. Pure so the gating is unit-testable — in particular
/// the invariant that a schedule-less Recurring plan is never eligible.
///
///   - OneShot keeps applying until every host is on the current hash, then goes quiet — so it's
///     gated purely on there being outdated hosts left (which is exactly `has_hosts_to_trigger`).
///   - Recurring runs on every schedule tick regardless of host hashes (a successful run marks all
///     hosts up-to-date, so an outdated-based gate would fire once and never again). It's gated only
///     on having a schedule to tick on; slot dedup via `last_triggered_run` is what stops a single
///     tick from starting more than one run, and without a schedule there'd be no slot to dedup
///     against — it would busy-loop. That's why the schedule check lives here.
///
/// Deliberately excludes `spec.suspend`. Suspending has to drop a run that has not launched
/// yet, and that decision is made *before* the inventory is resolved
/// ([`resolve_unlaunched_before_inputs`]) — dropping such a run needs no inventory, and
/// deferring it would leave a suspended plan holding host Leases behind a failing inventory read.
/// Starting a *new* run is gated by [`may_start_new_run`] at the one call site that does so; see
/// [`decide_unlaunched_action`] for why the resume path must not fold `suspend` in again.
fn has_work_to_start(mode: &ExecutionMode, has_schedule: bool, has_hosts_to_trigger: bool) -> bool {
    has_hosts_to_trigger
        && match mode {
            ExecutionMode::OneShot => true,
            ExecutionMode::Recurring => has_schedule,
        }
}

/// The start gate: whether this tick may start a *new* run. [`has_work_to_start`] deliberately
/// leaves `spec.suspend` out (see its doc), so this is the one place that folds it back in —
/// pinned as its own function so `suspend` losing its veto breaks a test, not a cluster.
fn may_start_new_run(suspend: bool, has_work_to_start: bool) -> bool {
    !suspend && has_work_to_start
}

/// The phase of a plan whose next run is still ahead of it: `Delayed` until the current revision
/// has a result, and that result from then on.
///
/// A schedule ahead of the plan is only a *lifecycle* state while nothing has been applied yet —
/// that is the plan waiting, and `Delayed` says so. Once a run has finished, what the plan last did
/// is the more useful thing to report, and the wait is fully described by `nextRun`; overwriting the
/// verdict with a state meaning "waiting" would erase the only record of the last run's outcome on
/// the plan itself.
///
/// A verdict is what marks the boundary because it is the one thing only a finished run writes, and
/// it is cleared with the revision it belongs to (`update_desired_hash`): an edited plan is waiting
/// for its first run again, whatever the previous revision achieved.
fn phase_while_waiting_for_schedule(current: &Phase) -> Phase {
    match current {
        Phase::Succeeded | Phase::Failed => current.clone(),
        _ => Phase::Delayed,
    }
}

/// The other half of the suspension contract: while suspended, the plan advertises no next run. The
/// start gate blocks the run itself, so a `nextRun` pointing at a slot that will not fire says the
/// plan is about to do something it will not do — to an operator reading it, and to any client
/// scheduling around it.
///
/// Held where the status is *written* rather than at the end of the pipeline, because a tick has
/// more than one way to write one and only one way to reach the end. A tick that finalizes a run, or
/// that reports an unreadable inventory and gives up, writes the status too — and those writes were
/// carrying whatever `nextRun` the plan already advertised straight back onto it, so a plan
/// suspended while waiting on its schedule could keep advertising its old slot until some later tick happened to
/// run the whole pipeline through. Every write now settles it, so the first one after the suspend
/// takes effect regardless of how the tick ends.
///
/// A run in progress is untouched (it has no `nextRun` anyway) and is left to finish; the phase
/// keeps reflecting the plan's real state, with the `Suspended` printer column (from `.spec.suspend`)
/// signalling the pause. The schedule path recomputes `nextRun` once the plan resumes.
fn suspended_advertises_no_next_run(suspend: bool, status: &mut PlaybookPlanStatus) {
    if suspend {
        status.next_run = None;
    }
}

#[derive(Debug, PartialEq, Eq)]
enum UnlaunchedAction {
    Abandon,
    ResumePreparing,
    ResumeLaunching { may_proceed: bool },
}

/// Decides a recovered absent-Job run after its desired inputs have been resolved. `Prepared`
/// remains subject to the normal start and schedule gates; `Starting` has already acquired its
/// locks, so from here on only an input change supersedes it. `Launching` always goes through
/// `resume_launching_run`, which adopts an existing Job even when `may_proceed` is false.
///
/// Reached **only for a plan that is not suspended**: [`resolve_unlaunched_before_inputs`] resolves
/// every phase's fate under `spec.suspend` before the inventory is read, so a run that gets
/// this far has already survived that gate. `has_work_to_start` is therefore the suspend-free half
/// of the start gate — folding `spec.suspend` back in here would add a condition that can never be
/// false, and reading like a second, independent suspend decision.
fn decide_unlaunched_action(
    phase: &v1beta1::PlayPhase,
    inputs_unchanged: bool,
    has_work_to_start: bool,
    slot_is_current: bool,
) -> UnlaunchedAction {
    let may_proceed = inputs_unchanged
        && (phase != &v1beta1::PlayPhase::Prepared || (has_work_to_start && slot_is_current));
    match phase {
        v1beta1::PlayPhase::Launching => UnlaunchedAction::ResumeLaunching { may_proceed },
        v1beta1::PlayPhase::Prepared | v1beta1::PlayPhase::Starting if may_proceed => {
            UnlaunchedAction::ResumePreparing
        }
        _ => UnlaunchedAction::Abandon,
    }
}

/// What to do with a recovered run once its Job has been looked for.
#[derive(Debug, PartialEq, Eq)]
enum JobPresenceAction {
    /// This run's own Job exists: take the started run over and let it finish.
    Adopt,
    /// Its Job is absent and the run is still wanted: carry on with it.
    Proceed,
    /// Its Job is absent and the run is no longer wanted: release and delete it.
    Abandon,
    /// A Job this run did not create holds its name. Neither adopted nor given up — see
    /// [`decide_job_presence`].
    Contested,
}

/// The rule [`resume_launching_run`] follows, from whether the run is still wanted and what is
/// actually sitting at its Job name. Pure so it stays pinned in one place and unit-testable.
///
/// This run's *own* Job always wins, whatever `may_proceed` says: a started run is never killed
/// by an edit or by `suspend`, and its results belong to the revision it actually ran. Only when the
/// name is free does anything else get a say — which is why what is there is established with a
/// direct apiserver read rather than a watch-cache one.
///
/// **A foreign Job is neither adopted nor a reason to give up.** Name collisions are made unlikely
/// rather than impossible (`job_builder::job_name`), so the name is a hint and the identity check is
/// the boundary. Adopting on the strength of the name would move this run's record to `Running`
/// for work it did not commission and later write the run off as `Unknown`. Abandoning instead may
/// look safe — a foreign Job means this run has none of its own, since the name is deterministic
/// — but it inverts the risk: if the identity check ever rejected a Job that genuinely *was* ours,
/// abandoning would release the host Leases while that Job kept running, which is the double-apply
/// the Leases exist to prevent. Waiting has no such failure mode, and it resolves on its own once
/// the foreign Job is reaped by its `ttlSecondsAfterFinished`, after which the name is free and the
/// run proceeds normally.
fn decide_job_presence(may_proceed: bool, job: RecordedJob) -> JobPresenceAction {
    match (may_proceed, job) {
        (_, RecordedJob::Own) => JobPresenceAction::Adopt,
        (_, RecordedJob::Foreign) => JobPresenceAction::Contested,
        (true, RecordedJob::Absent) => JobPresenceAction::Proceed,
        (false, RecordedJob::Absent) => JobPresenceAction::Abandon,
    }
}

/// What is actually sitting at a recorded run's Job name, read straight from the apiserver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordedJob {
    /// The Job this run created: every identity field `validate_selected_job` checks matches.
    Own,
    /// A Job this run did not create holds the name.
    Foreign,
    /// The name is free.
    Absent,
}

/// Reads what holds this run's Job name and checks whether it is the run's own Job.
///
/// Existence is deliberately *not* treated as identity. The name is derived, and derived names are
/// bounded and therefore lossy, so the only thing that establishes ownership is the identity
/// `validate_selected_job` compares: the plan's owner reference, the execution hash, the run
/// number, the run ID and the `Play` UID — on the Job *and* on its pod template.
async fn job_at_recorded_name(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    run: &RecordedRun,
) -> Result<RecordedJob, ReconcileError> {
    let (namespace, _) = namespace_and_name(object)?;
    let jobs_api = Api::<Job>::namespaced(context.client.clone(), namespace);
    let Some(job) = jobs_api.get_opt(&run.mirror.job_name).await? else {
        return Ok(RecordedJob::Absent);
    };
    Ok(
        match validate_selected_job(
            &job,
            object,
            run.execution_hash,
            run.mirror.run_number,
            &run.mirror.run_id,
            &run.mirror.play_uid,
        ) {
            Ok(()) => RecordedJob::Own,
            Err(_) => RecordedJob::Foreign,
        },
    )
}

/// How `spec.suspend` disposes of a recovered absent-Job run, decided before the desired
/// inputs are read. Pure so the rule that suspending always drops an unlaunched run — and does
/// so through the right door — stays pinned by unit tests rather than implied by control flow.
///
/// Only `Launching` straddles Job creation; the earlier phases cannot have a Job, so for them
/// `suspend` is the whole decision and the run is released outright. A `Launching` run may
/// already have committed its Job, so its fate belongs to [`resume_launching_run`] alone, called
/// with nothing left to resume for.
#[derive(Debug, PartialEq, Eq)]
enum SuspendedUnlaunched {
    /// The run cannot have a Job yet: release its locks and delete its record outright.
    Abandon,
    /// The run straddles Job creation: only [`resume_launching_run`] may decide its fate.
    GiveUpThroughResume,
    /// The plan is not suspended: the gate holds no opinion on the run.
    NotSuspended,
}

fn decide_suspended_unlaunched(phase: &v1beta1::PlayPhase, suspend: bool) -> SuspendedUnlaunched {
    match (suspend, phase) {
        (false, _) => SuspendedUnlaunched::NotSuspended,
        (true, v1beta1::PlayPhase::Launching) => SuspendedUnlaunched::GiveUpThroughResume,
        (true, _) => SuspendedUnlaunched::Abandon,
    }
}

/// Everything that can be decided about a recovered absent-Job run *before* the live desired
/// inputs are read. Returns `true` when the run survives and the remaining gates need those
/// inputs after all — which is also what makes this the sole owner of the two decisions below, and
/// lets [`decide_unlaunched_action`] assume the plan is not suspended.
///
///   - **`spec.suspend`, in every phase.** Dropping a run that has not launched needs no
///     inventory, so it is decided here rather than after resolution: a suspended plan must not sit
///     on its host Leases waiting for an inventory read that may never succeed.
///   - **Whether a `Launching` run's own Job exists.** Checked before input resolution so an
///     existing Job cannot be hidden behind a broken replacement inventory. Only the run's own
///     Job short-circuits here; anything else at the name falls through to
///     [`resume_launching_run`], which owns that decision and can report it.
async fn resolve_unlaunched_before_inputs(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    api: &Api<PlaybookPlan>,
    unlaunched: &UnlaunchedRun,
    resource_status: &mut PlaybookPlanStatus,
) -> Result<bool, ReconcileError> {
    match decide_suspended_unlaunched(&unlaunched.phase, object.spec.suspend) {
        SuspendedUnlaunched::Abandon => {
            abandon_unlaunched_run(
                context,
                object,
                api,
                &unlaunched.run,
                unlaunched.phase.clone(),
                "aborted the run: the plan was suspended before its Job was created".to_string(),
                resource_status,
            )
            .await?;
            return Ok(false);
        }
        SuspendedUnlaunched::GiveUpThroughResume => {
            // Its outcome and requeue hint are dropped deliberately: whichever way it went, a
            // suspended plan has nothing to start next, so there is nothing to come back promptly
            // for.
            let _outcome =
                resume_launching_run(context, object, api, &unlaunched.run, None, resource_status)
                    .await?;
            return Ok(false);
        }
        SuspendedUnlaunched::NotSuspended => {}
    }

    if unlaunched.phase != v1beta1::PlayPhase::Launching {
        return Ok(true);
    }

    // Not suspended: this run's own Job is adopted *now* rather than after inventory resolution,
    // which is what keeps a started run from losing its locks behind a broken replacement inventory.
    // Anything else — a free name, or a Job this run did not create — falls through to the
    // fingerprint and eligibility gates, and from there back to `resume_launching_run` for the real
    // decision, which is also the one place that reports a contested name.
    if job_at_recorded_name(context, object, &unlaunched.run).await? == RecordedJob::Own {
        adopt_started_run(context, object, &unlaunched.run).await?;
        return Ok(false);
    }
    Ok(true)
}

/// Takes over a run whose Job exists: renews its host Leases and moves its record to `Running`, so
/// the rest of the tick advances it like any other in-flight run.
async fn adopt_started_run(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    run: &RecordedRun,
) -> Result<(), ReconcileError> {
    let (namespace, name) = namespace_and_name(object)?;
    let leases_api = Api::<Lease>::namespaced(context.client.clone(), &context.operator_namespace);
    // The outcome is discarded: the Job is already out there, so a host this run no longer protects
    // has nothing safe left to do about it beyond `renew_locks`' own `warn!`.
    let _outcome = locking::renew_locks(
        &leases_api,
        &run.mirror.hosts,
        &holder_identity(namespace, name, run),
    )
    .await?;
    play_history::record_running(
        &context.client,
        namespace,
        &run.mirror.job_name,
        &run.mirror.play_uid,
    )
    .await?;
    Ok(())
}

/// Applies a lock-renewal outcome to a run whose Job does not exist yet, reporting the
/// contended host on the plan and deciding whether the run survives.
///
/// Returns `Some(requeue)` when the tick has to stop short, `None` when every lock is still this
/// run's. The two contended outcomes are deliberately *not* the same:
///
///   - `Lost` is evidence — another holder was observed on the Lease. Two runs applying a playbook
///     to the same host is what the Leases exist to prevent, and a run with no Job can still be
///     given up cleanly, so it is.
///   - `Unconfirmed` is the absence of evidence — a write race, with nobody seen taking the lock
///     over. Tearing a healthy run's node-root infrastructure down on a transient 409 would be a
///     far worse outcome than looking again a second later, so it is only retried.
async fn resolve_contended_locks(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    api: &Api<PlaybookPlan>,
    run: &RecordedRun,
    observed_phase: v1beta1::PlayPhase,
    outcome: locking::RenewalOutcome,
    resource_status: &mut PlaybookPlanStatus,
) -> Result<Option<std::time::Duration>, ReconcileError> {
    let (namespace, name) = namespace_and_name(object)?;
    status::set_blocked_condition(resource_status, outcome.contended());

    match outcome {
        locking::RenewalOutcome::Held => Ok(None),
        locking::RenewalOutcome::Unconfirmed(blocked) => {
            warn!(
                "PlaybookPlan {namespace}/{name}: could not confirm run {}'s lock on host '{}' this tick; looking again before deciding its fate",
                run.mirror.job_name, blocked.host
            );
            resource_status.summary = Some(format!(
                "could not confirm the lock on host '{}'; retrying",
                blocked.host
            ));
            Ok(Some(std::time::Duration::from_secs(1)))
        }
        locking::RenewalOutcome::Lost(blocked) => {
            let holder = blocked.holder.as_deref().unwrap_or("another run");
            warn!(
                "PlaybookPlan {namespace}/{name}: abandoning run {} — host '{}' is now locked by {holder}",
                run.mirror.job_name, blocked.host
            );
            abandon_unlaunched_run(
                context,
                object,
                api,
                run,
                observed_phase,
                format!(
                    "aborted the run: host '{}' is now locked by {holder}",
                    blocked.host
                ),
                resource_status,
            )
            .await?;
            Ok(Some(std::time::Duration::from_secs(1)))
        }
    }
}

/// Gives up a run whose Job does not exist, from the phase the caller observed it in.
///
/// The record is moved to `Aborted` **first**, so it outlives the cleanup that follows and keeps it
/// retryable; `abandon_run` then releases everything, persists a plan status that no longer mentions
/// the run, and finally deletes the record.
///
/// `reason` is the caller's one-line explanation, and it is a parameter rather than something the
/// caller sets beforehand so that giving a run up and saying why cannot come apart — see
/// [`abandon_run`].
async fn abandon_unlaunched_run(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    api: &Api<PlaybookPlan>,
    run: &RecordedRun,
    observed_phase: v1beta1::PlayPhase,
    reason: String,
    resource_status: &mut PlaybookPlanStatus,
) -> Result<(), ReconcileError> {
    let (namespace, _) = namespace_and_name(object)?;
    play_history::abort_unlaunched(
        &context.client,
        namespace,
        &run.mirror.job_name,
        &run.mirror.play_uid,
        observed_phase,
    )
    .await?;
    abandon_run(context, object, api, run, reason, resource_status).await
}

/// Steps 2-5: name the run (or adopt the one a `Play` already records), acquire its per-host
/// locks (all-or-nothing, renewed every tick for as long as the run is in progress), then hand off
/// to [`ensure_infra_and_launch`]. Each guard clause returns early with a short requeue the moment a
/// precondition isn't met yet; `None` means it ran to completion and the Job now exists.
///
/// A fresh run and one resumed from a `Prepared`/`Starting` record both come through here. They
/// differ only in `prepared`: a resumed run keeps the identity its `Play` recorded, while a
/// fresh one mints it and writes the record. Everything after the locks is identical, so it lives in
/// one place — an operator restart mid-setup must not take a different code path than the tick it
/// interrupted.
async fn try_start_run(
    context: &ReconciliationContext,
    run: &RunContext<'_>,
    object: &PlaybookPlan,
    resource_status: &mut PlaybookPlanStatus,
    prepared: Option<&UnlaunchedRun>,
) -> Result<Option<std::time::Duration>, ReconcileError> {
    let leases_api = Api::<Lease>::namespaced(context.client.clone(), &context.operator_namespace);

    // Before the record, the locks and the proxy pods: from here on the plan owns resources its own
    // deletion cannot reach, and the finalizer is the only thing that will release them.
    let plan_api = Api::<PlaybookPlan>::namespaced(context.client.clone(), run.namespace);
    ensure_run_cleanup_finalizer(&plan_api, object).await?;

    let run_groups = run.run_groups;
    let active_run = match prepared {
        // Recomputing the identity for a resume would silently re-derive resource names the record
        // already baked in, so it is read back verbatim. Only the Job blueprint is re-derived, and
        // only because `create_job_blueprint` is a pure function of inputs the caller has already
        // shown unchanged (`preparation_fingerprint`).
        Some(recorded) => recorded.run.clone(),
        None => {
            let jobs_api = Api::<Job>::namespaced(context.client.clone(), run.namespace);
            let selected = select_job(
                &context.client,
                &jobs_api,
                run.execution_hash,
                object,
                resource_status.last_run_number,
            )
            .await?;
            let run_id = run_id(object, &run.execution_hash)?;
            // The recorded inventory — not `hosts_to_trigger` — is what every later step reads the
            // run's host set back from, so it is also what the initial host count is taken from.
            let inventory = flatten_hosts(run_groups);
            let play = play_history::record_prepared(
                &context.client,
                run.namespace,
                &play_history::PlayRef {
                    plan: object,
                    job_name: &selected.job_name,
                    hash: &run.execution_hash,
                    run_id: &run_id,
                    preparation_fingerprint: run.preparation_fingerprint,
                    run_number: selected.run_number,
                    inventory: &inventory,
                    triggered_slot: run.triggered_slot,
                },
            )
            .await?;
            recorded_run_from_play(&play)?
        }
    };

    let holder_identity = holder_identity(run.namespace, run.name, &active_run);
    resource_status.last_run_number = active_run.mirror.run_number;
    resource_status.phase = Phase::Applying;
    resource_status.summary = Some(applying_summary(&active_run.mirror));
    resource_status.next_run = None;
    resource_status.active_run = Some(active_run.mirror.clone());

    if prepared.is_some_and(|run| run.phase == v1beta1::PlayPhase::Starting) {
        // A resumed `Starting` run already holds its locks, so this re-asserts them rather than
        // acquiring a set it may have lost — and only an *observed* takeover gives the run up.
        let outcome =
            locking::renew_locks(&leases_api, &active_run.mirror.hosts, &holder_identity).await?;
        let plan_api = Api::<PlaybookPlan>::namespaced(context.client.clone(), run.namespace);
        if let Some(requeue) = resolve_contended_locks(
            context,
            object,
            &plan_api,
            &active_run,
            v1beta1::PlayPhase::Starting,
            outcome,
            resource_status,
        )
        .await?
        {
            return Ok(Some(requeue));
        }
    } else if let Some(blocked) =
        locking::ensure_locks(&leases_api, &active_run.mirror.hosts, &holder_identity).await?
    {
        // Acquisition is all-or-nothing and took nothing this tick, so there is nothing to give up:
        // the run waits its turn and stays supersedable meanwhile.
        warn!(
            "PlaybookPlan {}/{} is blocked: host '{}' is locked by {}",
            run.namespace,
            run.name,
            blocked.host,
            blocked.holder.as_deref().unwrap_or("another run"),
        );
        status::set_blocked_condition(resource_status, Some(&blocked));
        return Ok(Some(std::time::Duration::from_secs(15)));
    } else {
        // Locks are ours this tick — clear any stale Blocked condition from a previous contended tick.
        status::set_blocked_condition(resource_status, None);
    }

    // Leave `Prepared` only once the locks are held: everything up to here is abortable, so a run
    // that can't take its locks stays supersedable by a newer revision (or by `suspend`) instead of
    // launching a stale one later. Idempotent, so resuming an already-`Starting` run is a no-op.
    play_history::commit_starting(
        &context.client,
        run.namespace,
        &active_run.mirror.job_name,
        &active_run.mirror.play_uid,
    )
    .await?;

    ensure_infra_and_launch(
        context,
        object,
        &active_run,
        run_groups,
        v1beta1::PlayPhase::Starting,
        resource_status,
    )
    .await
}

/// Everything between "this run holds its host Leases and its record says `Starting`" and "its
/// Job exists": live node authorization, the managed-ssh proxy infrastructure, the workspace Secret,
/// the playbook NetworkPolicy, the `Launching` commit, the Job itself, and `Running`.
///
/// Shared verbatim by a fresh run and one resumed after a restart. That sharing is the point:
/// these are the node-root steps, and having a resumed run walk a second, subtly different
/// implementation of them is exactly how an invariant gets lost on the path nobody exercises daily.
///
/// Returns `Some(requeue)` when it stopped short of the Job — proxy pods aren't Ready yet, or the
/// run's nodes lost their grant — and `None` once the Job exists and the record says `Running`.
async fn ensure_infra_and_launch(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    run: &RecordedRun,
    run_groups: &[ResolvedInventoryGroup],
    unlaunched_phase: v1beta1::PlayPhase,
    resource_status: &mut PlaybookPlanStatus,
) -> Result<Option<std::time::Duration>, ReconcileError> {
    let (namespace, name) = namespace_and_name(object)?;
    let (managed_hosts, tolerations) = managed_ssh_hosts_and_tolerations(run_groups);

    // INV-3/INV-3b: proxy pods are node root, so the set about to get them — derived from the groups
    // this tick will actually render, never read back from the record — is what has to be authorized,
    // and it has to be authorized *before* the pods exist. Step 0b already clamped this tick's
    // groups; this re-read closes the window between that clamp and the pods, on the resumed path
    // just as much as the fresh one.
    if !managed_hosts_still_allowed(context, object, &managed_hosts).await? {
        warn!(
            "PlaybookPlan {namespace}/{name}: aborting run {} — its nodes are no longer granted to this namespace",
            run.mirror.job_name
        );
        // Released here rather than left for the next tick to pick up as an `Aborted` record: the
        // run may already hold host Leases and proxy pods, and a grant live policy has just
        // refused is not worth holding those for a moment longer than the cleanup itself takes. The
        // record still outlives the cleanup, so a failure part-way through is retried as before.
        //
        // This is the one abandon of a `Launching` run that does not route through
        // `resume_launching_run` and so does not re-read the Job — see that function's doc for why
        // the exception is safe here and must not be copied elsewhere.
        let api = Api::<PlaybookPlan>::namespaced(context.client.clone(), namespace);
        abandon_unlaunched_run(
            context,
            object,
            &api,
            run,
            unlaunched_phase,
            "aborted the run: its nodes are no longer granted to this namespace".to_string(),
            resource_status,
        )
        .await?;
        return Ok(Some(std::time::Duration::from_secs(1)));
    }

    // Discards half-built infrastructure this run owns that the *current* CA cannot authenticate
    // against — i.e. a resume across an operator restart. A no-op (one `get_opt`) for a run that
    // has not built anything yet.
    managed_ssh::reset_incomplete_run(
        &context.client,
        &context.operator_namespace,
        namespace,
        &run.mirror.run_id,
        &managed_hosts,
        &context.ca,
    )
    .await?;

    let proxy_readiness = managed_ssh::ensure_proxy_infra(
        &context.client,
        &context.operator_namespace,
        namespace,
        &run.execution_hash,
        &run.mirror.run_id,
        &managed_hosts,
        tolerations.as_deref(),
        &context.proxy_grace,
        &context.ca,
        &context.proxy_image,
        context.workload_egress_policies.managed_ssh.clone(),
        // Owns the plan-namespace client-cert Secret so K8s GC reaps it if the plan is deleted
        // before cleanup runs (the per-run delete in `cleanup_proxy_infra` is the primary path).
        &playbookplan_owner_ref(object)?,
    )
    .await?;

    let (ready, unreachable) = match proxy_readiness {
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

    if !unreachable.is_empty() {
        warn!(
            "PlaybookPlan {namespace}/{name}: proceeding without node(s) {unreachable:?} — their managed-ssh proxy pods never became Ready within the grace window; Ansible will report them unreachable, and they'll be retried on the next run",
        );
    }

    // Proxy pod IPs are fresh every time a run's infrastructure is (re)built, so this is rendered
    // unconditionally rather than on a generation change: the workspace Secret has to describe the
    // pods that exist right now, not the plan revision it was last written for.
    let secrets_api = Api::<Secret>::namespaced(context.client.clone(), namespace);
    debug!("Rendering playbook to secret");
    upsert_workspace_secret(
        &secrets_api,
        name,
        render_secret(
            object,
            run_groups,
            &managed_ssh_host_map(ready, unreachable),
        )?,
    )
    .await?;
    resource_status.last_rendered_generation = object.metadata.generation;

    if let Some(network_policy_egress) = context.workload_egress_policies.playbook.clone() {
        job_builder::ensure_job_network_policy(
            context.client.clone(),
            &context.operator_namespace,
            &run.execution_hash,
            &run.mirror.run_id,
            run_groups,
            object,
            network_policy_egress,
        )
        .await?;
    }

    play_history::commit_launching(
        &context.client,
        namespace,
        &run.mirror.job_name,
        &run.mirror.play_uid,
    )
    .await?;
    let jobs_api = Api::<Job>::namespaced(context.client.clone(), namespace);
    launch_recorded_job(&jobs_api, object, run, run_groups).await?;
    play_history::record_running(
        &context.client,
        namespace,
        &run.mirror.job_name,
        &run.mirror.play_uid,
    )
    .await?;

    Ok(None)
}

/// The Ansible-facing view of this run's proxy pods: the Ready ones at their live pod IP, plus the
/// ones whose proxy never came up pointed at the unroutable sentinel (with a short connect timeout,
/// see `inventory_renderer`) so Ansible records them unreachable instead of hanging.
fn managed_ssh_host_map(
    ready: Vec<managed_ssh::ProxyPodInfo>,
    unreachable: Vec<String>,
) -> BTreeMap<String, ansible::ManagedSshHostInfo> {
    let mut hosts: BTreeMap<String, ansible::ManagedSshHostInfo> = ready
        .into_iter()
        .map(|proxy| {
            (
                proxy.host,
                ansible::ManagedSshHostInfo {
                    pod_ip: proxy.pod_ip,
                    port: proxy.port,
                    unreachable: false,
                },
            )
        })
        .collect();

    for host in unreachable {
        hosts.insert(
            host,
            ansible::ManagedSshHostInfo {
                pod_ip: managed_ssh::UNREACHABLE_SENTINEL_IP.to_string(),
                port: managed_ssh::PROXY_SSH_PORT,
                unreachable: true,
            },
        );
    }

    hosts
}

/// What one tick did with the run the plan's status names.
///
/// `Running` carries the requeue interval to wait on it with; `Finished` means the run reached a
/// terminal state and its result now has to be persisted; `AlreadyFinalized` means there was no such
/// run left to advance and the caller's status has been refreshed to say so.
enum ActiveRunProgress {
    Running(std::time::Duration),
    Finished {
        run: RecordedRun,
        /// The verdict the run's record carried, which is what the plan's own phase is decided
        /// from. A run finalized without its record reads `Unknown` here, and that is a failure
        /// like any other: nothing proves its hosts were reached.
        outcome: v1beta1::PlayPhase,
        record: TerminalRecord,
    },
    /// The cached plan status named a run that the apiserver's copy no longer has — an earlier tick
    /// finished it and the reflector had not caught up. Nothing was advanced, and `resource_status`
    /// now holds the live status instead of the stale one.
    AlreadyFinalized,
}

/// Whether a finished run still has its own `Play` behind it — the difference between a result that
/// was *read* from the record and one that had to be reconstructed without it.
///
/// Only the first can be acknowledged. Acknowledgement is a version-checked write against the run's
/// own record, so aiming it at a name whose object is gone (or is now somebody else's) is not a
/// weaker version of the same operation but a different one, and it is right for it to fail. Carrying
/// the distinction here keeps [`play_history::acknowledge_finished`] strict — during ordinary
/// finalization a vanished record and a UID mismatch are both real ownership errors — while letting
/// the one caller that already knows there is nothing to acknowledge skip it.
#[derive(Debug, PartialEq, Eq)]
enum TerminalRecord {
    /// The run's `Play` carried the result and is waiting to be acknowledged.
    Present,
    /// The record is gone, or a different object now holds its name, so the result was reconstructed
    /// from the plan's own copy of the run. There is nothing left to acknowledge.
    Lost,
}

/// Narrows what was found at a run's record name to what is actually *this run's* record.
///
/// A different object under the name is the same fact as no object at all — the recorded run is gone
/// — so both answer `None` and both reach `finalize_lost_run`, which reconstructs the result from the
/// plan's own copy of the run. Pure so the equivalence stays pinned: it is what keeps a replacement
/// run from being finalized, acknowledged or pruned as though it were the run it replaced.
fn own_record(found: Option<Play>, expected_uid: &str) -> Option<Play> {
    found.filter(|play| play.metadata.uid.as_deref() == Some(expected_uid))
}

/// Whether the plan's `activeRun` mirror is `run`'s — the question both paths that *stop* driving a
/// run have to answer before clearing it ([`finalize_finished_run`], [`abandon_run`]).
///
/// An absent mirror answers yes: the tick that finishes a run clears it before either path is reached
/// (`advance_active_run`), and that case still has to reset the phase. What the guard excludes is a mirror
/// describing a *different* run, which is genuinely in flight and is the only thing that would
/// bring it to [`finalize_lost_run`] if its `Play` were deleted. Clearing that would leave its host
/// Leases and node-root proxy pods with nothing pointing at them.
///
/// Pure, and shared, so the two paths cannot drift: the guard was only ever reasoned about on the
/// finalize side, while `abandon_run` reaches the same fields from `recover_active_run`'s `Aborted`
/// branch — the one path that adopts no run first.
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
fn play_is_running(play: &Play) -> Result<bool, ReconcileError> {
    let status = play
        .status
        .as_ref()
        .ok_or(ReconcileError::PreconditionFailed(
            "active Play has no status",
        ))?;
    Ok(status.phase == v1beta1::PlayPhase::Running)
}

/// Steps 6-7: once this run's Job is `Complete`/`Failed`, reads the per-host recap from its pod's
/// termination message, records it on the run's `Play`, folds it into the plan, and tears down the
/// run's locks and proxy infrastructure. While the Job is still active it renews the run's host
/// Leases and reports `Running`.
async fn advance_active_run(
    context: &ReconciliationContext,
    run: &RecordedRun,
    object: &PlaybookPlan,
    resource_status: &mut PlaybookPlanStatus,
) -> Result<ActiveRunProgress, ReconcileError> {
    let (namespace, name) = namespace_and_name(object)?;
    let jobs_api = Api::<Job>::namespaced(context.client.clone(), namespace);
    let leases_api = Api::<Lease>::namespaced(context.client.clone(), &context.operator_namespace);
    let holder_identity = holder_identity(namespace, name, run);

    let job_name = run.mirror.job_name.clone();
    let plays_api = Api::<Play>::namespaced(context.client.clone(), namespace);
    // A record that no longer carries this run's UID counts as absent, not as an error: a different
    // object at the same name is the same fact as no object at all — the recorded run is gone. Both
    // go to `finalize_lost_run`, which re-reads the live plan status and either adopts it (the usual
    // case: an earlier tick already finished this run and the cache lagged) or releases the run. An
    // error here instead would be the one recovery failure with no way out, since it precedes every
    // step that could clear the mirror it disagrees with.
    let Some(play) = own_record(plays_api.get_opt(&job_name).await?, &run.mirror.play_uid) else {
        return finalize_lost_run(context, object, run, resource_status).await;
    };
    // Deliberately silent on the plan, and deliberately the slow interval. Two ticks reach here,
    // and neither wants a message or a prompt return of its own:
    //
    //   - one that drained a queued terminal result while the mirror still named a run that
    //     has not reached `Running`. That tick describes the situation itself, in terms this could
    //     not improve on ("recorded a finished run; another run is still in flight"), and sets
    //     its own one-second requeue afterwards — so a summary written here would only be
    //     overwritten a few steps later, inviting a reader to reconcile two messages that always
    //     disagree about which of the two runs the plan is waiting on.
    //   - a suspended plan whose `Launching` run found a foreign Job at its name.
    //     `resolve_unlaunched_before_inputs` has already reported that through
    //     `resume_launching_run`, which keeps the mirror and asks for fifteen seconds; nothing
    //     between here and the end of the tick will set the interval again, so returning one second
    //     would poll a plan that is suspended *and* blocked once a second for as long as the
    //     foreign Job survives — which can be indefinitely, since a contested name is never
    //     abandoned.
    //
    // Fifteen seconds serves both: the first overrides it, and the second is exactly the cadence
    // the contested path asked for.
    if !play_is_running(&play)? {
        return Ok(ActiveRunProgress::Running(std::time::Duration::from_secs(
            15,
        )));
    }

    // Looked up by the exact recorded name, not the PLAYBOOKPLAN_HASH label — that label is
    // stable across every retry of an unchanged spec, so a label-only `list()` could return
    // an older, already-finished retry's Job instead of the one this run just created.
    let job = jobs_api.get_opt(&job_name).await?;
    let job_is_trusted = match &job {
        Some(job)
            if validate_selected_job(
                job,
                object,
                run.execution_hash,
                run.mirror.run_number,
                &run.mirror.run_id,
                &run.mirror.play_uid,
            )
            .is_err() =>
        {
            if !status::job_finished(job) {
                // Discarded as above: this run's hosts may be occupied by a Job we do not control,
                // so there is nothing safe left to do about a lock it no longer holds.
                let _outcome =
                    locking::renew_locks(&leases_api, &run.mirror.hosts, &holder_identity).await?;
                // The run is past setup, so a `Blocked`/`WaitingForNodes` left over from the
                // tick that started it would otherwise stay on the plan for the whole wait.
                status::clear_run_conditions(resource_status);
                status::set_job_identity_mismatch_condition(resource_status, &job_name);
                resource_status.summary = Some(format!(
                    "waiting for Job {job_name}, which does not carry this run's identity"
                ));
                return Ok(ActiveRunProgress::Running(std::time::Duration::from_secs(
                    15,
                )));
            }
            false
        }
        Some(_) => true,
        None => false,
    };

    // Still running -> renew this run's host locks so a run that outlasts the lease duration keeps
    // them (they're acquired once at start and otherwise never touched again while Applying), then
    // keep waiting.
    if let Some(job) = &job
        && !status::job_finished(job)
    {
        // As above: the Job is already running, so a lost lock is reported and nothing more.
        let _outcome =
            locking::renew_locks(&leases_api, &run.mirror.hosts, &holder_identity).await?;
        status::clear_run_conditions(resource_status);
        status::set_running_condition(resource_status);
        resource_status.summary = Some(applying_summary(&run.mirror));
        return Ok(ActiveRunProgress::Running(std::time::Duration::from_secs(
            15,
        )));
    }

    // The Job either finished, or is already gone — reaped by Kubernetes' TTL controller (its result
    // outlived a long operator outage) or deleted out from under us. Both mean the run is over: read
    // the recap from the pod's termination message if the Job is still there, otherwise the outcome
    // is lost and every host falls to `Unknown`. Not returning early on a missing Job is what keeps
    // a reaped run from wedging in `Applying` forever. The recap comes from the container's
    // termination message (what the callback wrote to /dev/termination-log), not logs — a dedicated
    // channel that isn't interleaved with playbook output and needs no `pods/log` access.
    let parsed = match (&job, job_is_trusted) {
        (Some(job), true) => {
            let pods_api: Api<Pod> = Api::namespaced(context.client.clone(), namespace);
            pods_api
                .list(&ListParams {
                    label_selector: Some(format!("job-name={job_name}")),
                    ..Default::default()
                })
                .await?
                .items
                .iter()
                .filter(|pod| {
                    annotation_value(&pod.metadata, labels::PLAY_UID_ANNOTATION)
                        == Some(run.mirror.play_uid.as_str())
                        && pod_belongs_to_job(pod, job)
                })
                .find_map(termination_message)
                .as_deref()
                .and_then(callback_output::parse_callback_output)
        }
        _ => None,
    };

    release_run_infrastructure(context, object, run).await?;

    // A terminal Play is the durable marker that cleanup completed. If any step above fails, the
    // Play remains Running and the next reconcile safely retries finalization.
    let finished_play = play_history::record_finished(
        &plays_api,
        play,
        &run.mirror.play_uid,
        &run.mirror.hosts,
        parsed.as_ref(),
    )
    .await?;
    let finished_status =
        finished_play
            .status
            .as_ref()
            .ok_or(ReconcileError::PreconditionFailed(
                "finished Play has no status",
            ))?;
    let outcome = finished_status.phase.clone();
    status::apply_terminal_play_status(&run.execution_hash, finished_status, resource_status);
    resource_status.active_run = None;
    Ok(ActiveRunProgress::Finished {
        run: run.clone(),
        outcome,
        record: TerminalRecord::Present,
    })
}

/// Finalizes a run whose `Play` is gone: its infrastructure is released and every targeted host is
/// reported `Unknown`, because without the record nothing about the run can be recovered. Wedging in
/// `Applying` on a record that is never coming back would hold this plan's host locks indefinitely.
///
/// First, though, it re-reads the plan **from the apiserver**. The run this is called for comes from
/// the reflector-cached status, which lags this controller's own writes, so a tick that raced ahead
/// of that cache can arrive here for a run a previous tick already finished, acknowledged and pruned
/// (a `historyLimit` of 0 prunes it immediately). Reporting that run lost would overwrite a
/// perfectly good recap with `Unknown` for every host. When the live status disagrees, it is adopted
/// wholesale — it is strictly newer than the copy this tick started from — and nothing is finalized.
async fn finalize_lost_run(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    run: &RecordedRun,
    resource_status: &mut PlaybookPlanStatus,
) -> Result<ActiveRunProgress, ReconcileError> {
    let (namespace, name) = namespace_and_name(object)?;

    let live_status = Api::<PlaybookPlan>::namespaced(context.client.clone(), namespace)
        .get_status(name)
        .await?
        .status;
    let still_active = live_status
        .as_ref()
        .and_then(|status| status.active_run.as_ref())
        .is_some_and(|mirrored| mirrored.play_uid == run.mirror.play_uid);
    if !still_active {
        debug!(
            "PlaybookPlan {namespace}/{name}: run {} was already finalized by an earlier tick; refreshing the cached status",
            run.mirror.job_name
        );
        *resource_status = live_status.unwrap_or_default();
        return Ok(ActiveRunProgress::AlreadyFinalized);
    }

    warn!(
        "PlaybookPlan {namespace}/{name}: Play {} is gone; finalizing its run as lost",
        run.mirror.job_name
    );

    release_run_infrastructure(context, object, run).await?;

    let lost_status = play_history::lost_run_status(&run.mirror.job_name, &run.mirror.hosts);
    let outcome = lost_status.phase.clone();
    status::apply_terminal_play_status(&run.execution_hash, &lost_status, resource_status);
    resource_status.active_run = None;
    Ok(ActiveRunProgress::Finished {
        run: run.clone(),
        outcome,
        record: TerminalRecord::Lost,
    })
}

/// Completes a run whose Job creation was already committed — and the **only** place that decides
/// the fate of a `Launching` run.
///
/// `Launching` is the one phase where "abandon the superseded run" is not unconditionally
/// available, because the Job may already be out there doing node-root work under this run's
/// identity. `resume_with` says which it is: `Some(groups)` when the run may still launch — the
/// groups are the inputs to converge it against — and `None` when it may not, because the desired
/// revision moved on, the plan was suspended, or those inputs could not be read at all.
/// [`decide_job_presence`] turns that, plus what [`job_at_recorded_name`] found, into the action —
/// which is also returned, so a caller that has to describe the outcome reads it rather than
/// inferring it from what the status happens to look like afterwards.
///
/// The read is a direct `get_opt` against the apiserver rather than a watch-cache one, and it is
/// repeated here even when `resolve_unlaunched_before_inputs` already did one. That matters: a
/// `create` whose response was lost still leaves a real Job, everything between the two reads is a
/// window for it to become visible, and a stale answer would tear infrastructure down out from under
/// a live run. Every path that abandons a `Launching` run *because the plan moved on* routes
/// through here for exactly that reason — including `suspend`, which has no inventory to converge
/// against and so arrives with `resume_with` of `None`.
///
/// There is one deliberate exception, and it is not a "the plan moved on" abandon:
/// `ensure_infra_and_launch` gives a run up on the spot when live policy has just revoked its
/// nodes, without coming back here. Re-reading the Job would change nothing — the run is only
/// there because this function *just* read it as absent, and nothing between the two reads creates
/// Jobs — while routing it back would recurse. Do not copy the shortcut into a path where the
/// intervening work can span a Job creation.
async fn resume_launching_run(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    api: &Api<PlaybookPlan>,
    run: &RecordedRun,
    resume_with: Option<&[ResolvedInventoryGroup]>,
    resource_status: &mut PlaybookPlanStatus,
) -> Result<(JobPresenceAction, Option<std::time::Duration>), ReconcileError> {
    let (namespace, name) = namespace_and_name(object)?;
    let found = job_at_recorded_name(context, object, run).await?;

    let action = decide_job_presence(resume_with.is_some(), found);
    let requeue = match action {
        JobPresenceAction::Proceed => {
            let Some(run_groups) = resume_with else {
                unreachable!("`Proceed` is only reachable while `resume_with` is `Some`")
            };
            let leases_api =
                Api::<Lease>::namespaced(context.client.clone(), &context.operator_namespace);
            let holder_identity = holder_identity(namespace, name, run);
            let outcome =
                locking::renew_locks(&leases_api, &run.mirror.hosts, &holder_identity).await?;
            if let Some(requeue) = resolve_contended_locks(
                context,
                object,
                api,
                run,
                v1beta1::PlayPhase::Launching,
                outcome,
                resource_status,
            )
            .await?
            {
                Some(requeue)
            } else {
                ensure_infra_and_launch(
                    context,
                    object,
                    run,
                    run_groups,
                    v1beta1::PlayPhase::Launching,
                    resource_status,
                )
                .await?
            }
        }
        JobPresenceAction::Adopt => {
            info!(
                "PlaybookPlan {namespace}/{name}: Job {} appeared while recovery was resolving its inputs; adopting the started run",
                run.mirror.job_name
            );
            adopt_started_run(context, object, run).await?;
            None
        }
        JobPresenceAction::Abandon => {
            info!(
                "PlaybookPlan {namespace}/{name}: abandoning run {} — it may no longer launch and its Job was never created",
                run.mirror.job_name
            );
            abandon_unlaunched_run(
                context,
                object,
                api,
                run,
                v1beta1::PlayPhase::Launching,
                "aborted the run: it may no longer launch and its Job was never created"
                    .to_string(),
                resource_status,
            )
            .await?;
            // A short requeue, matching every other abandon path: nothing of this run is left,
            // so the replacement revision should be prepared promptly rather than after the
            // caller's Job-polling interval.
            Some(std::time::Duration::from_secs(1))
        }
        JobPresenceAction::Contested => {
            warn!(
                "PlaybookPlan {namespace}/{name}: run {} cannot launch — a Job it did not create holds its name",
                run.mirror.job_name
            );
            // The run keeps its host Leases while it waits. It reached `Launching`, so it may
            // already own node-root proxy pods on these hosts, and it is not giving up — so the
            // protection has to stay. The renewal outcome is discarded for the same reason
            // `advance_active_run` discards it against a foreign Job: a host this run no longer
            // holds may be occupied by work it does not control, and there is nothing safe left to
            // do about that from here.
            let leases_api =
                Api::<Lease>::namespaced(context.client.clone(), &context.operator_namespace);
            let _outcome = locking::renew_locks(
                &leases_api,
                &run.mirror.hosts,
                &holder_identity(namespace, name, run),
            )
            .await?;
            resource_status.summary = Some(format!(
                "waiting for Job {}, which does not carry this run's identity",
                run.mirror.job_name
            ));
            Some(std::time::Duration::from_secs(15))
        }
    };

    Ok((action, requeue))
}

/// Drops an `Aborted` run for good: releases everything it holds, persists a plan status that no
/// longer references it, and only then deletes the record. Ordering matters — the record is what
/// makes the cleanup retryable, so it must outlive every step that can fail.
///
/// `reason` becomes the plan's summary, and taking it as a parameter is what makes that
/// unconditional. The phase this leaves behind (`Pending`) says only that nothing is happening, and
/// a plan can rest there indefinitely — a suspended one, or a `OneShot` with nothing left to do —
/// so an abandon that wrote no summary would leave whatever the last one happened to say standing
/// as the explanation for a state it does not describe.
///
/// Both fallible steps report themselves on the plan before handing the error back. This is the path
/// that gives up a run's node-root proxy pods and host Leases, so "it did not work" has to be
/// readable on the resource too, not only in the operator's log.
///
/// The mirror is given up only when it is *this* run's, exactly as in [`finalize_finished_run`]: it
/// is what lets the operator release a run whose `Play` was deleted out from under it
/// ([`finalize_lost_run`]), so clearing it for a run it does not describe would leave that run's
/// host Leases and node-root proxy pods with nothing pointing at them. Every caller reached through
/// [`abandon_unlaunched_run`] has just written this run into the mirror, so the guard is only
/// load-bearing on the `Aborted` recovery path, which adopts no run and inherits whatever the
/// reflector cache held. Stating it here rather than relying on that reasoning keeps the abandon and
/// finalize paths the same shape.
async fn abandon_run(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    api: &Api<PlaybookPlan>,
    run: &RecordedRun,
    reason: String,
    resource_status: &mut PlaybookPlanStatus,
) -> Result<(), ReconcileError> {
    let (namespace, _) = namespace_and_name(object)?;
    resource_status.summary = Some(reason);
    if let Err(error) = release_run_infrastructure(context, object, run).await {
        return Err(report_failed_abandon(api, object, run, resource_status, error).await);
    }

    if mirrors_run(resource_status, run) {
        resource_status.active_run = None;
        resource_status.phase = Phase::Pending;
        resource_status.next_run = None;
    }
    status::clear_run_conditions(resource_status);
    patch_status(api, object, resource_status.clone()).await?;

    if let Err(error) = play_history::delete_aborted(
        &context.client,
        namespace,
        &run.mirror.job_name,
        &run.mirror.play_uid,
    )
    .await
    {
        return Err(report_failed_abandon(api, object, run, resource_status, error).await);
    }
    Ok(())
}

/// Records why an abandon could not complete on the plan and hands the error straight back.
///
/// Best effort, and deliberately so: the reconcile fails on `error` either way, and a failure to
/// report must not replace the diagnosis it was trying to surface. Same shape as the recovery
/// failure path in `reconcile` and as `preserve_unlaunched_run_after_error`.
async fn report_failed_abandon(
    api: &Api<PlaybookPlan>,
    object: &PlaybookPlan,
    run: &RecordedRun,
    resource_status: &mut PlaybookPlanStatus,
    error: ReconcileError,
) -> ReconcileError {
    resource_status.summary = Some(format!(
        "could not release the abandoned run {}: {error}",
        run.mirror.job_name
    ));
    if let Err(patch_error) = patch_status(api, object, resource_status.clone()).await {
        warn!(
            "Could not report the failed abandon of run {} on {:?}/{:?}: {patch_error}",
            run.mirror.job_name, object.metadata.namespace, object.metadata.name
        );
    }
    error
}

/// Records why a finished run could not be completed on the plan and hands the error straight back.
///
/// Covers everything between "the Job reached a terminal state" and "the record has been handed back
/// to history": releasing the run's proxy pods and host Leases, stamping the recap onto its `Play`,
/// persisting that to the plan, and acknowledging it. Until those succeed, the run still owns
/// node-root resources — so the plan must say so rather than standing at "applying run …" while only
/// the log knows. They are all retried through the run's recovery record.
///
/// Deliberately *not* reached by a failure of the retention pass that follows acknowledgement. By
/// then the run is genuinely complete: its recap is on the plan and its record is acknowledged, so
/// nothing here is still owed and every resource this message sends a reader looking for has already
/// been released. [`prune_history`] reports that failure by return value instead, and the caller
/// only shortens the requeue.
///
/// Best effort, and deliberately so, for the same reason as [`report_failed_abandon`]: the reconcile
/// fails on `error` either way, and a failure to report must not replace the diagnosis it was trying
/// to surface.
async fn report_failed_finalization(
    api: &Api<PlaybookPlan>,
    object: &PlaybookPlan,
    run: &RecordedRun,
    resource_status: &mut PlaybookPlanStatus,
    error: ReconcileError,
) -> ReconcileError {
    resource_status.summary = Some(format!(
        "could not complete run {}: {error}",
        run.mirror.job_name
    ));
    if let Err(patch_error) = patch_status(api, object, resource_status.clone()).await {
        warn!(
            "Could not report the failed completion of run {} on {:?}/{:?}: {patch_error}",
            run.mirror.job_name, object.metadata.namespace, object.metadata.name
        );
    }
    error
}

/// The history-retention pass, run either as the last step of [`finalize_finished_run`] or — on a
/// tick that finalized nothing and has no run in flight — standalone from `reconcile`. The two are
/// mutually exclusive, so the tick a run completes does not also list and delete the same history
/// standalone.
///
/// That is not the same as "once per tick", and it is worth not claiming it is. One tick can finalize
/// *two* runs — a terminal record queued behind a live run is drained first, and the run it
/// was queued behind can reach its own terminal state in the same tick — and each finalization prunes
/// after acknowledging its own result. The second pass is a redundant list on a rare tick rather than
/// a correctness problem: the pass is idempotent, and it has to follow acknowledgement, so it cannot
/// simply be hoisted out of finalization and run once at the end.
///
/// It has to be reachable from an ordinary reconcile and not only from finalization: a terminal
/// Play is acknowledged *before* the pass that would delete it, so a deletion that fails leaves an
/// idle plan with no event that would ever retry it.
///
/// That is also the whole of what the standalone pass is for, which is why the caller runs it only
/// while nothing is in flight. Retention gains work only when a run finishes, and a plan with an
/// run in flight is requeued every 5-15s — listing its history on each of those ticks is a
/// steady, unindexed apiserver read that can only ever find the same nothing. Deferring a failed
/// deletion until the run ends costs a few retained records for the length of one run; the record it
/// would have deleted is acknowledged history and owns nothing.
///
/// Failures are reported by return value rather than by `?`. Retention is bookkeeping — by the time
/// it runs, the run's result is already on the plan and its record acknowledged — so it must not
/// fail a tick whose real work succeeded, and must not be reported as one of the teardown failures
/// [`report_failed_finalization`] describes. The caller only shortens the requeue so the deletion is
/// tried again soon.
async fn prune_history(context: &ReconciliationContext, object: &PlaybookPlan) -> bool {
    let Some(namespace) = object.metadata.namespace.as_deref() else {
        return false;
    };
    if let Err(error) = play_history::prune(&context.client, namespace, object).await {
        warn!(
            "Could not prune Play history for {:?}/{:?}: {error}",
            object.metadata.namespace, object.metadata.name
        );
        return true;
    }
    false
}

fn prune_retry_after(current: std::time::Duration) -> std::time::Duration {
    current.min(std::time::Duration::from_secs(15))
}

/// Reports on the plan that its desired inputs could not be read, for a tick with no run in
/// flight to hold open.
///
/// Both desired-input reads — the inventories and the referenced Secrets — come through here, so a
/// plan that cannot resolve what it should be running says so on the resource rather than only in
/// the operator's log. Without it the last successful run's summary keeps standing over a plan that
/// has been failing every tick since, which reads as "nothing to do" rather than "broken".
///
/// The phase and `nextRun` are reset for the same reason the summary is written: they are the other
/// two printer columns, and leaving a `Succeeded`/`Delayed` phase over a plan that has not been
/// able to read its own inputs since — pointing, in both cases, at a slot that will not fire — is
/// exactly the "nothing to do" reading this exists to prevent. `hostsStatus` is left
/// alone: the previous run's per-host results are still true, and nothing here re-ran anything.
///
/// A run still in flight keeps its phase, matching [`update_desired_hash`]'s guard. The read failure
/// does not stop a Job that is already executing, and reporting `Pending` over one would contradict
/// the `activeRun` standing right next to it.
///
/// Best effort, and deliberately so: the reconcile fails on the original error either way, and a
/// failure to report must not replace the diagnosis it was trying to surface. Same shape as
/// [`report_failed_abandon`] and the recovery failure path in [`reconcile`].
async fn report_input_failure(
    api: &Api<PlaybookPlan>,
    object: &PlaybookPlan,
    resource_status: &mut PlaybookPlanStatus,
    summary: String,
) {
    record_input_failure(resource_status, summary);
    if let Err(patch_error) = patch_status(api, object, resource_status.clone()).await {
        warn!(
            "Could not report a desired-input read failure on {:?}/{:?}: {patch_error}",
            object.metadata.namespace, object.metadata.name
        );
    }
}

/// The status half of [`report_input_failure`], split from the write so the guard is unit-testable
/// without a kube client — see that function for why each field is (or is not) touched.
fn record_input_failure(status: &mut PlaybookPlanStatus, summary: String) {
    status::set_inputs_unavailable_condition(status, &summary);
    status.summary = Some(summary);
    if status.active_run.is_none() {
        status.phase = Phase::Pending;
        status.next_run = None;
    }
}

/// Keeps a deferred unlaunched run safe when a prerequisite needed to decide its fate cannot be
/// read. `Starting` and `Launching` may hold Leases; renewing them here prevents a transient or
/// persistent inventory/policy error from letting another run acquire the same hosts while this
/// run's proxy pods or Job still exist. `Prepared` has not acquired anything and must stay that
/// way. Reporting is best effort because the original error remains the reconcile result.
///
/// The summary is only claimed if nothing better is already there. A step that fails *after*
/// deciding the run's fate reports itself — `report_failed_abandon` names the run whose
/// node-root proxy pods and host Leases could not be released, and tells the reader which manual
/// cleanup applies. Writing "run recovery paused" over that would replace a specific, actionable
/// diagnosis with a vague one, for the same error.
async fn preserve_unlaunched_run_after_error(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    api: &Api<PlaybookPlan>,
    unlaunched: &UnlaunchedRun,
    resource_status: &mut PlaybookPlanStatus,
    error: &ReconcileError,
) {
    let Ok((namespace, name)) = namespace_and_name(object) else {
        return;
    };

    if unlaunched.phase != v1beta1::PlayPhase::Prepared {
        let leases_api =
            Api::<Lease>::namespaced(context.client.clone(), &context.operator_namespace);
        if let Err(lock_error) = locking::renew_locks(
            &leases_api,
            &unlaunched.run.mirror.hosts,
            &holder_identity(namespace, name, &unlaunched.run),
        )
        .await
        {
            warn!(
                "Could not preserve host locks while recovery of {namespace}/{name} is paused: {lock_error}"
            );
        }
    }

    if summary_unclaimed_since_adoption(resource_status, &unlaunched.run.mirror) {
        resource_status.summary = Some(format!("run recovery paused: {error}"));
    }
    if let Err(patch_error) = patch_status(api, object, resource_status.clone()).await {
        warn!("Could not report paused run recovery on {namespace}/{name}: {patch_error}");
    }
}

/// Reports a failed desired-input read on the plan, whichever of the two reads it came from and
/// whether or not a run is waiting behind it.
///
/// Both reads — the inventories and the referenced Secrets — fail the same way and are answered the
/// same way, so the choice between the two reporting paths is made once here instead of at each
/// call site. What differs between them is only the diagnostic, which the caller passes in.
///
/// The caller still returns the original error afterwards: this reports, it does not decide the
/// tick's outcome.
async fn report_desired_input_error(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    api: &Api<PlaybookPlan>,
    unlaunched: Option<&UnlaunchedRun>,
    resource_status: &mut PlaybookPlanStatus,
    error: &ReconcileError,
    summary: String,
) -> Result<(), ReconcileError> {
    match unlaunched {
        Some(unlaunched) => {
            handle_unlaunched_input_error(
                context,
                object,
                api,
                unlaunched,
                resource_status,
                error,
                &summary,
            )
            .await
        }
        // Nothing in flight to hold open, but the plan still has to say why it is not running: a
        // deleted inventory or Secret would otherwise leave the last successful run's summary
        // standing while every tick fails in the log only.
        None => {
            report_input_failure(api, object, resource_status, summary).await;
            Ok(())
        }
    }
}

/// Decides what a failed desired-input read means for a run whose Job does not exist yet, and
/// reports the outage on the plan either way.
///
/// `summary` is the same diagnostic the no-run path ([`report_input_failure`]) would have
/// written, and it is passed in rather than rebuilt here so both paths describe one outage in one
/// wording. The readiness overlay is set before the branch because it is true of every outcome
/// below: whether the run is held, adopted or given up, the plan cannot read what it should be
/// running, and `Ready` is the column that says so. Leaving it to the *next* tick's no-run path
/// would let the last run's verdict stand over an outage for as long as a run was being held —
/// which, for a transient error, is exactly the case that can persist.
///
/// Reporting is not left to whatever the chosen outcome writes, because each of them can fail before
/// writing anything: the transient branch ends in a status write of its own, and the superseding one
/// publishes the outage up front. What follows may still replace the summary with something more
/// specific — which run was aborted, or that a started Job was adopted instead — but it can no longer
/// leave the plan showing only the previous run's verdict.
///
/// The phase is deliberately not touched here, unlike in [`record_input_failure`]: a run is in
/// flight, and `Pending` would contradict the `activeRun` standing next to it.
async fn handle_unlaunched_input_error(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    api: &Api<PlaybookPlan>,
    unlaunched: &UnlaunchedRun,
    resource_status: &mut PlaybookPlanStatus,
    error: &ReconcileError,
    summary: &str,
) -> Result<(), ReconcileError> {
    status::set_inputs_unavailable_condition(resource_status, summary);

    if !input_error_supersedes_unlaunched(error) {
        preserve_unlaunched_run_after_error(
            context,
            object,
            api,
            unlaunched,
            resource_status,
            error,
        )
        .await;
        return Ok(());
    }

    let (namespace, name) = namespace_and_name(object)?;
    info!(
        "PlaybookPlan {namespace}/{name}: giving up on run {} because its desired inputs cannot be resolved: {error}",
        unlaunched.run.mirror.job_name
    );

    // Persist the outage *before* the supersede below, which the transient branch above does not
    // need because it always ends in a status write of its own. Every step from here can fail in a
    // way that returns before anything reaches the apiserver — a Job read, a record transition, a
    // cleanup — and the plan would then show neither the read that failed nor the run it is about to
    // give up on, only the previous run's verdict. The outage is already decided and true at this
    // point, so it is safe to publish ahead of what is done about it; the specific outcome replaces
    // the summary below on success.
    resource_status.summary = Some(summary.to_string());
    if let Err(patch_error) = patch_status(api, object, resource_status.clone()).await {
        warn!("Could not report unreadable desired inputs on {namespace}/{name}: {patch_error}");
    }

    // A `Launching` run is never abandoned on the strength of the pre-input Job read alone:
    // `resolve_inventory` has run since, and that is exactly the window in which a `create` whose
    // response was lost becomes visible. Hand it to the one function that owns that boundary, with
    // no inputs to converge against — this run may not launch, so all that is left for it is
    // adopting an existing Job or abandoning an absent one.
    if unlaunched.phase == v1beta1::PlayPhase::Launching {
        let (action, _requeue) =
            resume_launching_run(context, object, api, &unlaunched.run, None, resource_status)
                .await?;
        // Read off the action rather than inferred from the status: `Contested` also leaves the run
        // mirrored, so "is there still an `activeRun`?" would report a contested name as an adoption.
        match action {
            JobPresenceAction::Adopt => {
                resource_status.summary = Some(format!(
                    "adopted the started run; the desired inputs cannot be resolved: {error}"
                ));
            }
            JobPresenceAction::Abandon => {
                resource_status.summary = Some(format!(
                    "aborted the run because its desired inputs cannot be resolved: {error}"
                ));
            }
            // `Contested` explained itself, and more usefully than this could. `Proceed` cannot
            // happen: it needs inputs to converge against, and this run has none.
            JobPresenceAction::Contested | JobPresenceAction::Proceed => {}
        }
        return patch_status(api, object, resource_status.clone()).await;
    }

    abandon_unlaunched_run(
        context,
        object,
        api,
        &unlaunched.run,
        unlaunched.phase.clone(),
        format!("aborted the run because its desired inputs cannot be resolved: {error}"),
        resource_status,
    )
    .await
}

/// Whether failing to read the plan's desired inputs is a reason to give an unlaunched run up.
///
/// The line is whether the failure can plausibly clear on its own. A referenced resource that does
/// not exist, or an inventory that names a variable the operator manages, leaves no executable
/// desired state to resume the run against, so it is superseded and a fresh one starts once the
/// input is fixed. Anything else — including a 404 that arrived as a bare `KubeError`, which no read
/// site has classified — is treated as transient and holds the run open instead.
///
/// Both desired-input reads route through here, so the two cannot drift: a deleted `ClusterInventory`
/// and a deleted variables Secret end the same way.
fn input_error_supersedes_unlaunched(error: &ReconcileError) -> bool {
    match error {
        ReconcileError::ReservedInventoryVariable { .. }
        | ReconcileError::InventoryNotFound { .. }
        | ReconcileError::SecretNotFound { .. } => true,
        ReconcileError::KubeError(_) => false,
        ReconcileError::PreconditionFailed(_)
        | ReconcileError::RenderError(_)
        | ReconcileError::CaError(_)
        | ReconcileError::JsonSerializationError(_)
        | ReconcileError::YamlSerializationError(_) => false,
    }
}

/// Gives back a run's proxy infrastructure and then its host Leases. Cleanup failures propagate so
/// the caller retains the Play as its retry handle; `cleanup_proxy_infra` documents the resource
/// ordering and revocation details.
async fn release_run_infrastructure(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    run: &RecordedRun,
) -> Result<(), ReconcileError> {
    let (namespace, name) = namespace_and_name(object)?;
    managed_ssh::cleanup_proxy_infra(
        &context.client,
        &context.operator_namespace,
        namespace,
        &run.execution_hash,
        &run.mirror.run_id,
        name,
    )
    .await?;
    let leases_api = Api::<Lease>::namespaced(context.client.clone(), &context.operator_namespace);
    locking::release_locks(
        &leases_api,
        &run.mirror.hosts,
        &holder_identity(namespace, name, run),
    )
    .await
}

/// Keeps a deleted plan around until the resources its run holds outside the plan's namespace are
/// gone.
///
/// Everything a run creates in the plan's *own* namespace carries an `OwnerReference` to the plan
/// and is reaped by Kubernetes when the plan goes. Its proxy pods, their NetworkPolicy and Secret,
/// and its host Leases live in the operator's namespace, where an owner reference is not allowed to
/// reach — so nothing but this operator can ever release them. Without the finalizer a deleted plan
/// leaves a node-root proxy pod running and a host Lease held by an identity that will never renew
/// or release it, locking that host against every other plan until it expires.
///
/// Held only while a run actually owns such resources, never on an idle plan: a finalizer that is
/// always present makes a plan undeletable for as long as the operator is down, and there is nothing
/// to clean up between runs.
pub const RUN_CLEANUP_FINALIZER: &str = "ansible.cloudbending.dev/run-cleanup";

/// Tears down a deleted plan's run and then lets the object go.
///
/// The plan's spec and status survive for as long as the finalizer does, so `status.activeRun` — the
/// same mirror `finalize_lost_run` recovers a run by — is still readable here. That is the primary
/// handle: the `Play` records are owned by the plan and may already be halfway through their own
/// cascade by the time this runs.
///
/// The run's Job is cancelled and *awaited* before anything is released, because releasing a host
/// Lease while Ansible may still be talking to that host is the one outcome the whole locking design
/// exists to prevent. The wait is unbounded and renews the run's Leases while it lasts: a plan that
/// will not finish deleting is visible and fixable, whereas a host handed to another plan while a
/// playbook is still running against it is neither.
async fn release_deleted_plan(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
) -> Result<Action, ReconcileError> {
    if !holds_run_cleanup_finalizer(object) {
        return Ok(Action::await_change());
    }
    let (namespace, name) = namespace_and_name(object)?;
    let api = Api::<PlaybookPlan>::namespaced(context.client.clone(), namespace);

    let runs = runs_to_release(context, object).await?;
    let mut executing = false;
    for run in &runs {
        executing |= cancel_run_job(context, object, run).await?;
    }
    if executing {
        return Ok(Action::requeue(std::time::Duration::from_secs(5)));
    }

    for run in &runs {
        release_run_infrastructure(context, object, run).await?;
        info!(
            "PlaybookPlan {namespace}/{name} was deleted; released run {}",
            run.mirror.job_name
        );
    }

    patch_finalizers(
        &api,
        object,
        without_run_cleanup_finalizer(&object.metadata.finalizers),
    )
    .await?;
    Ok(Action::await_change())
}

/// Every run of a deleted plan that may still hold resources, newest handle first.
///
/// The records are listed before anything is released and a failure to list them ends the teardown,
/// because they are not a supplement to the status mirror — they are the *only* handle on a run
/// during the window between `record_prepared` and the status write that mirrors it. A run in
/// that window already holds host Leases and node-root proxy pods, so a teardown that saw only the
/// (still empty) mirror and then dropped the finalizer would strand them where nothing can reach
/// them again. Every discovery failure that a later tick could clear is therefore kept as one, in
/// the same way [`release_run_infrastructure`]'s failures are.
async fn runs_to_release(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
) -> Result<Vec<RecordedRun>, ReconcileError> {
    let (namespace, plan_name) = namespace_and_name(object)?;
    let plays_api = Api::<Play>::namespaced(context.client.clone(), namespace);
    let plays = plays_api
        .list(&ListParams::default().labels(&format!("{}={plan_name}", labels::PLAYBOOKPLAN_NAME)))
        .await?;

    Ok(discovered_runs(object, &plays.items))
}

/// The runs a deleted plan's status mirror and records name between them, deduplicated.
///
/// The mirror leads because it is the one source that survives the plan's own cascade; the records
/// cover the run that has not reached the status yet. A handle that does not parse is dropped
/// with a warning rather than failing the teardown: there is nothing to release for a run whose
/// identity is unreadable, and no tick will ever repair it, so holding the finalizer over one would
/// only trade a leak for a plan that can never finish deleting. The manual cleanup procedure in the
/// troubleshooting guide is the answer to that case.
///
/// A statusless record supplies no identity here, for the same reason [`classify_record`] calls it
/// `Uninitialized` and recovery deletes it: nothing has crossed the operator-owned status boundary,
/// so it describes no run. It cannot describe one either — a record is written before the locks and
/// the proxy pods, and the tick that fails to initialize it stops before both — so this gives up
/// nothing that was ever releasable. What it does give up is deriving cleanup identities from an
/// object anything holding `plays: create` alone could have written: `cleanup_proxy_infra` scopes
/// its operator-namespace deletes by execution hash and run ID, which are not this plan's to prove,
/// and the status subresource is a separate RBAC grant.
fn discovered_runs(object: &PlaybookPlan, plays: &[Play]) -> Vec<RecordedRun> {
    let plan = format!(
        "{}/{}",
        object.metadata.namespace.as_deref().unwrap_or("<unknown>"),
        object.metadata.name.as_deref().unwrap_or("<unknown>")
    );
    let mut runs = Vec::new();

    if let Some(mirror) = object
        .status
        .as_ref()
        .and_then(|status| status.active_run.clone())
    {
        match RecordedRun::from_mirror(mirror) {
            Ok(run) => runs.push(run),
            Err(error) => warn!(
                "PlaybookPlan {plan} was deleted with an unusable activeRun ({error}); its run cannot be released automatically"
            ),
        }
    }

    for play in recoverable_plays_for_plan(plays, object)
        .into_iter()
        .filter(|play| classify_record(play) != RecordKind::Uninitialized)
    {
        match recorded_run_from_play(play) {
            Ok(run) => runs.push(run),
            Err(error) => warn!(
                "PlaybookPlan {plan} was deleted with an unusable record {:?} ({error}); that run cannot be released automatically",
                play.metadata.name
            ),
        }
    }

    dedupe_runs(runs)
}

/// The distinct runs among `runs`, in first-seen order. The status mirror and the record it was
/// built from describe the same run, and releasing it twice would spend a second round of deletes
/// and Lease calls on resources the first pass already removed.
fn dedupe_runs(runs: Vec<RecordedRun>) -> Vec<RecordedRun> {
    let mut seen = std::collections::HashSet::new();
    runs.into_iter()
        .filter(|run| seen.insert(run.mirror.run_id.clone()))
        .collect()
}

/// Cancels a deleted plan's Job and reports whether Ansible may still be executing on its hosts.
///
/// Deleting the plan already makes Kubernetes reap the Job, but the propagation policy that reaps it
/// is the deleting client's choice — an orphaning delete would leave the pod running with nothing
/// pointing at it — so the Job is deleted here explicitly rather than assumed gone. Only this run's
/// own Job is touched: a foreign Job at the recorded name belongs to something this plan never
/// created, and neither its existence nor its pods say anything about this run.
///
/// The deletion is **foreground**, and the Job's own disappearance is the barrier this waits on.
/// Under foreground propagation the apiserver keeps the Job until garbage collection has deleted
/// every dependent that blocks its owner — which is exactly the Job's pods — so a Job that is gone
/// is proof that no pod of it survives. Background propagation gives no such ordering: the Job is
/// removed at once, and a pod the Job controller was already creating when the delete landed can
/// appear afterwards. A single pod list would have missed it and released the hosts of a run that
/// then started talking to them. Garbage collection accounts for pods by owner reference, so this
/// also does not depend on the pods still carrying their labels.
///
/// The pods are still consulted once the Job is gone, because a pod outlives the Job object while it
/// terminates — and it is the pod, not the Job, that holds the SSH session. The run's Leases are
/// renewed for as long as either says the run is up, since the deletion path is the one place that
/// would otherwise stop renewing them while a playbook is still running.
async fn cancel_run_job(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    run: &RecordedRun,
) -> Result<bool, ReconcileError> {
    let (namespace, name) = namespace_and_name(object)?;
    let jobs_api = Api::<Job>::namespaced(context.client.clone(), namespace);
    let pods_api = Api::<Pod>::namespaced(context.client.clone(), namespace);

    let job = jobs_api.get_opt(&run.mirror.job_name).await?;
    let job = job.filter(|job| {
        validate_selected_job(
            job,
            object,
            run.execution_hash,
            run.mirror.run_number,
            &run.mirror.run_id,
            &run.mirror.play_uid,
        )
        .is_ok()
    });

    if let Some(job) = &job
        && job.metadata.deletion_timestamp.is_none()
    {
        info!(
            "PlaybookPlan {namespace}/{name} was deleted; cancelling its Job {}",
            run.mirror.job_name
        );
        // The UID carries the identity `validate_selected_job` just established into the mutation
        // itself. Without it the delete applies to whatever holds the name when it lands, so a Job
        // created at that name in the round-trip since the read — one the validation would have
        // refused — would be cancelled on this run's behalf. No `resourceVersion` alongside it: the
        // validation compares immutable identity, never status, so a Job whose counters ticked in
        // the meantime is still the Job to cancel, and requiring it unchanged would refuse exactly
        // the busy runs that most need cancelling.
        let params = DeleteParams::foreground().preconditions(Preconditions {
            uid: job.metadata.uid.clone(),
            resource_version: None,
        });
        match jobs_api.delete(&run.mirror.job_name, &params).await {
            Ok(_) => {}
            Err(error) if is_not_found(&error) => {}
            // The precondition refused the delete, so nothing was cancelled and the name is not
            // this run's any more. Nothing is decided from a stale read: the run counts as still
            // executing (its Job was there a moment ago), which keeps its host locks renewed while
            // the next tick re-reads the name and classifies whatever it finds from scratch.
            Err(error) if is_conflict(&error) => warn!(
                "PlaybookPlan {namespace}/{name}: Job {} was replaced while it was being cancelled; looking again before releasing its hosts",
                run.mirror.job_name
            ),
            Err(error) => return Err(error.into()),
        }
    }

    // The pod list is only reached once this run's Job is gone, so it answers the one question the
    // Job can no longer answer — is a pod that outlived it still up? — instead of standing in for
    // the Job's own cascade.
    let executing = match job {
        Some(_) => true,
        None => {
            let pods = pods_api
                .list(&ListParams::default().labels(&run_pod_selector(&run.mirror.run_id)))
                .await?;
            pods.items.iter().any(pod_may_be_executing)
        }
    };
    if executing {
        let leases_api =
            Api::<Lease>::namespaced(context.client.clone(), &context.operator_namespace);
        if let Err(error) = locking::renew_locks(
            &leases_api,
            &run.mirror.hosts,
            &holder_identity(namespace, name, run),
        )
        .await
        {
            warn!(
                "Could not renew the host locks of deleted plan {namespace}/{name}'s run {}: {error}",
                run.mirror.job_name
            );
        }
        debug!(
            "PlaybookPlan {namespace}/{name} is waiting for run {} to stop before releasing its hosts",
            run.mirror.job_name
        );
    }
    Ok(executing)
}

/// Selects a run's *playbook* pods — the Job's — and not the proxy pods it shares its run ID
/// with, which carry the managed-ssh component instead and are released with the rest of the
/// infrastructure.
fn run_pod_selector(run_id: &str) -> String {
    format!(
        "{}={run_id},{}={}",
        labels::RUN_ID,
        labels::COMPONENT,
        labels::PLAYBOOK_COMPONENT
    )
}

/// Whether a pod may still be running the playbook.
///
/// Only the two phases that positively say the pod has stopped release its hosts. Everything else —
/// `Unknown`, a phase that has not been reported yet, a value this operator does not know — is the
/// same fact: nobody can currently say what that pod is doing, which is not the same as it having
/// stopped. `Unknown` in particular means the *runner's* node has gone unreachable, and the Job pod
/// is scheduled away from the nodes the run targets (see `configure_job_for_node_affinity`), so the
/// usual shape of it is a partitioned runner whose container is still SSHed into perfectly healthy
/// hosts. Releasing their Leases on that evidence is what lets a second playbook onto them.
///
/// Waiting instead cannot hold a host forever: the Leases are only held while this operator keeps
/// renewing them, so they expire and become takeable within `locking::LEASE_DURATION_SECONDS` of it
/// stopping — and the plan waiting in `Terminating` is visible in the log, with a documented manual
/// release for a node that never comes back.
fn pod_may_be_executing(pod: &Pod) -> bool {
    !matches!(
        pod.status
            .as_ref()
            .and_then(|status| status.phase.as_deref()),
        Some("Succeeded" | "Failed")
    )
}

fn holds_run_cleanup_finalizer(object: &PlaybookPlan) -> bool {
    object
        .metadata
        .finalizers
        .iter()
        .flatten()
        .any(|finalizer| finalizer == RUN_CLEANUP_FINALIZER)
}

/// The two edits to a plan's finalizer list, kept pure and total so neither can drop an entry this
/// operator does not own — `foregroundDeletion` and anything a user or another controller added sit
/// in the same list, and the patch that writes it replaces the whole array.
fn with_run_cleanup_finalizer(current: &Option<Vec<String>>) -> Vec<String> {
    let mut finalizers: Vec<String> = current.clone().unwrap_or_default();
    if !finalizers.iter().any(|f| f == RUN_CLEANUP_FINALIZER) {
        finalizers.push(RUN_CLEANUP_FINALIZER.to_string());
    }
    finalizers
}

fn without_run_cleanup_finalizer(current: &Option<Vec<String>>) -> Vec<String> {
    current
        .iter()
        .flatten()
        .filter(|finalizer| *finalizer != RUN_CLEANUP_FINALIZER)
        .cloned()
        .collect()
}

/// Claims the cleanup finalizer before a run creates anything outside the plan's namespace.
///
/// Kubernetes refuses to add a finalizer to an object whose deletion has already started, so a plan
/// deleted in the same instant fails *here* — before the proxy pods and Leases exist — rather than
/// after, with nothing left to release them. That is why every path that creates run infrastructure
/// goes through this first, and why the error is not swallowed.
async fn ensure_run_cleanup_finalizer(
    api: &Api<PlaybookPlan>,
    object: &PlaybookPlan,
) -> Result<(), ReconcileError> {
    if holds_run_cleanup_finalizer(object) {
        return Ok(());
    }
    patch_finalizers(
        api,
        object,
        with_run_cleanup_finalizer(&object.metadata.finalizers),
    )
    .await
}

/// Gives the finalizer back once the plan holds no run, so an idle plan deletes immediately.
async fn drop_run_cleanup_finalizer(
    api: &Api<PlaybookPlan>,
    object: &PlaybookPlan,
) -> Result<(), ReconcileError> {
    if !holds_run_cleanup_finalizer(object) {
        return Ok(());
    }
    patch_finalizers(
        api,
        object,
        without_run_cleanup_finalizer(&object.metadata.finalizers),
    )
    .await
}

/// Writes a finalizer list, version-checked — unlike [`patch_status`], which deliberately is not.
///
/// A merge patch replaces the whole array, so a blind write would drop an entry added since this
/// object was read. Carrying the `resourceVersion` turns that race into a 409 the tick retries,
/// which is safe here because the list is only touched on the two transitions rather than every
/// tick.
async fn patch_finalizers(
    api: &Api<PlaybookPlan>,
    object: &PlaybookPlan,
    finalizers: Vec<String>,
) -> Result<(), ReconcileError> {
    let (_, name) = namespace_and_name(object)?;
    api.patch(
        name,
        &PatchParams::default(),
        &Patch::Merge(serde_json::json!({
            "metadata": {
                "resourceVersion": object.metadata.resource_version,
                "finalizers": finalizers,
            }
        })),
    )
    .await?;
    Ok(())
}

/// The Lease holder identity for a run. Derived from the run ID rather than the execution hash, so
/// two retries of an unchanged spec never claim each other's locks.
fn holder_identity(namespace: &str, name: &str, run: &RecordedRun) -> String {
    format!("{namespace}/{name}/{}", run.mirror.run_id)
}

/// Renews the host Leases of every record in `plays` whose run may still be executing, for the one
/// case where a tick gives up without advancing any of them (`sole_active_record`'s refusal).
///
/// The set is exactly the phases that can have something running on a host. `Prepared` is excluded
/// because it has not taken its locks yet, and `renew_locks` re-asserts a *missing* Lease, so
/// renewing for it would acquire locks on a tick that is about to bail. `Aborted` is excluded for
/// the same reason from the other end: it has no Job, so nothing is executing behind it, and an
/// run aborted straight out of `Prepared` never held a lock to renew — while the refusal that
/// brought us here can persist for a long time, pinning hosts against every other plan. Best effort
/// by design: the caller is already returning an error, and a failure to renew here must not replace
/// the diagnosis that explains why.
async fn renew_contested_locks(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    plays: &[&Play],
) {
    let Ok((namespace, name)) = namespace_and_name(object) else {
        return;
    };
    let leases_api = Api::<Lease>::namespaced(context.client.clone(), &context.operator_namespace);

    for play in plays {
        let holds_locks = play.status.as_ref().is_some_and(|status| {
            matches!(
                status.phase,
                v1beta1::PlayPhase::Starting
                    | v1beta1::PlayPhase::Launching
                    | v1beta1::PlayPhase::Running
            )
        });
        if !holds_locks {
            continue;
        }
        let Ok(run) = recorded_run_from_play(play) else {
            continue;
        };
        if let Err(error) = locking::renew_locks(
            &leases_api,
            &run.mirror.hosts,
            &holder_identity(namespace, name, &run),
        )
        .await
        {
            warn!(
                "Could not renew the host locks of contested run {} on {namespace}/{name}: {error}",
                run.mirror.job_name
            );
        }
    }
}

fn update_desired_hash(status: &mut PlaybookPlanStatus, execution_hash: &ExecutionHash) {
    if status.current_hash == execution_hash.to_string() {
        return;
    }

    status.current_hash = execution_hash.to_string();
    status.last_run_number = 0;
    // Clearing the slot is what lets an edit take effect inside the very window it was made in: the
    // dedupe exists to stop one revision re-triggering itself, not to stop a different one from
    // running. Reverting to an earlier revision is a change like any other, so it runs again too.
    status.last_triggered_run = None;
    if status.active_run.is_none() {
        status.phase = Phase::Pending;
    }
}

/// Restores the terminal verdict a `OneShot` plan had before a failed input read cleared it.
///
/// The conditions under which that is the right thing to do — idle, `OneShot`, no outdated hosts,
/// per-host results still on the plan, and a phase that a read failure reset to `Pending` — are the
/// caller's `else if`, and are not restated here. They have to be the caller's: they select this
/// branch out of the chain that also decides scheduling, so a plan that fails them must fall
/// through to the next arm rather than reach a function that quietly does nothing.
fn restore_idle_oneshot_status(status: &mut PlaybookPlanStatus, total_count: usize) {
    status.phase = Phase::Succeeded;
    status.next_run = None;
    status.summary = Some(format!("{total_count}/{total_count} up-to-date"));
}

/// Puts a recovered run back onto the plan's status: the run itself, the `Applying` phase it
/// implies, and — only while the run applies the currently desired revision — the run number
/// it reached, which is what stops a later run from reusing its name.
fn adopt_recovered_run(status: &mut PlaybookPlanStatus, active_run: &ActiveRun) {
    if status.current_hash == active_run.execution_hash {
        status.last_run_number = status.last_run_number.max(active_run.run_number);
    }
    status.phase = Phase::Applying;
    status.summary = Some(applying_summary(active_run));
    status.active_run = Some(active_run.clone());
}

/// The plan's summary while a run is in progress.
///
/// Written wherever a run is adopted or advanced, and deliberately said in one line rather than
/// narrating the step the run has reached: waiting on host locks and waiting on proxy pods are
/// reported by the `Blocked`/`WaitingForNodes` conditions, and duplicating them here would only give
/// them a second chance to disagree.
///
/// What matters is that *something* claims the summary on the way in. Every error path this tick
/// might take overwrites it with its own message, and merge patches never drop the key, so without
/// this a message explaining why an earlier run was given up would stay on the plan for the
/// whole of the run that replaced it.
fn applying_summary(active_run: &ActiveRun) -> String {
    format!("applying run {}", active_run.job_name)
}

/// Whether the summary is still the one [`adopt_recovered_run`] claimed for this run on the
/// way into the tick — i.e. no step has since replaced it with an account of its own failure.
///
/// This is what lets a fallback message defer to a specific one without the two having to be
/// sequenced through a shared return value: every recovered run passes through
/// `adopt_recovered_run`, so anything else standing here was written by the step that just
/// failed, and that step knew more about the failure than the fallback does.
fn summary_unclaimed_since_adoption(status: &PlaybookPlanStatus, active_run: &ActiveRun) -> bool {
    status.summary.as_deref() == Some(applying_summary(active_run).as_str())
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

/// A run whose terminal result this tick applied, and the verdict its record carried.
///
/// The two travel together because both halves are needed to classify the plan afterwards: the run
/// says which revision and which schedule window the result belongs to, while the verdict says what
/// the result *was*. Recovering the verdict later from the plan's own state is not possible — a
/// failed `Recurring` run leaves no drift behind to read it back out of.
struct FinishedRun {
    run: RecordedRun,
    outcome: v1beta1::PlayPhase,
}

/// Persists a run's terminal result and hands its record back to history. Returns whether the
/// closing retention pass failed and should be retried with a shortened requeue — see
/// [`prune_history`] for why that is a return value rather than an error.
///
/// The plan is written **first** and the record acknowledged **second**, so a crash in between
/// replays the (idempotent) result rather than losing it. History pruning follows acknowledgement and
/// is also retried independently on ordinary reconciles once nothing is in flight, so a deletion
/// failure cannot block the run's result from being durable or leave old records behind forever. Persisting before the caller goes on
/// to resolve the replacement revision also means a broken new inventory cannot make the completed run
/// look active again on the next tick. Both the tick that finishes a run and the tick that recovers an
/// already-finished one come through here, so that ordering cannot drift between them.
///
/// The mirror is only given up when it is *this* run's. A terminal result is drained ahead of
/// anything live (`recover_active_run`), so the plan may well still be mirroring a different run
/// that is genuinely in flight — and that mirror is what lets the operator release a run whose `Play`
/// is deleted out from under it (`finalize_lost_run`). Clearing it for a run it does not describe
/// would leave that run's host Leases and node-root proxy pods with nothing pointing at them.
/// The drain path adopts the surviving run before calling this, so an absent mirror there means
/// there is genuinely nothing left in flight rather than a plan that has not caught up.
async fn finalize_finished_run(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    api: &Api<PlaybookPlan>,
    finished: &RecordedRun,
    record: TerminalRecord,
    resource_status: &mut PlaybookPlanStatus,
) -> Result<bool, ReconcileError> {
    let (namespace, _) = namespace_and_name(object)?;

    if mirrors_run(resource_status, finished) {
        resource_status.active_run = None;
        resource_status.phase = Phase::Pending;
        resource_status.next_run = None;
    }
    patch_status(api, object, resource_status.clone()).await?;

    // A run finalized without its record has nothing to acknowledge, and must not try: the name may
    // now hold a *replacement* run's `Play`, and a version-checked write aimed at that would fail
    // as "Play UID changed" — reporting a teardown problem for a run that is complete, and delaying
    // the replacement's own recovery by a tick. Retention still runs: the plan gained a result.
    if record == TerminalRecord::Present {
        play_history::acknowledge_finished(
            &context.client,
            namespace,
            &finished.mirror.job_name,
            &finished.mirror.play_uid,
        )
        .await?;
    }
    Ok(prune_history(context, object).await)
}

/// Folds a finished run's revision bookkeeping into the plan.
///
/// `surviving` is the *different* run the plan still holds behind this result, if any — a
/// terminal record is drained ahead of anything live, so a tick can apply one run's outcome while
/// another is genuinely running. `lastTriggeredRun` is the sole dedupe key for "one run per schedule
/// window", so it has to describe the newest run of the desired revision the plan is holding:
/// stamping the finished run's window over a live run's would describe a run that is already
/// over. That is taken from the surviving run's own record rather than from whatever the last
/// status write left behind, because a tick that failed between marking the run `Running` and
/// patching the plan leaves the *previous* run's slot standing. A surviving run with no slot of
/// its own consumed none, so the finished run's remains the newest window there was.
///
/// The run number is claimed either way, because it answers a different question: it reserves a
/// name against every later run, and a finished run holds its number whatever else is in flight.
fn sync_desired_hash_after_finished_run(
    status: &mut PlaybookPlanStatus,
    desired_hash: &ExecutionHash,
    finished: &RecordedRun,
    surviving: Option<&SurvivingRun>,
) {
    // Clears the slot when the desired revision has moved on, so the replacement can start inside
    // the window the finished run used. When it hasn't, the slot is re-recorded below instead, which
    // is what stops a run that completes inside its own grace window from re-triggering itself.
    update_desired_hash(status, desired_hash);
    let surviving_slot = surviving
        .filter(|surviving| {
            consumed_its_slot(
                &surviving.phase,
                &surviving.run.execution_hash,
                desired_hash,
            )
        })
        .and_then(|surviving| surviving.run.mirror.triggered_slot);
    if finished.execution_hash == *desired_hash {
        record_triggered_slot(status, surviving_slot.or(finished.mirror.triggered_slot));
        status.last_run_number = status.last_run_number.max(finished.mirror.run_number);
    } else {
        record_triggered_slot(status, surviving_slot);
    }
}

fn record_triggered_slot(status: &mut PlaybookPlanStatus, slot: Option<DateTime<FixedOffset>>) {
    if let Some(slot) = slot {
        status.last_triggered_run = Some(slot);
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
/// invariant and is drained ahead of anything live: it owns no cluster resources any more, and
/// handing its recap over is what allows the plan to move on at all. The invariant is still settled
/// first, because the drain describes the run that outlives the result and so must not be taken
/// from a live set that was never proved to hold one.
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

    let selected = match select_recoverable_record(&live, &unacknowledged) {
        Ok(selected) => selected,
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

    let play = match selected {
        None => return Ok(None),
        Some(RecoverableRecord::Finished { play, surviving }) => {
            let play_status = play
                .status
                .as_ref()
                .expect("a record needing recovery has a status");
            return Ok(Some(RecoveredRun::Finished {
                finished: recorded_run_from_play(play)?,
                status: play_status.clone(),
                surviving: surviving.map(surviving_run_from_play).transpose()?,
            }));
        }
        Some(RecoverableRecord::Live(play)) => play,
    };

    let play_status = play
        .status
        .as_ref()
        .expect("statusless records were filtered out above");
    let run = recorded_run_from_play(play)?;

    match play_status.phase.clone() {
        // Deferred rather than decided here: whether an absent-Job run may still be resumed
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

async fn managed_hosts_still_allowed(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
    managed_hosts: &[String],
) -> Result<bool, ReconcileError> {
    if managed_hosts.is_empty() {
        return Ok(true);
    }
    let (namespace, _) = namespace_and_name(object)?;
    let mut groups = vec![ResolvedInventoryGroup::ManagedSsh {
        hosts: ResolvedHosts {
            name: "recovery-authorization".into(),
            hosts: managed_hosts.to_vec(),
        },
        tolerations: None,
        variables: None,
    }];
    node_access::enforce(
        &context.client,
        &context.node_access_policies,
        namespace,
        &mut groups,
    )
    .await?;
    let allowed: std::collections::HashSet<&str> = groups
        .iter()
        .flat_map(|group| group.hosts().hosts.iter().map(String::as_str))
        .collect();
    Ok(managed_hosts
        .iter()
        .all(|host| allowed.contains(host.as_str())))
}

/// What one reconcile found for a plan's run.
enum RecoveredRun {
    Active(RecordedRun),
    Unlaunched(UnlaunchedRun),
    Aborted(RecordedRun),
    Finished {
        finished: RecordedRun,
        status: v1beta1::PlayStatus,
        /// The run still in flight behind the drained result, if any. A terminal result is
        /// handed over ahead of anything live, so the plan is *not* finished when this is set, and
        /// the tick must not classify it as such — nor let the finished run's schedule window
        /// overwrite the one this run holds.
        ///
        /// Carried whole, and rebuilt from the run's own immutable record rather than read off
        /// a plan status that may not have caught up with it: the tick adopts it as the plan's
        /// mirror, which is both the handle every later tick recovers it by and the only way its
        /// Leases and proxy pods can still be released if its record is deleted while it runs.
        /// Boxed to keep this variant from dominating the size of every recovery result.
        surviving: Option<Box<SurvivingRun>>,
    },
}

/// The run that outlives a drained terminal result: its run, and the phase its record was found
/// in. The phase travels with it because the two things the tick does with the run need
/// different evidence — adopting its mirror is right in every phase, while crediting it with the
/// schedule window its record names is only right once its Job exists.
struct SurvivingRun {
    run: RecordedRun,
    phase: v1beta1::PlayPhase,
}

/// Whether a run has actually consumed the schedule window its record names — the one rule
/// `lastTriggeredRun` is written by, wherever the write happens.
///
/// Both halves have to hold.
///
///   - **Its Job must exist**, and `Running` is the only phase that says so — it is also the only
///     one no later tick re-records a slot for. Every earlier phase is credited by the tick that
///     gives it a Job instead ([`resume_launching_run`]'s adoption and the `ResumePreparing` path),
///     and `Aborted` never had one: `play_history::abort_unlaunched` only accepts an unlaunched
///     record, and from `Launching` only once its Job is known to be absent. Crediting those would
///     let a run that is then abandoned — suspended, or left with no hosts to trigger — burn a
///     window nothing ever ran in, since no abandon path clears the marker.
///   - **It must apply the revision the plan currently wants.** A superseded run whose Job
///     already exists is adopted and allowed to finish, but the window belongs to the revision that
///     replaced it: `update_desired_hash` cleared the marker precisely so the edit can run inside
///     the window it was made in, and the replacement is what will claim it. Nothing takes a
///     wrongly-claimed window back — the finished superseded run does not clear it either, because
///     its own hash no longer matches the desired one.
///
/// Pure so the rule stays pinned in one place: a new phase landing on the wrong side of it, or a
/// caller forgetting the revision, breaks a test rather than silently suppressing a scheduled run.
fn consumed_its_slot(
    phase: &v1beta1::PlayPhase,
    run_hash: &ExecutionHash,
    desired_hash: &ExecutionHash,
) -> bool {
    let job_exists = match phase {
        v1beta1::PlayPhase::Running => true,
        v1beta1::PlayPhase::Prepared
        | v1beta1::PlayPhase::Starting
        | v1beta1::PlayPhase::Launching
        | v1beta1::PlayPhase::Aborted
        | v1beta1::PlayPhase::Succeeded
        | v1beta1::PlayPhase::Failed
        | v1beta1::PlayPhase::Unknown => false,
    };
    job_exists && run_hash == desired_hash
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

/// What a tick has to recover, chosen from the records a plan holds.
enum RecoverableRecord<'a> {
    /// A terminal result to hand over, together with the run that outlives it, if any.
    Finished {
        play: &'a Play,
        surviving: Option<&'a Play>,
    },
    /// A run that is genuinely in flight.
    Live(&'a Play),
}

/// Picks that record. Pure so the order the two kinds are considered in is testable.
///
/// A queued terminal result wins, because it is the only copy of its run's recap and the plan cannot
/// start anything until it has been applied — but only once the live set has been proved to hold at
/// most one run. Draining names the surviving run off that set and ends the tick there, so
/// taking it unproved would let a second live record pass a whole tick without being advanced or
/// having its host Leases renewed, which is precisely what the refusal exists to prevent.
fn select_recoverable_record<'a>(
    live: &[&'a Play],
    unacknowledged: &[&'a Play],
) -> Result<Option<RecoverableRecord<'a>>, ReconcileError> {
    let live_run = sole_active_record(live)?;
    Ok(match unacknowledged.first() {
        Some(play) => Some(RecoverableRecord::Finished {
            play,
            surviving: live_run,
        }),
        None => live_run.map(RecoverableRecord::Live),
    })
}

/// The one in-flight record that may describe this plan's run, or `None` when it has none.
///
/// Pure so the invariant is testable: a plan has at most one run in flight at a time, and every path
/// that creates a record does so only when no other is in flight. Two therefore means something
/// outside this protocol wrote one, and picking either would leave the other's node-root proxy pods
/// unswept with nothing left pointing at them. Refusing is recoverable by an operator (delete the
/// stray record); silently choosing is not. The caller renews *every* candidate's host Leases before
/// it acts on the refusal, so failing this way never also unprotects the hosts those runs hold.
///
/// Terminal records awaiting acknowledgement are *not* in flight and are kept out of `live` — they
/// can legitimately queue up behind a live run after an outage, and are drained once this has
/// established that the run they queued behind is a single one.
fn sole_active_record<'a>(live: &[&'a Play]) -> Result<Option<&'a Play>, ReconcileError> {
    match live {
        [] => Ok(None),
        [play] => Ok(Some(play)),
        _ => Err(ReconcileError::PreconditionFailed(
            "more than one Play claims to be this plan's active run",
        )),
    }
}

/// A run recovered before its Job exists, reduced to what deciding its fate needs: its
/// identity, the phase it was found in, and the fingerprint of the inputs it was prepared against.
///
/// The `Play` itself is deliberately not carried further: the fingerprint is the only thing about
/// the record that the resume decision consults, and everything else the run needs is re-derived
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
            run_number: play.spec.run_number,
            triggered_slot: play.spec.triggered_slot,
        },
        execution_hash,
    })
}

fn surviving_run_from_play(play: &Play) -> Result<Box<SurvivingRun>, ReconcileError> {
    let phase = play
        .status
        .as_ref()
        .map(|status| status.phase.clone())
        .ok_or(ReconcileError::PreconditionFailed(
            "an in-flight Play has no status",
        ))?;
    Ok(Box::new(SurvivingRun {
        run: recorded_run_from_play(play)?,
        phase,
    }))
}

fn preparation_fingerprint(
    plan: &PlaybookPlan,
    run_groups: &[ResolvedInventoryGroup],
) -> Result<String, ReconcileError> {
    let mut hasher = twox_hash::XxHash3_64::new();
    use std::hash::{Hash as _, Hasher as _};
    serde_json::to_string(&plan.spec)?.hash(&mut hasher);
    serde_json::to_string(run_groups)?.hash(&mut hasher);
    Ok(format!("{:x}", hasher.finish()))
}

/// How many characters [`run_id`] mints.
///
/// Long enough that concurrent runs cannot collide on it, short enough to leave room for a node
/// name inside the object names it feeds. Every name budget that depends on it — the proxy pods and
/// Secrets in `managed_ssh::resource_name`, the egress policy in
/// `job_builder::job_network_policy_name` — is pinned by a test that mints an ID of exactly this
/// length, so raising it fails in all of them at once rather than at the apiserver.
pub(super) const RUN_ID_LENGTH: usize = 10;

/// Mints this run's run ID — the identity that scopes its Leases, proxy resources, client
/// certificate principal and cleanup.
///
/// Deliberately *not* a function of (plan, hash, runNumber): an aborted run frees its number
/// again, so a derived ID would be reused by the retry while the aborted run's proxy pods are
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

/// Creates a recorded run's backing Job from inputs already checked against its fingerprint.
async fn launch_recorded_job(
    jobs_api: &Api<Job>,
    object: &PlaybookPlan,
    run: &RecordedRun,
    run_groups: &[ResolvedInventoryGroup],
) -> Result<(), ReconcileError> {
    let mut job = job_builder::create_job_blueprint(
        &run.execution_hash,
        run.mirror.run_number,
        &run.mirror.run_id,
        run_groups,
        object,
    )?;
    job_builder::correlate_job_to_play(&mut job, &run.mirror.play_uid);
    let selected = SelectedJob {
        job_name: run.mirror.job_name.clone(),
        run_number: run.mirror.run_number,
    };
    spawn_ansible_job(jobs_api, object, &selected, &run.mirror.play_uid, job).await
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

fn run_number_from_job_name(job_name: &str) -> Option<u32> {
    job_name.rsplit('-').next()?.parse().ok()
}

/// The terminal-state decision for a finished run: what the plan's `phase`, `next_run`, `summary`,
/// and the caller's requeue duration become once this run's Job has reached a terminal state. Pure
/// (every wall-clock/inventory input is passed in) so the per-mode matrix is unit-testable without a
/// kube client:
///   - Every finished run resolves to `Succeeded`/`Failed`, in either mode, from *that run's* own
///     verdict — see [`phase_for_finished_run`].
///   - OneShot never reschedules.
///   - Recurring with a schedule keeps the verdict and advertises the next slot through `next_run`,
///     requeueing until then.
///   - Recurring *without* a schedule is the dead-end the start gate normally prevents (the caller
///     logs it): the verdict still stands, there is simply no next slot to name.
struct TerminalOutcome {
    phase: Phase,
    next_run: Option<DateTime<FixedOffset>>,
    summary: String,
    requeue: Option<std::time::Duration>,
}

fn decide_terminal<Tz: TimeZone>(
    mode: &ExecutionMode,
    schedule: Option<&str>,
    outcome: &v1beta1::PlayPhase,
    outdated_count: usize,
    total_count: usize,
    now: DateTime<Tz>,
) -> TerminalOutcome {
    let summary = match outdated_count {
        0 => format!("{total_count}/{total_count} up-to-date"),
        n => format!("{n}/{total_count} outdated"),
    };
    let phase = phase_for_finished_run(outcome);

    match mode {
        ExecutionMode::OneShot => TerminalOutcome {
            phase,
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
                    phase,
                    next_run: Some(next.fixed_offset()),
                    summary,
                    requeue,
                }
            }
            // Any prior forecast is now unreachable, so clear `next_run`. The verdict is kept: it
            // describes a run that did happen, and removing the schedule does not undo it.
            None => TerminalOutcome {
                phase,
                next_run: None,
                summary,
                requeue: None,
            },
        },
    }
}

/// The plan phase a finished run resolves to, in either mode.
///
/// Read from the run's own record rather than from the plan's drift state, because the two can
/// legitimately disagree: a `Recurring` run that fails leaves every host still carrying the
/// `lastAppliedHash` an earlier run gave it, so nothing is outdated and a drift-based verdict would
/// report the failed run as a success. Anything short of `Succeeded` is a failure, `Unknown`
/// included — a recap that could not be read is not evidence that the hosts were reached.
///
/// The non-terminal phases cannot arrive here: `apply_terminal_play_status` refuses them, and both
/// paths that produce an outcome have already been through it.
fn phase_for_finished_run(outcome: &v1beta1::PlayPhase) -> Phase {
    match outcome {
        v1beta1::PlayPhase::Succeeded => Phase::Succeeded,
        _ => Phase::Failed,
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
/// break naming consistency for proxy infra/Job labels/lock identity mid-run. The workspace is
/// rendered unconditionally in `ensure_infra_and_launch` after current proxy endpoints are known.
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
///
/// Every write goes through [`suspended_advertises_no_next_run`] on the way out — see there for why
/// the suspension contract is held at this boundary rather than at the end of the pipeline.
async fn patch_status(
    api: &Api<PlaybookPlan>,
    target: &PlaybookPlan,
    mut status: PlaybookPlanStatus,
) -> Result<(), ReconcileError> {
    use kube::runtime::reflector::Lookup as _;

    suspended_advertises_no_next_run(target.spec.suspend, &mut status);

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
) -> Result<ExecutionHash, ReconcileError> {
    let secret_reads = futures::future::join_all(
        secret_names
            .iter()
            .map(|name| async { ((*name).clone(), secrets_api.get(name).await) }),
    )
    .await;
    let variables_secrets = collect_secret_data(secret_reads)?;

    Ok(
        execution_evaluator::calculate_execution_hash(playbook, variables_secrets.iter())
            .fold_inventory_variables(inventory_variables.iter().copied()),
    )
}

/// Collects the data of every referenced Secret, refusing the whole read if any of them failed —
/// hashing a partial set would silently produce a revision nobody asked for.
///
/// A 404 is separated out as [`ReconcileError::SecretNotFound`] rather than left as a generic
/// `KubeError`, so [`input_error_supersedes_unlaunched`] can tell "this Secret is gone" from "the
/// apiserver is having a moment". The name has to be carried in alongside each result to say *which*
/// Secret, which is why the caller pairs them.
fn collect_secret_data(
    reads: Vec<(String, Result<Secret, kube::Error>)>,
) -> Result<Vec<BTreeMap<String, k8s_openapi::ByteString>>, ReconcileError> {
    let mut data = Vec::new();
    let mut missing = None;
    let mut transient_error = None;
    for (name, read) in reads {
        match read {
            Ok(secret) => data.extend(secret.data),
            Err(error) if is_not_found(&error) => {
                missing.get_or_insert(name);
            }
            Err(error) => {
                transient_error.get_or_insert(error);
            }
        }
    }

    if let Some(name) = missing {
        return Err(ReconcileError::SecretNotFound { name });
    }
    if let Some(error) = transient_error {
        return Err(error.into());
    }

    Ok(data)
}

/// Steps 0 and 0b — the plan's desired host set, as the rest of the tick is allowed to see it:
/// every referenced inventory resolved, then clamped by `NodeAccessPolicy` to the managed-ssh nodes
/// this namespace may target (INV-2/3/5). Returns the groups plus the nodes enforcement removed.
///
/// The two are one step because nothing may ever observe the unclamped result: `eligible_hosts`, the
/// execution hash, the run's groups and every proxy pod derive from what this returns. Fail-closed —
/// an ungoverned namespace resolves to zero managed-ssh nodes.
async fn resolve_authorized_inventory(
    context: &ReconciliationContext,
    object: &PlaybookPlan,
) -> Result<(Vec<ResolvedInventoryGroup>, Vec<String>), ReconcileError> {
    let namespace = object
        .metadata
        .namespace
        .as_deref()
        .ok_or(ReconcileError::PreconditionFailed("namespace not set"))?;

    let mut groups = resolve_inventory(context, object).await?;
    let excluded_nodes = node_access::enforce(
        &context.client,
        &context.node_access_policies,
        namespace,
        &mut groups,
    )
    .await?;

    Ok((groups, excluded_nodes))
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

    let cluster_inventory_names: Vec<&String> = inventory_refs
        .iter()
        .filter_map(|inventory_ref| inventory_ref.cluster_inventory.as_ref())
        .collect();
    let cluster_inventory_results = futures::future::join_all(
        cluster_inventory_names
            .iter()
            .map(|name| async { ((*name).clone(), cluster_inventory_api.get(name).await) }),
    )
    .await;
    let mut cluster_inventories = Vec::new();
    for (name, result) in cluster_inventory_results {
        match result {
            Ok(inventory) => cluster_inventories.push(inventory),
            Err(error) => {
                return Err(if is_not_found(&error) {
                    ReconcileError::InventoryNotFound {
                        kind: "ClusterInventory",
                        name,
                    }
                } else {
                    ReconcileError::KubeError(error)
                });
            }
        }
    }

    let static_inventory_names: Vec<&String> = inventory_refs
        .iter()
        .filter_map(|inventory_ref| inventory_ref.static_inventory.as_ref())
        .collect();
    let static_inventory_results = futures::future::join_all(
        static_inventory_names
            .iter()
            .map(|name| async { ((*name).clone(), static_inventory_api.get(name).await) }),
    )
    .await;
    let mut static_inventories = Vec::new();
    for (name, result) in static_inventory_results {
        match result {
            Ok(inventory) => static_inventories.push(inventory),
            Err(error) => {
                return Err(if is_not_found(&error) {
                    ReconcileError::InventoryNotFound {
                        kind: "StaticInventory",
                        name,
                    }
                } else {
                    ReconcileError::KubeError(error)
                });
            }
        }
    }

    let mut groups = Vec::new();

    for ci in cluster_inventories {
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

    for si in static_inventories {
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

struct SelectedJob {
    job_name: String,
    run_number: u32,
}

/// One past the highest run number any of `claimed` occupies. Pure so the "never reuse a name
/// something still on the cluster claims" rule is unit-testable without a kube client.
fn next_run_number(claimed: &[u32]) -> Result<u32, ReconcileError> {
    claimed
        .iter()
        .copied()
        .max()
        .unwrap_or_default()
        .checked_add(1)
        .ok_or(ReconcileError::PreconditionFailed("run number overflowed"))
}

/// Names the next run of `hash`, one past every run number anything still on the cluster
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
/// wedging the run on an unrepairable `PreconditionFailed`. Resuming a genuinely in-flight run
/// is `recover_active_run`'s job; same-run idempotency within a tick is `spawn_ansible_job`'s.
async fn select_job(
    client: &kube::Client,
    api: &Api<Job>,
    hash: ExecutionHash,
    playbookplan: &PlaybookPlan,
    last_run_number: u32,
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
    let max_job_run_number = jobs
        .items
        .iter()
        .filter(|job| job_belongs_to_plan(job, plan_name.as_ref(), plan_uid.as_ref()))
        .filter_map(|job| job.metadata.name.as_deref())
        .filter_map(run_number_from_job_name)
        .max()
        .unwrap_or_default();

    let plays = Api::<Play>::namespaced(client.clone(), namespace.as_ref())
        .list(&ListParams::default().labels(&format!("{}={plan_name}", labels::PLAYBOOKPLAN_NAME)))
        .await?;
    let max_recorded_run_number = plays
        .items
        .iter()
        .filter(|play| play_belongs_to_plan(play, plan_name.as_ref(), plan_uid.as_ref()))
        .map(|play| play.spec.run_number)
        .max()
        .unwrap_or_default();

    let run_number =
        next_run_number(&[last_run_number, max_job_run_number, max_recorded_run_number])?;

    Ok(SelectedJob {
        job_name: job_builder::job_name(plan_name.as_ref(), plan_uid.as_ref(), &hash, run_number),
        run_number,
    })
}

/// Creates this run's Job, tolerating the fact that it may already exist.
///
/// Same-run idempotency, and nothing wider: which run gets to run is decided long before this by
/// `select_job` (which never adopts a Job it has no record for) and `recover_active_run`. What is
/// left here is that the *same* run can reach this point more than once — several reconciles
/// fired in quick succession all read `phase` from the reflector cache, which lags this controller's
/// own `patch_status` writes, and a `create` whose response was lost still left a real Job behind.
/// So the Job is looked up by its exact name and, either way, `validate_selected_job` has to confirm
/// it carries this run's identity before it is adopted.
async fn spawn_ansible_job(
    api: &Api<Job>,
    playbookplan: &PlaybookPlan,
    selected: &SelectedJob,
    play_uid: &str,
    expected_job: Job,
) -> Result<(), ReconcileError> {
    let job_name = &selected.job_name;
    let run_number = selected.run_number;
    let hash = job_execution_hash(&expected_job)?;
    let run_id = job_run_id(&expected_job)?.to_string();
    if let Some(existing) = api.get_opt(job_name).await? {
        validate_selected_job(&existing, playbookplan, hash, run_number, &run_id, play_uid)?;
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
            validate_selected_job(&existing, playbookplan, hash, run_number, &run_id, play_uid)?;
            debug!("Adopting already-active job {job_name} for this run");
        }
        Err(err) => return Err(err.into()),
    }

    Ok(())
}

/// Whether `job` is the exact Job this run committed to. Identity, not content: the run's `Play` UID
/// (unique per run) has to be on both the Job and its pod template, alongside the plan's owner
/// reference, the execution hash, the run ID and the run number in the name.
///
/// Deliberately *not* a comparison against the stored blueprint. A Job's pod template is immutable
/// once created, so a Job carrying this run's `Play` UID can only have been created from that
/// blueprint — while a field-by-field comparison would have to model every server-side default and
/// mutating webhook, and each field it failed to predict would disown a healthy run: the operator
/// would sit out the whole run holding this plan's host Leases against every other plan targeting
/// those hosts, and then write the run off as `Unknown` once its Job finished.
fn validate_selected_job(
    job: &Job,
    plan: &PlaybookPlan,
    expected_hash: ExecutionHash,
    expected_run_number: u32,
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
    let actual_run_number = job
        .metadata
        .name
        .as_deref()
        .and_then(run_number_from_job_name);
    let expected_hash_string = expected_hash.to_string();
    if !job_belongs_to_plan(job, plan_name.as_ref(), plan_uid.as_ref())
        || job_label(job, labels::PLAYBOOKPLAN_NAME) != Some(plan_name.as_ref())
        || job_label(job, labels::COMPONENT) != Some(labels::PLAYBOOK_COMPONENT)
        || job_execution_hash(job)? != expected_hash
        || actual_run_number != Some(expected_run_number)
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
    /// "is this object part of *this* run?", and each is deliberately proof rather than a label
    /// match — a name or a label can be reused by a later run or a recreated plan.
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
            "a Job with no run ID cannot be matched to a run"
        );

        job.metadata.labels = Some(BTreeMap::from([(
            labels::RUN_ID.to_string(),
            "run-1".to_string(),
        )]));
        assert_eq!(job_run_id(&job).unwrap(), "run-1");
    }

    /// The run number is carried in the Job name, so recovering it has to survive plan names
    /// that themselves contain dashes and digits.
    #[test]
    fn run_number_is_read_from_the_trailing_segment_of_a_job_name() {
        assert_eq!(run_number_from_job_name("apply-web-abc-7"), Some(7));
        assert_eq!(
            run_number_from_job_name("apply-web-2-config-abc-12"),
            Some(12),
            "a plan name containing digits must not confuse the run number"
        );
        assert_eq!(run_number_from_job_name("apply-web-abc-notanumber"), None);
        assert_eq!(run_number_from_job_name(""), None);
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

    /// The fingerprint is the whole change detector: it is what lets a record be recognized without
    /// storing a copy of the inputs it was prepared from, so it has to move whenever either of them
    /// does. The execution hash is deliberately not enough on its own — it covers only the playbook
    /// text plus referenced Secret contents, so an `image`/`tolerations`/`verbosity` edit, or node
    /// churn under the plan's inventory, reaches the fingerprint and nothing else.
    #[test]
    fn preparation_fingerprint_covers_the_plan_spec_and_the_resolved_groups() {
        let mut plan = PlaybookPlan::new("web", PlaybookPlanSpec::default());
        plan.metadata.uid = Some("uid".into());
        plan.spec.image = "ansible:2.18".into();
        let groups = vec![managed_ssh_group("nodes", &["a"], None)];

        let baseline = preparation_fingerprint(&plan, &groups).unwrap();
        assert_eq!(
            baseline,
            preparation_fingerprint(&plan, &groups).unwrap(),
            "the same inputs must fingerprint identically across calls"
        );

        // An edit that never touches the playbook, so the execution hash cannot see it.
        let mut retagged = plan.clone();
        retagged.spec.image = "ansible:2.19".into();
        assert_ne!(
            baseline,
            preparation_fingerprint(&retagged, &groups).unwrap(),
            "an image change must move the fingerprint"
        );

        // The resolved node set is not derivable from the plan, which is why it is fingerprinted
        // alongside it.
        let relabelled = vec![managed_ssh_group("nodes", &["a", "b"], None)];
        assert_ne!(
            baseline,
            preparation_fingerprint(&plan, &relabelled).unwrap(),
            "a change in the resolved node set must move the fingerprint"
        );
    }

    /// The load-bearing property behind dropping the Job snapshot from the `Play`: rebuilding the
    /// blueprint from the plan reproduces the prepared bytes exactly. `create_job_blueprint` must
    /// stay a pure function of the recorded identity plus the plan and groups the fingerprint
    /// covers — if anything time- or environment-dependent ever leaks into it, a resumed
    /// `Launching` run would create a Job that differs from the one it committed to.
    #[test]
    fn a_rebuilt_blueprint_reproduces_the_one_prepared_for_the_same_run() {
        let mut plan = PlaybookPlan::new("web", PlaybookPlanSpec::default());
        plan.metadata.namespace = Some("team".into());
        plan.metadata.uid = Some("plan-uid".into());
        let groups = vec![managed_ssh_group("nodes", &["a", "b"], None)];
        let hash = ExecutionHash::from_hex("1").unwrap();

        let prepared =
            job_builder::create_job_blueprint(&hash, 2, "run-1", &groups, &plan).unwrap();
        let rebuilt = job_builder::create_job_blueprint(&hash, 2, "run-1", &groups, &plan).unwrap();

        assert_eq!(
            serde_json::to_value(&prepared).unwrap(),
            serde_json::to_value(&rebuilt).unwrap(),
            "the same recorded identity and inputs must rebuild byte-identically"
        );
    }

    /// Every run number anything still on the cluster claims — this plan's Jobs for the hash
    /// and its retained `Play` records — is skipped, so a new run can never land on a name an
    /// existing object already occupies.
    #[test]
    fn next_run_number_starts_past_everything_still_claiming_a_name() {
        // First run: nothing claims a number yet.
        assert_eq!(next_run_number(&[0, 0, 0]).unwrap(), 1);

        // A retained Play reserves its number even after its Job has been reaped.
        assert_eq!(next_run_number(&[0, 0, 7]).unwrap(), 8);

        // A surviving Job past the plan's own last run number still wins.
        assert_eq!(next_run_number(&[3, 5, 0]).unwrap(), 6);

        assert!(next_run_number(&[u32::MAX]).is_err());
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
        /// Splits `apply-{plan}-{digest}-{run}` on its last two separators.
        fn parts(name: &str) -> (&str, &str, &str) {
            let (head, run_number) = name.rsplit_once('-').unwrap();
            let (plan, digest) = head.rsplit_once('-').unwrap();
            (plan, digest, run_number)
        }

        let a = ExecutionHash::from_hex("1").unwrap();
        let b = ExecutionHash::from_hex("2").unwrap();
        let name_a = job_builder::job_name("web", "plan-uid", &a, 1);
        let name_b = job_builder::job_name("web", "plan-uid", &b, 1);
        let (plan_a, digest_a, run_number_a) = parts(&name_a);
        let (plan_b, digest_b, run_number_b) = parts(&name_b);

        // Two revisions of one plan are separated by the digest and nothing else...
        assert_ne!(name_a, name_b);
        assert_eq!((plan_a, run_number_a), (plan_b, run_number_b));
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

        // The run number is the part that is guaranteed to differ, which is why it is reserved
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

        assert!(play_is_running(&play(v1beta1::PlayPhase::Running)).unwrap());
        for phase in [
            v1beta1::PlayPhase::Prepared,
            v1beta1::PlayPhase::Starting,
            v1beta1::PlayPhase::Launching,
            v1beta1::PlayPhase::Aborted,
            v1beta1::PlayPhase::Succeeded,
        ] {
            assert!(!play_is_running(&play(phase)).unwrap());
        }

        // A statusless record never crossed the operator-owned boundary, so it describes no phase to
        // act on — distinct from a record whose UID says it is not this run at all, which the caller
        // filters out before ever getting here.
        let mut statusless = play(v1beta1::PlayPhase::Running);
        statusless.status = None;
        assert!(play_is_running(&statusless).is_err());
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
    /// naming a *different* run is the one thing that must survive: it is genuinely in flight,
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
                run_number: 1,
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
            "a mirror describing another run is that run's only recovery handle"
        );

        // What the drain path relies on: adopting the run that outlives the result is what turns
        // the "give it up" answer into "keep it". Without the adoption the plan would be persisted as
        // `Applying` with no `activeRun` at all, and a run whose record is deleted in that state
        // has nothing left to release its host Leases and node-root proxy pods by.
        let mut status = mirroring(None);
        let surviving = run("other-play-uid");
        adopt_recovered_run(&mut status, &surviving.mirror);
        assert!(!mirrors_run(&status, &this_run));
        assert_eq!(status.phase, Phase::Applying);
        assert_eq!(
            status.active_run.as_ref().map(|run| run.play_uid.as_str()),
            Some("other-play-uid")
        );
    }

    /// The finalizer edits must be surgical: the list they rewrite also holds Kubernetes' own
    /// `foregroundDeletion` entry and anything another controller put there, and the merge patch
    /// that writes it replaces the array wholesale — so dropping a stranger's entry here would
    /// release an object somebody else is still holding.
    #[test]
    fn finalizer_edits_touch_only_this_operators_entry() {
        let plan = |finalizers: Option<Vec<String>>| {
            let mut plan = PlaybookPlan::new("web", Default::default());
            plan.metadata.finalizers = finalizers;
            plan
        };
        let foreign = "foregroundDeletion".to_string();
        let ours = RUN_CLEANUP_FINALIZER.to_string();

        assert!(!holds_run_cleanup_finalizer(&plan(None)));
        assert!(!holds_run_cleanup_finalizer(&plan(Some(vec![
            foreign.clone()
        ]))));
        assert!(holds_run_cleanup_finalizer(&plan(Some(vec![ours.clone()]))));

        assert_eq!(with_run_cleanup_finalizer(&None), vec![ours.clone()]);
        assert_eq!(
            with_run_cleanup_finalizer(&Some(vec![foreign.clone()])),
            vec![foreign.clone(), ours.clone()],
            "a stranger's finalizer survives the claim"
        );
        assert_eq!(
            with_run_cleanup_finalizer(&Some(vec![ours.clone()])),
            vec![ours.clone()],
            "claiming twice must not stack up entries"
        );

        assert_eq!(
            without_run_cleanup_finalizer(&Some(vec![foreign.clone(), ours.clone()])),
            vec![foreign.clone()],
            "a stranger's finalizer survives the release"
        );
        assert!(without_run_cleanup_finalizer(&Some(vec![ours])).is_empty());
        assert!(without_run_cleanup_finalizer(&None).is_empty());
    }

    /// The teardown a deleted plan performs is driven by two sources that overlap: the status mirror
    /// and the record it was built from name the same run. Releasing it twice is not harmful, but it
    /// spends a second round of deletes and Lease calls on resources the first pass already removed.
    #[test]
    fn a_deleted_plan_releases_each_run_once() {
        let run = |run_id: &str, job: &str| RecordedRun {
            execution_hash: ExecutionHash::from_hex("1").unwrap(),
            mirror: ActiveRun {
                execution_hash: "1".into(),
                run_id: run_id.into(),
                job_name: job.into(),
                play_uid: "play-uid".into(),
                hosts: vec!["worker-1".into()],
                run_number: 1,
                triggered_slot: None,
            },
        };

        let released = dedupe_runs(vec![
            run("run-a", "apply-web-abc-1"),
            run("run-a", "apply-web-abc-1"),
            run("run-b", "apply-web-abc-2"),
        ]);

        assert_eq!(
            released
                .iter()
                .map(|run| run.mirror.run_id.as_str())
                .collect::<Vec<_>>(),
            vec!["run-a", "run-b"],
            "the mirror is seen first, and every distinct run is still released"
        );
    }

    /// The two halves of the deletion path's discovery answer for different failures. A record is
    /// the only handle on a run that has taken its Leases and proxy pods but has not reached
    /// the plan's status yet, so its list failing propagates and keeps the finalizer (enforced by
    /// `runs_to_release`'s `?`). A handle that does not *parse* is a dead end no retry repairs, so
    /// it is dropped and never stops the runs next to it from being released.
    #[test]
    fn a_deleted_plans_runs_come_from_the_records_as_much_as_the_mirror() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};

        fn play(name: &str, run_id: &str, execution_hash: &str) -> Play {
            let mut play = Play::new(
                name,
                v1beta1::PlaySpec {
                    playbook_plan: "plan".into(),
                    playbook_plan_uid: "plan-uid".into(),
                    execution_hash: execution_hash.into(),
                    run_id: run_id.into(),
                    preparation_fingerprint: "fingerprint".into(),
                    run_number: 1,
                    inventory: vec![ResolvedHosts {
                        name: "workers".into(),
                        hosts: vec!["worker-1".into()],
                    }],
                    triggered_slot: None,
                },
            );
            play.metadata = ObjectMeta {
                name: Some(name.into()),
                uid: Some(format!("{name}-uid")),
                owner_references: Some(vec![OwnerReference {
                    kind: "PlaybookPlan".into(),
                    name: "plan".into(),
                    uid: "plan-uid".into(),
                    ..Default::default()
                }]),
                ..Default::default()
            };
            play.status = Some(v1beta1::PlayStatus {
                phase: v1beta1::PlayPhase::Prepared,
                ..Default::default()
            });
            play
        }

        let mut plan = PlaybookPlan::new("plan", PlaybookPlanSpec::default());
        plan.metadata.uid = Some("plan-uid".into());
        plan.metadata.namespace = Some("default".into());

        let run_ids = |plan: &PlaybookPlan, plays: &[Play]| {
            discovered_runs(plan, plays)
                .into_iter()
                .map(|run| run.mirror.run_id)
                .collect::<Vec<_>>()
        };

        // The window this exists for: the record is written before the locks and the proxy pods, the
        // mirror only at the end of the tick.
        assert_eq!(
            run_ids(&plan, &[play("apply-plan-abc-1", "run-a", "1a")]),
            vec!["run-a"],
            "a run that has not reached the status yet still has to be released"
        );

        plan.status = Some(PlaybookPlanStatus {
            active_run: Some(ActiveRun {
                execution_hash: "not-a-hash".into(),
                run_id: "run-broken".into(),
                job_name: "apply-plan-broken-1".into(),
                play_uid: "play-uid".into(),
                hosts: vec!["worker-1".into()],
                run_number: 1,
                triggered_slot: None,
            }),
            ..Default::default()
        });

        assert_eq!(
            run_ids(
                &plan,
                &[
                    play("apply-plan-broken-1", "run-broken", "also-not-a-hash"),
                    play("apply-plan-abc-1", "run-a", "1a"),
                ]
            ),
            vec!["run-a"],
            "unreadable handles are skipped without taking the releasable run down with them"
        );

        // A statusless record is `Uninitialized` to recovery, which deletes it as describing
        // nothing. It must describe nothing here too: it names an execution hash and a run ID, and
        // those are what scope the deletes `cleanup_proxy_infra` performs in the operator's
        // namespace — where the run it names need not be this plan's at all.
        let mut uninitialized = play("apply-plan-abc-1", "run-a", "1a");
        uninitialized.status = None;
        plan.status = None;
        assert!(
            run_ids(&plan, &[uninitialized]).is_empty(),
            "a record that never crossed the operator-owned status boundary supplies no identity \
             for cleanup to act on"
        );
    }

    /// What the deletion path waits on before it releases a host: the playbook pod, not the proxy
    /// pods that share its run ID, and not a pod that has already stopped talking to its hosts.
    #[test]
    fn only_a_live_playbook_pod_holds_a_deleted_plans_hosts() {
        let selector = run_pod_selector("run-a");
        assert!(selector.contains("ansible.cloudbending.dev/run-id=run-a"));
        assert!(
            selector.contains(&format!(
                "{}={}",
                labels::COMPONENT,
                labels::PLAYBOOK_COMPONENT
            )),
            "the proxy pods share the run ID and must not be waited on: {selector}"
        );

        let pod = |phase: Option<&str>| Pod {
            status: Some(k8s_openapi::api::core::v1::PodStatus {
                phase: phase.map(String::from),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(pod_may_be_executing(&pod(Some("Running"))));
        assert!(pod_may_be_executing(&pod(Some("Pending"))));
        assert!(
            pod_may_be_executing(&pod(None)),
            "a pod whose phase has not been reported yet may still start"
        );
        assert!(
            pod_may_be_executing(&pod(Some("Unknown"))),
            "`Unknown` is the node that runs the pod having gone unreachable, not the playbook \
             having stopped — and the hosts it is applying to are usually on other nodes entirely"
        );
        assert!(
            pod_may_be_executing(&pod(Some("SomePhaseFromALaterKubernetes"))),
            "a phase this operator cannot interpret says as little about the pod as `Unknown` does"
        );

        // The whole list of phases that release a run's hosts: a pod has to positively say it has
        // stopped, because everything else is only an absence of evidence.
        assert!(!pod_may_be_executing(&pod(Some("Succeeded"))));
        assert!(!pod_may_be_executing(&pod(Some("Failed"))));
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

    /// A queued terminal result must not buy a contested live set a free tick. Draining one ends the
    /// tick, so if the refusal were deferred until the result had been handed over, the live record
    /// the plan is *not* mirroring would go unadvanced and unrenewed until the drain completed —
    /// leaving its host Leases to lapse while its Job and proxy pods are still running.
    #[test]
    fn a_queued_result_does_not_defer_the_refusal_over_two_live_runs() {
        let play = |name: &str| Play::new(name, PlaySpec::default());
        let (first, second) = (play("apply-web-abc-1"), play("apply-web-abc-2"));
        let finished = play("apply-web-abc-0");

        assert!(select_recoverable_record(&[], &[]).unwrap().is_none());
        assert!(matches!(
            select_recoverable_record(&[&first], &[]).unwrap(),
            Some(RecoverableRecord::Live(play)) if play.metadata.name.as_deref() == Some("apply-web-abc-1")
        ));
        // One live run behind a result: the result is still drained first, and names that run as the
        // run outliving it.
        assert!(matches!(
            select_recoverable_record(&[&first], &[&finished]).unwrap(),
            Some(RecoverableRecord::Finished { play, surviving: Some(live) })
                if play.metadata.name.as_deref() == Some("apply-web-abc-0")
                    && live.metadata.name.as_deref() == Some("apply-web-abc-1")
        ));
        assert!(select_recoverable_record(&[&first, &second], &[&finished]).is_err());
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

    /// The half of the start gate that does not go through the plan's status: a window one of the
    /// plan's own records already took must never be handed to a second run, however far behind
    /// `lastTriggeredRun` happens to be.
    #[test]
    fn a_record_with_a_job_takes_the_window_for_its_own_revision() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

        let slot = "2025-08-12T20:00:00Z"
            .parse::<DateTime<FixedOffset>>()
            .unwrap();
        let hash = ExecutionHash::from_hex("1a").unwrap();
        let other_hash = ExecutionHash::from_hex("2b").unwrap();

        let play = |uid: &str,
                    execution_hash: &str,
                    triggered_slot: Option<DateTime<FixedOffset>>,
                    phase: Option<v1beta1::PlayPhase>| {
            let mut play = Play::new(
                "apply-plan-abc-1",
                v1beta1::PlaySpec {
                    playbook_plan: "plan".into(),
                    playbook_plan_uid: uid.into(),
                    execution_hash: execution_hash.into(),
                    run_id: "run-1".into(),
                    preparation_fingerprint: "fingerprint".into(),
                    run_number: 1,
                    inventory: Vec::new(),
                    triggered_slot,
                },
            );
            play.metadata = ObjectMeta {
                name: Some("apply-plan-abc-1".into()),
                ..Default::default()
            };
            play.status = phase.map(|phase| v1beta1::PlayStatus {
                phase,
                ..Default::default()
            });
            play
        };

        let mut plan = PlaybookPlan::new("plan", PlaybookPlanSpec::default());
        plan.metadata.uid = Some("plan-uid".into());

        let taken = |plays: &[Play]| window_taken_by_a_record(plays, &plan, slot, &hash);

        // A run that reached a Job takes the window, running or already finished — the plan's
        // marker is written from these and may be behind them, or missing entirely.
        for phase in [
            v1beta1::PlayPhase::Running,
            v1beta1::PlayPhase::Succeeded,
            v1beta1::PlayPhase::Failed,
            v1beta1::PlayPhase::Unknown,
        ] {
            assert!(
                taken(&[play("plan-uid", "1a", Some(slot), Some(phase.clone()))]),
                "{phase:?} reached a Job, so its window is spent"
            );
        }

        // Nothing ran for the window: a run given up before its Job hands it back, exactly as
        // `consumed_its_slot` decides it for a live one.
        for phase in [
            None,
            Some(v1beta1::PlayPhase::Prepared),
            Some(v1beta1::PlayPhase::Starting),
            Some(v1beta1::PlayPhase::Aborted),
        ] {
            assert!(
                !taken(&[play("plan-uid", "1a", Some(slot), phase.clone())]),
                "{phase:?} never had a Job, so the window is still free"
            );
        }

        // A record of another revision leaves the window to the revision that replaced it, and one
        // of another slot — or of a plan recreated under the same name — says nothing about it.
        assert!(!taken(&[play(
            "plan-uid",
            "2b",
            Some(slot),
            Some(v1beta1::PlayPhase::Running)
        )]));
        assert!(window_taken_by_a_record(
            &[play(
                "plan-uid",
                "2b",
                Some(slot),
                Some(v1beta1::PlayPhase::Running)
            )],
            &plan,
            slot,
            &other_hash,
        ));
        assert!(!taken(&[play(
            "plan-uid",
            "1a",
            Some("2025-08-13T20:00:00Z".parse().unwrap()),
            Some(v1beta1::PlayPhase::Running)
        )]));
        assert!(!taken(&[play(
            "plan-uid",
            "1a",
            None,
            Some(v1beta1::PlayPhase::Running)
        )]));
        assert!(!taken(&[play(
            "other-uid",
            "1a",
            Some(slot),
            Some(v1beta1::PlayPhase::Running)
        )]));
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

    #[test]
    fn failed_pruning_wins_over_a_distant_schedule() {
        assert_eq!(
            prune_retry_after(std::time::Duration::from_secs(3600)),
            std::time::Duration::from_secs(15)
        );
        assert_eq!(
            prune_retry_after(std::time::Duration::from_secs(5)),
            std::time::Duration::from_secs(5)
        );
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
    fn secret_read_errors_are_not_hashed_as_empty_data() {
        let api_error = |code| {
            kube::Error::Api(Box::new(kube::core::Status {
                code,
                ..Default::default()
            }))
        };

        // A transient failure holds an unlaunched run open, so it must stay a plain KubeError.
        assert!(matches!(
            collect_secret_data(vec![("vars".into(), Err(api_error(500)))]),
            Err(ReconcileError::KubeError(_))
        ));

        // A Secret that is gone supersedes the run, which needs the 404 named as such — and
        // named after the Secret, since the message is what tells the user which one to recreate.
        assert!(matches!(
            collect_secret_data(vec![("vars".into(), Err(api_error(404)))]),
            Err(ReconcileError::SecretNotFound { name }) if name == "vars"
        ));

        assert!(matches!(
            collect_secret_data(vec![
                ("unavailable".into(), Err(api_error(500))),
                ("deleted".into(), Err(api_error(404))),
            ]),
            Err(ReconcileError::SecretNotFound { name }) if name == "deleted"
        ));

        let secret = Secret {
            data: Some(BTreeMap::from([(
                "variables.yaml".into(),
                k8s_openapi::ByteString(b"key: value".to_vec()),
            )])),
            ..Default::default()
        };
        assert_eq!(
            collect_secret_data(vec![("vars".into(), Ok(secret))]).unwrap()[0]["variables.yaml"].0,
            b"key: value"
        );
    }

    #[test]
    fn has_work_to_start_oneshot_gates_only_on_outdated_hosts() {
        // OneShot with work to do starts whether or not a schedule is set.
        assert!(has_work_to_start(&ExecutionMode::OneShot, false, true));
        assert!(has_work_to_start(&ExecutionMode::OneShot, true, true));
        // Nothing outdated -> goes quiet.
        assert!(!has_work_to_start(&ExecutionMode::OneShot, true, false));
    }

    #[test]
    fn has_work_to_start_recurring_requires_a_schedule() {
        // The busy-loop guard: Recurring with hosts but no schedule must NOT start — there's no
        // slot to dedup against, so it would re-trigger on every tick.
        assert!(!has_work_to_start(&ExecutionMode::Recurring, false, true));
        // With a schedule it's eligible...
        assert!(has_work_to_start(&ExecutionMode::Recurring, true, true));
        // ...but still only when there are hosts to trigger.
        assert!(!has_work_to_start(&ExecutionMode::Recurring, true, false));
    }

    #[test]
    fn a_plan_waiting_for_its_first_run_is_delayed_and_then_keeps_its_verdict() {
        // Nothing has been applied under this revision yet — an untouched plan, one whose edit just
        // reset it, and one whose run was given up before it launched all read the same way.
        assert_eq!(
            phase_while_waiting_for_schedule(&Phase::Pending),
            Phase::Delayed
        );
        assert_eq!(
            phase_while_waiting_for_schedule(&Phase::Delayed),
            Phase::Delayed
        );

        // Once a run has finished, the wait is `nextRun`'s to describe and the verdict stands.
        assert_eq!(
            phase_while_waiting_for_schedule(&Phase::Succeeded),
            Phase::Succeeded
        );
        assert_eq!(
            phase_while_waiting_for_schedule(&Phase::Failed),
            Phase::Failed
        );
    }

    #[test]
    fn suspend_vetoes_starting_a_new_run_even_with_work_to_do() {
        assert!(!may_start_new_run(true, true));
        // The veto is suspend's alone: without it the work gate decides.
        assert!(may_start_new_run(false, true));
        assert!(!may_start_new_run(false, false));
    }

    /// The other half of the contract: a suspended plan never advertises a run it will not start.
    /// Asserted over a status that already carries a forecast, because that is the case the rule
    /// exists for — a plan suspended while `Delayed` has one standing on it.
    #[test]
    fn a_suspended_plan_advertises_no_next_run() {
        let forecast = || PlaybookPlanStatus {
            phase: Phase::Delayed,
            next_run: Some(
                "2025-08-12T20:00:00Z"
                    .parse::<DateTime<FixedOffset>>()
                    .unwrap(),
            ),
            ..Default::default()
        };

        let mut suspended = forecast();
        suspended_advertises_no_next_run(true, &mut suspended);
        assert_eq!(suspended.next_run, None);
        // Only the forecast: the phase keeps saying what the plan's underlying state is, and the
        // `Suspended` printer column is what says it is paused.
        assert_eq!(suspended.phase, Phase::Delayed);

        let mut running = forecast();
        suspended_advertises_no_next_run(false, &mut running);
        assert_eq!(running.next_run, forecast().next_run);
    }

    /// The suspend half of the unlaunched-run decision: a suspended plan must never keep an
    /// unlaunched run sitting on its host Leases, and a `Launching` run may only be given
    /// up through `resume_launching_run`, which adopts a Job that made it out before the suspend.
    #[test]
    fn a_suspended_plan_drops_every_unlaunched_run_through_the_right_door() {
        use v1beta1::PlayPhase;
        assert_eq!(
            decide_suspended_unlaunched(&PlayPhase::Prepared, true),
            SuspendedUnlaunched::Abandon
        );
        assert_eq!(
            decide_suspended_unlaunched(&PlayPhase::Starting, true),
            SuspendedUnlaunched::Abandon
        );
        assert_eq!(
            decide_suspended_unlaunched(&PlayPhase::Launching, true),
            SuspendedUnlaunched::GiveUpThroughResume
        );
    }

    #[test]
    fn an_unsuspended_plan_passes_the_suspend_gate_in_every_phase() {
        use v1beta1::PlayPhase;
        for phase in [
            PlayPhase::Prepared,
            PlayPhase::Starting,
            PlayPhase::Launching,
        ] {
            assert_eq!(
                decide_suspended_unlaunched(&phase, false),
                SuspendedUnlaunched::NotSuspended
            );
        }
    }

    /// The one rule shared by every "may this run still go on?" site: the run's *own* Job is
    /// always adopted, whatever the plan now says, and only a free name may be abandoned. Getting
    /// this backwards would tear a live run's node-root infrastructure down underneath it.
    ///
    /// A Job that is not this run's is neither, in either direction. Adopting it would put this
    /// run's record behind work it did not commission; abandoning would release the host Leases
    /// on the strength of an identity check, and a check that ever rejected a Job which genuinely was
    /// ours would then let a second run start on hosts the first is still applying to.
    #[test]
    fn only_the_runs_own_job_is_adopted_and_only_a_free_name_abandoned() {
        for may_proceed in [true, false] {
            assert_eq!(
                decide_job_presence(may_proceed, RecordedJob::Own),
                JobPresenceAction::Adopt
            );
            assert_eq!(
                decide_job_presence(may_proceed, RecordedJob::Foreign),
                JobPresenceAction::Contested
            );
        }
        assert_eq!(
            decide_job_presence(true, RecordedJob::Absent),
            JobPresenceAction::Proceed
        );
        assert_eq!(
            decide_job_presence(false, RecordedJob::Absent),
            JobPresenceAction::Abandon
        );
    }

    /// The identity check that classifies what holds a run's name, exercised at the boundary that
    /// used to trust the name alone. A colliding name is not evidence of ownership: the Job has to
    /// carry this run's own run ID, `Play` UID, hash, run number and owner reference — on the
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

        // Another run of this same plan, which shares the name's readable half but not the run.
        let mut other_run =
            job_builder::create_job_blueprint(&hash, 8, "run-2", &[], &plan).unwrap();
        job_builder::correlate_job_to_play(&mut other_run, "other-play-uid");
        other_run.metadata.owner_references = Some(vec![playbookplan_owner_ref(&plan).unwrap()]);
        assert!(validate(&other_run).is_err());

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

    /// Every argument here is deliberately suspend-free: `resolve_unlaunched_before_inputs` has
    /// already resolved `spec.suspend` for every phase by the time this runs, which is what lets
    /// `Starting` and `Launching` ignore the start gate entirely. Folding `spec.suspend` back into
    /// the gate — the obvious-looking "simplification" — would silently make the last two
    /// assertions here decide a suspended plan's fate a second time, after the inventory read that
    /// the first decision exists to stay in front of.
    #[test]
    fn only_a_prepared_run_is_gated_on_its_schedule_window() {
        // Still waiting for its locks: the window (and the rest of the start gate) still applies.
        assert_eq!(
            decide_unlaunched_action(&v1beta1::PlayPhase::Prepared, true, true, false),
            UnlaunchedAction::Abandon
        );
        assert_eq!(
            decide_unlaunched_action(&v1beta1::PlayPhase::Prepared, true, false, true),
            UnlaunchedAction::Abandon
        );

        // Already building node-root infrastructure: waiting on proxy pods is not a reason to drop
        // the run, so neither the window nor the start gate is consulted any more.
        assert_eq!(
            decide_unlaunched_action(&v1beta1::PlayPhase::Starting, true, false, false),
            UnlaunchedAction::ResumePreparing
        );
        assert_eq!(
            decide_unlaunched_action(&v1beta1::PlayPhase::Launching, true, false, false),
            UnlaunchedAction::ResumeLaunching { may_proceed: true }
        );
    }

    /// A superseded run is dropped from every unlaunched phase, `suspend` or not — that check is
    /// what keeps a stale revision from being launched once its locks or proxy pods come free.
    #[test]
    fn changed_inputs_stop_an_unlaunched_run_in_every_phase() {
        for phase in [v1beta1::PlayPhase::Prepared, v1beta1::PlayPhase::Starting] {
            assert_eq!(
                decide_unlaunched_action(&phase, false, true, true),
                UnlaunchedAction::Abandon
            );
        }
        assert_eq!(
            decide_unlaunched_action(&v1beta1::PlayPhase::Launching, false, true, true),
            UnlaunchedAction::ResumeLaunching { may_proceed: false }
        );
    }

    #[test]
    fn permanent_input_errors_supersede_absent_job_runs() {
        let api_error = |code| {
            ReconcileError::from(kube::Error::Api(Box::new(kube::core::Status {
                code,
                ..Default::default()
            })))
        };

        // An unclassified 404 is not enough on its own — only a read site that knows *what* was
        // missing may turn one into a supersede.
        assert!(!input_error_supersedes_unlaunched(&api_error(404)));
        assert!(!input_error_supersedes_unlaunched(&api_error(500)));
        assert!(input_error_supersedes_unlaunched(
            &ReconcileError::InventoryNotFound {
                kind: "ClusterInventory",
                name: "nodes".into(),
            }
        ));
        // The Secret read reaches the same verdict as the inventory read; a plan whose variables
        // Secret was deleted must not sit on its hosts' Leases forever waiting for it to return.
        assert!(input_error_supersedes_unlaunched(
            &ReconcileError::SecretNotFound {
                name: "db-credentials".into(),
            }
        ));
        assert!(input_error_supersedes_unlaunched(
            &ReconcileError::ReservedInventoryVariable {
                group: "workers".into(),
                key: "ansible_host".into(),
            }
        ));
    }

    #[test]
    fn desired_hash_change_resets_revision_state_without_disturbing_an_active_run() {
        let old_hash = ExecutionHash::from_hex("1").unwrap();
        let new_hash = ExecutionHash::from_hex("2").unwrap();
        let slot = "2025-08-12T20:00:00Z"
            .parse::<DateTime<FixedOffset>>()
            .unwrap();
        let mut status = PlaybookPlanStatus {
            active_run: Some(ActiveRun {
                execution_hash: old_hash.to_string(),
                run_id: "run-1".into(),
                job_name: "apply-plan-1-1".into(),
                play_uid: "play-uid".into(),
                hosts: vec!["worker-1".into()],
                run_number: 1,
                triggered_slot: Some(slot),
            }),
            current_hash: old_hash.to_string(),
            phase: Phase::Applying,
            last_run_number: 1,
            last_triggered_run: Some(slot),
            ..Default::default()
        };

        update_desired_hash(&mut status, &new_hash);

        assert_eq!(status.current_hash, new_hash.to_string());
        assert_eq!(status.phase, Phase::Applying);
        assert_eq!(status.last_run_number, 0);
        assert_eq!(status.last_triggered_run, None);
        assert_eq!(
            status.active_run.as_ref().unwrap().execution_hash,
            old_hash.to_string()
        );
        assert_eq!(
            status.active_run.as_ref().unwrap().job_name,
            "apply-plan-1-1",
            "the run in flight keeps the Job it is reconciled through"
        );
        assert_eq!(
            status.active_run.as_ref().unwrap().triggered_slot,
            Some(slot)
        );

        let mut idle = PlaybookPlanStatus {
            current_hash: old_hash.to_string(),
            phase: Phase::Succeeded,
            last_run_number: 3,
            last_triggered_run: Some(slot),
            ..Default::default()
        };
        update_desired_hash(&mut idle, &new_hash);
        assert_eq!(idle.phase, Phase::Pending);
        assert_eq!(idle.last_run_number, 0);
        assert_eq!(idle.last_triggered_run, None);
    }

    /// A plan that cannot read its own inputs must not keep advertising the last run's verdict. The
    /// summary alone is not enough — `phase` and `nextRun` are the other two printer columns, and a
    /// `Succeeded`/`Delayed` plan pointing at a slot that will never fire reads as healthy.
    ///
    /// The exception is a run still in flight: the read failure did not stop its Job, so it keeps
    /// its phase, exactly as `update_desired_hash` leaves an active run alone.
    #[test]
    fn an_unreadable_input_stops_the_plan_advertising_the_previous_verdict() {
        let slot = "2025-08-12T20:00:00Z"
            .parse::<DateTime<FixedOffset>>()
            .unwrap();

        let mut idle = PlaybookPlanStatus {
            phase: Phase::Succeeded,
            next_run: Some(slot),
            summary: Some("3/3 up-to-date".into()),
            conditions: vec![v1beta1::PlaybookPlanCondition {
                type_: "Ready".into(),
                status: "True".into(),
                reason: Some("AllHostsSucceeded".into()),
                message: Some("3/3 hosts completed successfully".into()),
                last_transition_time: None,
            }],
            hosts_status: Some(BTreeMap::from([(
                "worker-1".to_string(),
                v1beta1::HostStatus::default(),
            )])),
            ..Default::default()
        };
        record_input_failure(&mut idle, "cannot read referenced Secrets: nope".into());
        assert_eq!(idle.phase, Phase::Pending);
        assert_eq!(idle.next_run, None);
        assert_eq!(
            idle.summary.as_deref(),
            Some("cannot read referenced Secrets: nope")
        );
        let ready = idle
            .conditions
            .iter()
            .find(|condition| condition.type_ == "Ready")
            .unwrap();
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason.as_deref(), Some("InputsUnavailable"));
        assert_eq!(
            ready.message.as_deref(),
            Some("cannot read referenced Secrets: nope")
        );
        // The previous run's per-host results are still true — nothing here re-ran anything.
        assert!(idle.hosts_status.unwrap().contains_key("worker-1"));

        let mut applying = PlaybookPlanStatus {
            active_run: Some(ActiveRun {
                execution_hash: "1".into(),
                run_id: "run-1".into(),
                job_name: "apply-plan-1-1".into(),
                play_uid: "play-uid".into(),
                hosts: vec!["worker-1".into()],
                run_number: 1,
                triggered_slot: None,
            }),
            phase: Phase::Applying,
            ..Default::default()
        };
        record_input_failure(
            &mut applying,
            "cannot resolve the plan's inventories: nope".into(),
        );
        assert_eq!(applying.phase, Phase::Applying);
    }

    /// An outage reported while an unlaunched run is being decided has to survive that decision.
    /// `handle_unlaunched_input_error` sets the overlay before branching, and every branch below it
    /// ends in `clear_run_conditions` (via `abandon_run`) — which must keep clearing only the
    /// per-run conditions, never the readiness verdict that outlives the run.
    #[test]
    fn clearing_run_conditions_leaves_the_input_outage_standing() {
        let mut status = PlaybookPlanStatus::default();
        status::set_blocked_condition(
            &mut status,
            Some(&locking::BlockedBy {
                host: "worker-1".into(),
                holder: None,
            }),
        );
        status::set_inputs_unavailable_condition(
            &mut status,
            "cannot resolve the plan's inventories: nope",
        );

        status::clear_run_conditions(&mut status);

        let ready = status
            .conditions
            .iter()
            .find(|condition| condition.type_ == "Ready")
            .unwrap();
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason.as_deref(), Some("InputsUnavailable"));
        assert_eq!(
            status
                .conditions
                .iter()
                .find(|condition| condition.type_ == "Blocked")
                .unwrap()
                .status,
            "False"
        );
    }

    /// Once desired inputs are readable again, an idle OneShot plan with no outdated hosts restores
    /// the successful status it had before the read failure.
    #[test]
    fn a_recovered_idle_oneshot_restores_its_successful_verdict() {
        let hash = ExecutionHash::from_hex("1").unwrap();
        let mut status = PlaybookPlanStatus {
            current_hash: hash.to_string(),
            phase: Phase::Succeeded,
            summary: Some("1/1 up-to-date".into()),
            eligible_hosts: vec![ResolvedHosts {
                name: "workers".into(),
                hosts: vec!["worker-1".into()],
            }],
            hosts_status: Some(BTreeMap::from([(
                "worker-1".into(),
                v1beta1::HostStatus {
                    last_applied_hash: hash.to_string(),
                    ..Default::default()
                },
            )])),
            ..Default::default()
        };

        record_input_failure(
            &mut status,
            "cannot read referenced Secrets: temporary failure".into(),
        );
        assert_eq!(status.phase, Phase::Pending);
        assert_eq!(
            status.summary.as_deref(),
            Some("cannot read referenced Secrets: temporary failure")
        );

        update_desired_hash(&mut status, &hash);
        let outdated = find_outdated_hosts(&status, &hash);
        assert!(outdated.is_empty());
        status::clear_inputs_unavailable_condition(&mut status, outdated.len());
        restore_idle_oneshot_status(&mut status, 1);

        assert_eq!(status.phase, Phase::Succeeded);
        assert_eq!(status.next_run, None);
        assert_eq!(status.summary.as_deref(), Some("1/1 up-to-date"));
        let ready = status
            .conditions
            .iter()
            .find(|condition| condition.type_ == "Ready")
            .unwrap();
        assert_eq!(ready.status, "True");
        assert_eq!(ready.reason.as_deref(), Some("HostsUpToDate"));
        assert_eq!(
            ready.message.as_deref(),
            Some("1/1 hosts on the current revision")
        );
    }

    /// A recovered run is put back onto the plan whole, but its retry number only counts towards
    /// the revision it belongs to — carrying it onto a plan that has since moved on would make the
    /// replacement's first run skip numbers for no reason.
    #[test]
    fn a_recovered_run_is_readopted_and_keeps_its_number_only_for_its_own_revision() {
        let active_run = ActiveRun {
            execution_hash: "1".into(),
            run_id: "run-1".into(),
            job_name: "apply-plan-1-4".into(),
            play_uid: "play-uid".into(),
            hosts: vec!["worker-1".into()],
            run_number: 4,
            triggered_slot: None,
        };
        let mut matching = PlaybookPlanStatus {
            current_hash: "1".into(),
            last_run_number: 1,
            ..Default::default()
        };
        adopt_recovered_run(&mut matching, &active_run);
        assert_eq!(matching.last_run_number, 4);
        assert_eq!(matching.phase, Phase::Applying);
        assert_eq!(
            matching
                .active_run
                .as_ref()
                .map(|run| run.play_uid.as_str()),
            Some("play-uid")
        );

        let mut replacement = PlaybookPlanStatus {
            current_hash: "2".into(),
            last_run_number: 0,
            ..Default::default()
        };
        adopt_recovered_run(&mut replacement, &active_run);
        assert_eq!(replacement.last_run_number, 0);
        assert!(replacement.active_run.is_some());
    }

    /// A fallback summary must not bury a specific one. `preserve_unlaunched_run_after_error` runs
    /// after steps that may already have reported themselves — `report_failed_abandon` names the run
    /// whose node-root proxy pods and host Leases could not be released, and points at the manual
    /// cleanup — so it claims the summary only while nothing has replaced the one every recovered
    /// run is adopted with.
    #[test]
    fn a_step_that_reported_itself_keeps_the_summary() {
        let active_run = ActiveRun {
            execution_hash: "1".into(),
            run_id: "run-1".into(),
            job_name: "apply-plan-1-4".into(),
            play_uid: "play-uid".into(),
            hosts: vec!["worker-1".into()],
            run_number: 4,
            triggered_slot: None,
        };

        let mut status = PlaybookPlanStatus::default();
        adopt_recovered_run(&mut status, &active_run);
        assert!(summary_unclaimed_since_adoption(&status, &active_run));

        status.summary = Some("could not release the abandoned run apply-plan-1-4: boom".into());
        assert!(!summary_unclaimed_since_adoption(&status, &active_run));

        // A summary left over from a *previous* tick describes a run that is no longer current, so
        // it is not a claim on this one and must not suppress the fallback.
        let mut stale = PlaybookPlanStatus {
            summary: Some("applying run apply-plan-1-3".into()),
            ..Default::default()
        };
        assert!(!summary_unclaimed_since_adoption(&stale, &active_run));
        adopt_recovered_run(&mut stale, &active_run);
        assert!(summary_unclaimed_since_adoption(&stale, &active_run));
    }

    #[test]
    fn run_ids_are_minted_fresh_and_stay_short_enough_for_resource_names() {
        let mut plan = PlaybookPlan::new("plan", PlaybookPlanSpec::default());
        plan.metadata.uid = Some("plan-uid".into());
        let hash = ExecutionHash::from_hex("1a").unwrap();

        let first = run_id(&plan, &hash).unwrap();
        let second = run_id(&plan, &hash).unwrap();

        // Same plan, same revision, same run number: an aborted run's retry must still not
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
                    run_number: 1,
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
                run_number: 2,
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
        assert_eq!(run.mirror.run_number, 2);

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

        // A Job created for a different run of the same revision is not this run's Job, even
        // though it shares the plan, the execution hash and the run number.
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

    fn finished_run(
        hash: ExecutionHash,
        run_number: u32,
        slot: DateTime<FixedOffset>,
    ) -> RecordedRun {
        RecordedRun {
            execution_hash: hash,
            mirror: ActiveRun {
                execution_hash: hash.to_string(),
                run_id: "run-1".into(),
                job_name: "apply-plan-1-3".into(),
                play_uid: "play-uid".into(),
                hosts: vec!["worker-1".into()],
                run_number,
                triggered_slot: Some(slot),
            },
        }
    }

    #[test]
    fn finishing_the_same_revision_restores_its_slot_and_run_number() {
        let slot = "2025-08-12T20:00:00Z"
            .parse::<DateTime<FixedOffset>>()
            .unwrap();
        let hash = ExecutionHash::from_hex("1").unwrap();
        let mut status = PlaybookPlanStatus {
            current_hash: hash.to_string(),
            last_run_number: 0,
            ..Default::default()
        };

        sync_desired_hash_after_finished_run(
            &mut status,
            &hash,
            &finished_run(hash, 3, slot),
            None,
        );

        assert_eq!(status.last_run_number, 3);
        // Still the desired revision, so the slot it consumed keeps it from re-triggering itself
        // inside its own grace window.
        assert_eq!(status.last_triggered_run, Some(slot));
    }

    fn surviving_run(hash: ExecutionHash, slot: Option<DateTime<FixedOffset>>) -> SurvivingRun {
        surviving_run_in(v1beta1::PlayPhase::Running, hash, slot)
    }

    fn surviving_run_in(
        phase: v1beta1::PlayPhase,
        hash: ExecutionHash,
        slot: Option<DateTime<FixedOffset>>,
    ) -> SurvivingRun {
        SurvivingRun {
            run: RecordedRun {
                execution_hash: hash,
                mirror: ActiveRun {
                    execution_hash: hash.to_string(),
                    run_id: "run-2".into(),
                    job_name: "apply-plan-1-4".into(),
                    play_uid: "surviving-play-uid".into(),
                    hosts: vec!["worker-1".into()],
                    run_number: 4,
                    triggered_slot: slot,
                },
            },
            phase,
        }
    }

    /// A terminal result is drained ahead of anything live, so a tick can apply one run's outcome
    /// while a *different* run is still going. `lastTriggeredRun` is the only thing standing
    /// between a schedule window and a second run inside it, so it must describe the run the
    /// plan is actually holding — not the one that has already finished.
    #[test]
    fn a_finished_run_does_not_claim_the_slot_of_a_run_still_in_flight() {
        let finished_slot = "2025-08-12T20:00:00Z"
            .parse::<DateTime<FixedOffset>>()
            .unwrap();
        let live_slot = "2025-08-12T21:00:00Z"
            .parse::<DateTime<FixedOffset>>()
            .unwrap();
        let hash = ExecutionHash::from_hex("1").unwrap();
        let mut status = PlaybookPlanStatus {
            current_hash: hash.to_string(),
            last_run_number: 0,
            last_triggered_run: Some(live_slot),
            ..Default::default()
        };

        sync_desired_hash_after_finished_run(
            &mut status,
            &hash,
            &finished_run(hash, 3, finished_slot),
            Some(&surviving_run(hash, Some(live_slot))),
        );

        assert_eq!(
            status.last_triggered_run,
            Some(live_slot),
            "the slot must keep describing the run still in flight"
        );
        // The number is still claimed: it reserves a name against every later run, which is
        // true of a finished run whatever else the plan is holding.
        assert_eq!(status.last_run_number, 3);
    }

    /// The surviving run's window is taken from its own record, so a plan status that has not
    /// caught up with it — the tick that created its Job failed before patching the plan, leaving
    /// the *previous* run's slot standing — is corrected rather than trusted.
    #[test]
    fn draining_a_result_records_the_surviving_run_over_a_stale_marker() {
        let finished_slot = "2025-08-12T20:00:00Z"
            .parse::<DateTime<FixedOffset>>()
            .unwrap();
        let live_slot = "2025-08-12T21:00:00Z"
            .parse::<DateTime<FixedOffset>>()
            .unwrap();
        let hash = ExecutionHash::from_hex("1").unwrap();
        let mut status = PlaybookPlanStatus {
            current_hash: hash.to_string(),
            last_triggered_run: Some(finished_slot),
            ..Default::default()
        };

        sync_desired_hash_after_finished_run(
            &mut status,
            &hash,
            &finished_run(hash, 3, finished_slot),
            Some(&surviving_run(hash, Some(live_slot))),
        );

        assert_eq!(status.last_triggered_run, Some(live_slot));
    }

    /// An unscheduled run consumed no window, so it has none to record. The finished run's is
    /// then the newest window the plan has used, and leaving the marker behind it would let its own
    /// grace window trigger a second run once the run is out of the way.
    #[test]
    fn an_unscheduled_surviving_run_leaves_the_finished_window_standing() {
        let finished_slot = "2025-08-12T20:00:00Z"
            .parse::<DateTime<FixedOffset>>()
            .unwrap();
        let hash = ExecutionHash::from_hex("1").unwrap();
        let mut status = PlaybookPlanStatus {
            current_hash: hash.to_string(),
            ..Default::default()
        };

        sync_desired_hash_after_finished_run(
            &mut status,
            &hash,
            &finished_run(hash, 3, finished_slot),
            Some(&surviving_run(hash, None)),
        );

        assert_eq!(status.last_triggered_run, Some(finished_slot));
        assert_eq!(status.last_run_number, 3);
    }

    /// A run that has not launched a Job has consumed nothing, whatever its record says about
    /// the window it was created for. Crediting it would let a run that is then abandoned — a
    /// plan suspended and resumed inside the window, or one left with no hosts to trigger — mark a
    /// window as used that nothing ever ran in, and no abandon path clears the marker again. The
    /// tick that gives such a run a Job records the slot itself, so nothing is lost by waiting.
    #[test]
    fn a_run_without_a_job_claims_no_window() {
        let finished_slot = "2025-08-12T20:00:00Z"
            .parse::<DateTime<FixedOffset>>()
            .unwrap();
        let live_slot = "2025-08-12T21:00:00Z"
            .parse::<DateTime<FixedOffset>>()
            .unwrap();
        let hash = ExecutionHash::from_hex("1").unwrap();
        let unlaunched = [
            v1beta1::PlayPhase::Prepared,
            v1beta1::PlayPhase::Starting,
            v1beta1::PlayPhase::Launching,
            v1beta1::PlayPhase::Aborted,
        ];

        for phase in unlaunched {
            assert!(
                !consumed_its_slot(&phase, &hash, &hash),
                "{phase:?} has no Job, even on the desired revision"
            );

            let mut status = PlaybookPlanStatus {
                current_hash: hash.to_string(),
                ..Default::default()
            };
            sync_desired_hash_after_finished_run(
                &mut status,
                &hash,
                &finished_run(hash, 3, finished_slot),
                Some(&surviving_run_in(phase.clone(), hash, Some(live_slot))),
            );

            assert_eq!(
                status.last_triggered_run,
                Some(finished_slot),
                "{phase:?} must not claim the window its record names"
            );
        }

        // The one phase that proves the Job was created, and the only one no later tick records a
        // slot for — which is what this restore is for.
        assert!(consumed_its_slot(
            &v1beta1::PlayPhase::Running,
            &hash,
            &hash
        ));
    }

    /// The other half of the same rule, and the one an adopted `Launching` run meets: its
    /// own Job exists, so it is allowed to finish, but the window is the replacement revision's.
    /// `update_desired_hash` cleared the marker for exactly that reason, and nothing would clear it
    /// a second time — the superseded run's own finalization leaves it standing, because its hash no
    /// longer matches the desired one.
    #[test]
    fn an_adopted_superseded_run_claims_no_window() {
        let slot = "2025-08-12T20:00:00Z"
            .parse::<DateTime<FixedOffset>>()
            .unwrap();
        let old_hash = ExecutionHash::from_hex("1").unwrap();
        let new_hash = ExecutionHash::from_hex("2").unwrap();

        assert!(!consumed_its_slot(
            &v1beta1::PlayPhase::Running,
            &old_hash,
            &new_hash
        ));

        // What the plan is left with once that run finishes: the marker `update_desired_hash`
        // cleared stays cleared, so the replacement revision may run inside the same window.
        let mut status = PlaybookPlanStatus {
            current_hash: new_hash.to_string(),
            ..Default::default()
        };
        sync_desired_hash_after_finished_run(
            &mut status,
            &new_hash,
            &finished_run(old_hash, 3, slot),
            None,
        );

        assert_eq!(status.last_triggered_run, None);
    }

    /// A run still applying a superseded revision must not claim the window: the edit is owed a
    /// run inside the window it was made in, which is exactly what clearing the marker allows.
    #[test]
    fn a_surviving_run_on_an_obsolete_revision_claims_no_window() {
        let slot = "2025-08-12T20:00:00Z"
            .parse::<DateTime<FixedOffset>>()
            .unwrap();
        let old_hash = ExecutionHash::from_hex("1").unwrap();
        let new_hash = ExecutionHash::from_hex("2").unwrap();
        let mut status = PlaybookPlanStatus {
            current_hash: old_hash.to_string(),
            last_triggered_run: Some(slot),
            ..Default::default()
        };

        sync_desired_hash_after_finished_run(
            &mut status,
            &new_hash,
            &finished_run(old_hash, 3, slot),
            Some(&surviving_run(old_hash, Some(slot))),
        );

        assert_eq!(status.last_triggered_run, None);
    }

    #[test]
    fn finishing_an_obsolete_revision_clears_its_slot() {
        let slot = "2025-08-12T20:00:00Z"
            .parse::<DateTime<FixedOffset>>()
            .unwrap();
        let old_hash = ExecutionHash::from_hex("1").unwrap();
        let new_hash = ExecutionHash::from_hex("2").unwrap();
        let mut status = PlaybookPlanStatus {
            current_hash: old_hash.to_string(),
            last_run_number: 3,
            last_triggered_run: Some(slot),
            ..Default::default()
        };

        sync_desired_hash_after_finished_run(
            &mut status,
            &new_hash,
            &finished_run(old_hash, 3, slot),
            None,
        );

        assert_eq!(status.current_hash, new_hash.to_string());
        assert_eq!(status.last_run_number, 0);
        // The replacement revision may start straight away, in the same window.
        assert_eq!(status.last_triggered_run, None);
    }

    #[test]
    fn decide_terminal_oneshot_all_current_succeeds() {
        let now = "2025-08-12T20:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let outcome = decide_terminal(
            &ExecutionMode::OneShot,
            None,
            &v1beta1::PlayPhase::Succeeded,
            0,
            3,
            now,
        );

        assert_eq!(outcome.phase, Phase::Succeeded);
        assert_eq!(outcome.next_run, None);
        assert_eq!(outcome.summary, "3/3 up-to-date");
        assert_eq!(outcome.requeue, None);
    }

    #[test]
    fn decide_terminal_oneshot_failed_run_fails_and_never_reschedules() {
        let now = "2025-08-12T20:00:00Z".parse::<DateTime<Utc>>().unwrap();
        // A schedule is irrelevant in OneShot — even with one set it must resolve terminally and
        // never reschedule.
        let outcome = decide_terminal(
            &ExecutionMode::OneShot,
            Some("0 3 * * *"),
            &v1beta1::PlayPhase::Failed,
            1,
            3,
            now,
        );

        assert_eq!(outcome.phase, Phase::Failed);
        assert_eq!(outcome.next_run, None);
        assert_eq!(outcome.summary, "1/3 outdated");
        assert_eq!(outcome.requeue, None);
    }

    #[test]
    fn decide_terminal_recurring_keeps_the_verdict_and_names_the_next_slot() {
        let now = "2025-08-12T20:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let next_slot = Some(
            "2025-08-13T03:00:00Z"
                .parse::<DateTime<FixedOffset>>()
                .unwrap(),
        );

        for (outcome, expected) in [
            (v1beta1::PlayPhase::Succeeded, Phase::Succeeded),
            (v1beta1::PlayPhase::Failed, Phase::Failed),
        ] {
            let terminal = decide_terminal(
                &ExecutionMode::Recurring,
                Some("0 3 * * *"),
                &outcome,
                0,
                2,
                now,
            );

            // The result of the run that just finished stands between slots; `next_run` is what
            // says another one is coming.
            assert_eq!(terminal.phase, expected);
            assert_eq!(terminal.next_run, next_slot);
            // Overrides the caller's default requeue so the plan wakes up at the next slot.
            assert!(terminal.requeue.is_some());
        }
    }

    /// A `Recurring` run that fails leaves every host on the `lastAppliedHash` an earlier run gave
    /// it, so nothing is outdated — the verdict has to come from the run, not from the drift.
    #[test]
    fn decide_terminal_reports_a_failed_run_that_left_no_drift_behind() {
        let now = "2025-08-12T20:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let outcome = decide_terminal(
            &ExecutionMode::Recurring,
            Some("0 3 * * *"),
            &v1beta1::PlayPhase::Failed,
            0,
            2,
            now,
        );

        assert_eq!(outcome.phase, Phase::Failed);
        assert_eq!(outcome.summary, "2/2 up-to-date");
        assert!(outcome.next_run.is_some());
    }

    /// A recap that could not be read is not evidence that the hosts were reached.
    #[test]
    fn decide_terminal_reports_an_unreadable_recap_as_failed() {
        let now = "2025-08-12T20:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let outcome = decide_terminal(
            &ExecutionMode::OneShot,
            None,
            &v1beta1::PlayPhase::Unknown,
            0,
            2,
            now,
        );

        assert_eq!(outcome.phase, Phase::Failed);
    }

    #[test]
    fn decide_terminal_recurring_without_schedule_keeps_the_verdict() {
        let now = "2025-08-12T20:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let succeeded = decide_terminal(
            &ExecutionMode::Recurring,
            None,
            &v1beta1::PlayPhase::Succeeded,
            0,
            2,
            now,
        );
        let failed = decide_terminal(
            &ExecutionMode::Recurring,
            None,
            &v1beta1::PlayPhase::Failed,
            0,
            2,
            now,
        );

        // Nothing to reschedule against (the start gate normally prevents a schedule-less Recurring
        // plan from ever starting a run), but the run that did happen keeps its verdict.
        assert_eq!(succeeded.phase, Phase::Succeeded);
        assert_eq!(succeeded.next_run, None);
        assert_eq!(succeeded.requeue, None);
        assert_eq!(failed.phase, Phase::Failed);
        assert_eq!(failed.next_run, None);
        assert_eq!(failed.requeue, None);
    }
}
