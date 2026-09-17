use k8s_openapi::api::{batch, core::v1::Node};
use kube::runtime::reflector::Store;

use crate::{
    utils::upsert_condition,
    v1beta1::{
        DependencyStatus, HostOutcome, Phase, PlayPhase, PlayStatus, PlaybookPlanCondition,
        PlaybookPlanStatus, distinct_host_count,
    },
};

use super::{execution_evaluator::ExecutionHash, locking::BlockedBy, node_labels, node_recreation};

/// Whether this run's single Job has reached a terminal state — `Complete` or `Failed`.
pub fn job_finished(job: &batch::v1::Job) -> bool {
    job.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .map(|conditions| {
            conditions
                .iter()
                .any(|c| (c.type_ == "Complete" || c.type_ == "Failed") && c.status == "True")
        })
        .unwrap_or(false)
}

/// Applies the durable result of a finished `Play` to the owning plan. Normal completion and
/// restart recovery both use this path so host state and conditions cannot diverge based on which
/// side of the final plan-status write the operator stopped on.
///
/// A non-terminal `Play` is a no-op rather than a partial application: the phase is decided *before*
/// anything is written, so a caller that ever passes one leaves the plan untouched instead of
/// half-updated.
///
/// `provides_version` is the version *that run's* record declared, not the plan's current one, and
/// is `None` for a plan that provides nothing or a run whose record is gone. It is stamped beside
/// the hash under exactly the same condition, so a host can never carry one without the other.
///
/// `nodes` names the machine each succeeded host was: its Node's uid is stamped beside the hash, so
/// a Node later re-registered under the same name can be told apart (`node_recreation`).
pub fn apply_terminal_play_status(
    execution_hash: &ExecutionHash,
    provides_version: Option<&str>,
    play_status: &PlayStatus,
    nodes: &Store<Node>,
    status: &mut PlaybookPlanStatus,
) {
    let now = chrono::Local::now().fixed_offset();
    let succeeded = play_status
        .hosts
        .values()
        .filter(|result| result.outcome == HostOutcome::Succeeded)
        .count();
    let total = play_status.host_count as usize;
    let ready = match play_status.phase {
        PlayPhase::Succeeded => PlaybookPlanCondition {
            type_: "Ready".into(),
            status: "True".into(),
            reason: Some("AllHostsSucceeded".into()),
            message: Some(format!("{succeeded}/{total} hosts completed successfully")),
            last_transition_time: Some(now),
        },
        PlayPhase::Unknown => PlaybookPlanCondition {
            type_: "Ready".into(),
            status: "False".into(),
            reason: Some("RecapUnavailable".into()),
            message: Some("the operator could not recover per-host results for this run".into()),
            last_transition_time: Some(now),
        },
        PlayPhase::Failed => PlaybookPlanCondition {
            type_: "Ready".into(),
            status: "False".into(),
            reason: Some("SomeHostsDidNotSucceed".into()),
            message: Some(format!("{succeeded}/{total} hosts completed successfully")),
            last_transition_time: Some(now),
        },
        PlayPhase::Prepared
        | PlayPhase::Starting
        | PlayPhase::Launching
        | PlayPhase::Running
        | PlayPhase::Aborted => {
            return;
        }
    };

    clear_run_conditions(status);
    let hosts_status = status.hosts_status.get_or_insert_default();
    for (host, result) in &play_status.hosts {
        let entry = hosts_status.entry(host.clone()).or_default();
        if result.outcome == HostOutcome::Succeeded {
            entry.last_applied_hash = execution_hash.to_string();
            // Stamped with the hash and only with the hash: it dates the *claim*. Same source as
            // `lastTransitionTime` below, so a replayed recovery dates the claim when the run
            // finished rather than when it was noticed.
            entry.applied_at = play_status.finished_at.or(Some(now));
            // The machine the claim is about, so that a Node re-registered under this name can be
            // recognised as a different one (`node_recreation`). Read now rather than at launch:
            // a Node replaced mid-run takes the run's pod on it down, so the host cannot report
            // `Succeeded` for a machine it was never on.
            entry.applied_node_uid = node_recreation::current_node_uid(nodes, host);
            // From the run, so the three halves of one claim — the revision, when it was made and
            // what it provides — are always the same run's. A plan edited while this run was in
            // flight already advertises the next version, and stamping that here would label the
            // host for a revision it never received.
            entry.applied_version = provides_version.map(str::to_string);
        }
        entry.last_outcome = result.outcome.clone();
        // The run's own finish time when the record carries one, so replaying a recovered result
        // reports when it happened rather than when it was noticed. Falling back to `now` rather
        // than to `None`, which would blank a timestamp the previous run had legitimately set.
        entry.last_transition_time = play_status.finished_at.or(Some(now));
    }

    upsert_condition(
        &mut status.conditions,
        PlaybookPlanCondition {
            type_: "Running".into(),
            status: "False".into(),
            reason: None,
            message: None,
            last_transition_time: Some(now),
        },
    );
    upsert_condition(&mut status.conditions, ready);
}

/// What a providing plan publishes, and how far it currently reaches.
pub struct ProvidedLabel<'a> {
    /// The key derived from the plan's own namespace and name.
    pub key: &'a str,
    /// The version the plan's spec declares — what a converged host's label becomes.
    pub version: &'a str,
    /// How many Nodes in the cluster carry the key at exactly `version` — how far the current
    /// version's rollout has got.
    pub at_version: usize,
    /// How many Nodes in the cluster carry the key, at whatever version.
    ///
    /// The plan's *reach*, not a claim about any dependent's inventory: a `NodeAccessPolicy` may
    /// narrow what a given dependent can actually use. Kept apart from `at_version` because with
    /// node labels disabled this is the number that matters: leftovers an admin has to remove,
    /// whatever version they carry.
    pub nodes: usize,
}

impl<'a> ProvidedLabel<'a> {
    /// Reads both counts for `key` off the Node cache, in one pass.
    pub fn from_nodes(key: &'a str, version: &'a str, nodes: &Store<Node>) -> Self {
        let reach = node_labels::label_reach(key, version, nodes);
        Self {
            key,
            version,
            at_version: reach.at_version,
            nodes: reach.carrying,
        }
    }
}

/// Reports whether this plan's `spec.provides` claim is actually reaching the Nodes, and how far.
///
/// Only present on a plan that provides something — for every other plan the question is meaningless
/// and a condition answering it would be noise, so dropping `provides` drops the condition too.
///
/// It names the key and the counts so that both ends of a dependency are readable on their own
/// objects. A dependent says it is waiting for `platform/containerd-config`; the provider says what
/// it publishes, on how many Nodes that version has landed, and how many carry the key at all. A
/// version bump leaves every Node on the old value until its host runs again, so only the first
/// count moves during a rollout. Without it,
/// answering "is the provider actually doing anything?" means going to the Nodes.
///
/// The `False` case is the one this exists for. With the chart's `nodeLabels.enabled` turned off the
/// operator has no `nodes: patch`, so a plan with `provides` runs perfectly well and publishes
/// nothing — and every plan depending on it waits forever, looking exactly like a typo in a
/// selector. Saying so on the provider is what turns that into a five-second diagnosis. Its count
/// means something different there: labels left over from before the feature was switched off, which
/// still steer inventories and which only an admin can now remove.
pub fn set_provides_labels_condition(
    status: &mut PlaybookPlanStatus,
    provided: Option<ProvidedLabel>,
    labels_enabled: bool,
) {
    let Some(provided) = provided else {
        status
            .conditions
            .retain(|condition| condition.type_ != "ProvidesLabels");
        return;
    };

    let ProvidedLabel {
        key,
        version,
        at_version,
        nodes,
    } = provided;
    let now = chrono::Local::now().fixed_offset();
    let condition = if labels_enabled {
        PlaybookPlanCondition {
            type_: "ProvidesLabels".into(),
            status: "True".into(),
            reason: Some("PublishingNodeLabels".into()),
            message: Some(format!(
                "publishing {key}={version} on {at_version} of {nodes} Node(s) for other plans to depend on"
            )),
            last_transition_time: Some(now),
        }
    } else {
        PlaybookPlanCondition {
            type_: "ProvidesLabels".into(),
            status: "False".into(),
            reason: Some("NodeLabelsDisabled".into()),
            message: Some(format!(
                "node labels are disabled on this cluster (chart nodeLabels.enabled=false), so this plan does not publish {key} and plans depending on it will not see its hosts; {nodes} Node(s) still carry it from before"
            )),
            last_transition_time: Some(now),
        }
    };

    upsert_condition(&mut status.conditions, condition);
}

/// One dependency a plan inherits from an inventory it references.
///
/// The inventory's name travels with it because the plan references several and the fix is in one of
/// them: "3 hosts waiting" is a fact, "3 hosts waiting, in `workers-with-containerd`" is something a
/// reader can act on.
#[derive(Clone, Debug)]
pub struct InventoryDependency {
    pub inventory: String,
    pub dependency: DependencyStatus,
}

/// How many dependencies a condition message names before it gives up and counts the rest.
///
/// A condition message is read, not parsed. A plan referencing a handful of inventories that each
/// gate on a handful of providers would otherwise produce a paragraph nobody finishes.
const NAMED_DEPENDENCIES: usize = 3;

/// Reports the hosts this plan would run on if another plan had finished with them.
///
/// Absent on a plan that references no dependency at all, for the same reason as `ProvidesLabels`:
/// a condition answering a question the plan does not pose is noise on every object that does not
/// have the problem.
///
/// The counts are the inventories' own, copied rather than recomputed. Two controllers deriving the
/// same number by different routes would eventually disagree, and a plan contradicting the inventory
/// it names is worse than either number on its own.
///
/// Note what the numbers are *not*: they are the inventory's view, taken before the
/// `NodeAccessPolicy` clamp this plan is subject to. A Node counted as satisfied may still be out of
/// this plan's reach — `eligibleHosts` is what says which hosts it actually has.
pub fn set_dependencies_waiting_condition(
    status: &mut PlaybookPlanStatus,
    dependencies: &[InventoryDependency],
) {
    if dependencies.is_empty() {
        status
            .conditions
            .retain(|condition| condition.type_ != "DependenciesWaiting");
        return;
    }

    let now = chrono::Local::now().fixed_offset();
    let waiting: Vec<&InventoryDependency> = dependencies
        .iter()
        .filter(|entry| entry.dependency.waiting > 0)
        .collect();

    let condition = if waiting.is_empty() {
        PlaybookPlanCondition {
            type_: "DependenciesWaiting".into(),
            status: "False".into(),
            reason: Some("DependenciesMet".into()),
            message: Some(
                "every host the plan's inventories resolve to has the dependencies they require"
                    .into(),
            ),
            last_transition_time: Some(now),
        }
    } else {
        let named: Vec<String> = waiting
            .iter()
            .take(NAMED_DEPENDENCIES)
            .map(|entry| {
                let dependency = &entry.dependency;
                // An empty namespace is a key that decodes to no plan, reported by its spelling.
                let provider = if dependency.provider_namespace.is_empty() {
                    dependency.provider_name.clone()
                } else {
                    format!(
                        "{}/{}",
                        dependency.provider_namespace, dependency.provider_name
                    )
                };
                format!(
                    "{} host(s) in group '{}' of ClusterInventory '{}' waiting for {provider} ({})",
                    dependency.waiting, dependency.group, entry.inventory, dependency.requirement
                )
            })
            .collect();
        let mut message = named.join("; ");
        if let Some(rest) = waiting
            .len()
            .checked_sub(NAMED_DEPENDENCIES)
            .filter(|rest| *rest > 0)
        {
            message.push_str(&format!("; and {rest} more"));
        }

        PlaybookPlanCondition {
            type_: "DependenciesWaiting".into(),
            status: "True".into(),
            reason: Some("HostsWaiting".into()),
            message: Some(message),
            last_transition_time: Some(now),
        }
    };

    upsert_condition(&mut status.conditions, condition);
}

/// Restates what the plan is waiting on, from `dependencies` as this tick resolved them.
///
/// `None` is a tick that never resolved the inventories. It says nothing about them, so the
/// `DependenciesWaiting` condition keeps what the last resolving tick set: removing it would claim
/// the plan depends on nothing. The summary clause is still stripped, because the summary it was
/// appended to may have been rewritten since.
pub fn restate_dependencies(
    status: &mut PlaybookPlanStatus,
    dependencies: Option<&[InventoryDependency]>,
) {
    if let Some(dependencies) = dependencies {
        set_dependencies_waiting_condition(status, dependencies);
    }
    append_dependency_summary_clause(status, dependencies.unwrap_or_default());
}

/// How every dependency clause ends, and the only thing that identifies one already on a summary.
///
/// The clause is always the last thing appended — `apply_run_diagnostic`'s runs earlier in the tick
/// — so matching the end of the string is enough to find it.
const WAITING_CLAUSE_TAIL: &str = " host(s) waiting for dependencies)";

/// Restates the one clause the summary column has room for: how many hosts a dependency is keeping
/// out.
///
/// **A qualifier, never a substitute.** The summary's job is to say what the plan is doing, and a
/// wait for another plan does not replace that. `5/5 up-to-date` beside an inventory holding eight
/// more machines back is true and misleading in exactly the way this fixes.
///
/// **Idempotent, and that is load-bearing.** An idle tick does not rewrite `summary` at all — it
/// carries the stored one forward — so the clause a previous tick added is still on it. Appending
/// to that would grow the summary by a clause per reconcile, and because every changed status is a
/// write, every write is a watch event and every event is the next reconcile, it would never settle:
/// a printer column growing until the object hits the size limit and no status can be written at
/// all. So the previous clause is stripped first and the result is a fixed point, which makes the
/// merge patch a no-op as soon as the count stops moving. Stripping is also what *removes* the
/// clause when the last dependency is satisfied, since nothing else would.
///
/// The clause is only *added* while the plan is idle. A plan mid-run has a summary about that run,
/// which is what someone watching it wants; the dependencies are still on the condition, and the
/// clause comes back when the run ends.
///
/// The **strip runs either way**, so no clause can outlive the tick that wrote it. Every path that
/// starts or adopts a run replaces the summary with the run's own, which would carry the stale
/// clause off with it — but that is an invariant spread across several call sites, and being wrong
/// about it once would leave a stale count on a running plan and break the exact-match in
/// `summary_unclaimed_since_adoption`. Stripping unconditionally costs one comparison and does not
/// depend on being right.
///
/// Counted over distinct requirements' waiting hosts, which may name the same Node twice if two
/// dependencies hold it — the condition is where the breakdown is, and the largest single wait is
/// the honest headline for one clause.
pub fn append_dependency_summary_clause(
    status: &mut PlaybookPlanStatus,
    dependencies: &[InventoryDependency],
) {
    if let Some(summary) = status.summary.as_mut() {
        // A loop rather than one strip, so a status already carrying several from before this was
        // idempotent is healed on the first tick instead of shedding one clause per reconcile.
        while summary.ends_with(WAITING_CLAUSE_TAIL) {
            match summary.rfind(" (") {
                Some(clause_start) => summary.truncate(clause_start),
                None => {
                    summary.clear();
                    break;
                }
            }
        }
        // All that was there was the clause, written onto a plan that had no summary of its own.
        if summary.is_empty() {
            status.summary = None;
        }
    }

    if status.active_run.is_some() {
        return;
    }

    let Some(waiting) = dependencies
        .iter()
        .map(|entry| entry.dependency.waiting)
        .max()
        .filter(|waiting| *waiting > 0)
    else {
        return;
    };

    // A plan that has never run has no summary to qualify, and it is the one most likely to be
    // waiting: its inventory resolves no host until the provider reaches one. The clause then stands
    // alone, and the strip above takes the whole string back off.
    match status.summary.as_mut() {
        Some(summary) => summary.push_str(&format!(" ({waiting}{WAITING_CLAUSE_TAIL}")),
        None => status.summary = Some(format!("({waiting}{WAITING_CLAUSE_TAIL}")),
    }
}

/// Sets the plan-level `Blocked` condition, which reports whether this run is currently waiting on
/// a per-host lock held by another run (locks are global per node — see `locking::ensure_locks`).
/// `Some(blocked)` sets it `True` with the offending host and, when known, the holding run named in
/// the message; `None` — the run holds (or could take) all its locks — sets it `False`. The `phase`
/// stays whatever it was (typically `Applying`): being blocked is an orthogonal, transient overlay
/// on the plan's lifecycle, not a lifecycle state of its own, so a condition models it better than a
/// phase would.
pub fn set_blocked_condition(status: &mut PlaybookPlanStatus, blocked: Option<&BlockedBy>) {
    let now = chrono::Local::now().fixed_offset();

    let condition = match blocked {
        Some(blocked) => {
            let holder = blocked.holder.as_deref().unwrap_or("another run");
            PlaybookPlanCondition {
                type_: "Blocked".into(),
                status: "True".into(),
                reason: Some("HostLockHeld".into()),
                message: Some(format!(
                    "waiting for a lock on host '{}' held by {holder}",
                    blocked.host
                )),
                last_transition_time: Some(now),
            }
        }
        None => PlaybookPlanCondition {
            type_: "Blocked".into(),
            status: "False".into(),
            reason: None,
            message: None,
            last_transition_time: Some(now),
        },
    };

    upsert_condition(&mut status.conditions, condition);
}

/// What a plan is waiting on the cluster's nodes for, when it is waiting on them at all.
///
/// The two are genuinely different waits and a reader has to be able to tell them apart: one
/// happens *inside* a run that has already committed to its hosts, the other happens *instead* of
/// starting one. They share a condition because to anyone watching the plan they are the same
/// question — "why is nothing happening, and what would change that?" — and a plan can only ever be
/// in one of them at a time.
pub enum WaitingForNodes<'a> {
    /// A run is under way and its managed-ssh proxy pods have not all come up yet (a node may be
    /// `NotReady`, or its pod still starting). Resolves on its own, one way or the other: the pods
    /// become Ready, or the grace window closes and the run proceeds without those hosts.
    ProxyPods(&'a [String]),
    /// No run was started, because every host one would target is on a node that is not `Ready`.
    /// Resolves when a node does — the controller's Node watch is what notices.
    NodesNotReady(&'a [String]),
}

/// Sets the plan-level `WaitingForNodes` condition. `None` — the proxies are all Ready or timed out
/// and the run is proceeding, or there are no down nodes holding a run back — sets it `False`.
///
/// Like `Blocked`, this is an orthogonal transient overlay on the plan's lifecycle, not a phase of
/// its own, so a condition models it better than a phase would.
pub fn set_waiting_for_nodes_condition(
    status: &mut PlaybookPlanStatus,
    waiting: Option<WaitingForNodes>,
) {
    let now = chrono::Local::now().fixed_offset();

    let condition = match waiting {
        Some(WaitingForNodes::ProxyPods(hosts)) => PlaybookPlanCondition {
            type_: "WaitingForNodes".into(),
            status: "True".into(),
            reason: Some("ProxyPodsNotReady".into()),
            message: Some(format!(
                "waiting for managed-ssh proxy pods on host(s): {}",
                hosts.join(", ")
            )),
            last_transition_time: Some(now),
        },
        Some(WaitingForNodes::NodesNotReady(nodes)) => PlaybookPlanCondition {
            type_: "WaitingForNodes".into(),
            status: "True".into(),
            reason: Some("NodesNotReady".into()),
            message: Some(format!(
                "not starting a run: every node it would target is not Ready ({})",
                nodes.join(", ")
            )),
            last_transition_time: Some(now),
        },
        None => PlaybookPlanCondition {
            type_: "WaitingForNodes".into(),
            status: "False".into(),
            reason: None,
            message: None,
            last_transition_time: Some(now),
        },
    };

    upsert_condition(&mut status.conditions, condition);
}

/// Whether the plan is currently reporting the [`WaitingForNodes::NodesNotReady`] hold, as opposed
/// to the proxy-pod wait that shares the condition or no wait at all.
///
/// Exists so a caller can retire *its* wait without touching the other one. Clearing the condition
/// unconditionally looks harmless — the tick that starts a run re-asserts `ProxyPodsNotReady` a
/// moment later — but `upsert_condition` restamps `lastTransitionTime` whenever the status flips,
/// so the round trip through `False` turns a status that says nothing new into a write, a
/// `resourceVersion` bump and another reconcile, every five seconds for as long as a run waits on
/// its proxy pods. It also leaves the timestamp meaning "the last tick" rather than "when the wait
/// began".
pub fn held_for_unready_nodes(status: &PlaybookPlanStatus) -> bool {
    status.conditions.iter().any(|condition| {
        condition.type_ == "WaitingForNodes"
            && condition.status == "True"
            && condition.reason.as_deref() == Some("NodesNotReady")
    })
}

/// Whether the plan's last outcome leaves something a further run could still apply.
///
/// One comparison, but shared on purpose: the mapper that wakes a plan on an SSH key rotation and
/// the budget reset that lets the woken plan act must agree exactly. If the mapper were the wider of
/// the two it would wake plans that then decline to do anything; if it were the narrower, a plan
/// would sit on a fix it had already been given.
pub fn may_need_another_run(status: &PlaybookPlanStatus) -> bool {
    status.phase != Phase::Succeeded
}

pub fn clear_run_conditions(status: &mut PlaybookPlanStatus) {
    set_blocked_condition(status, None);
    set_waiting_for_nodes_condition(status, None);
}

/// Marks the plan as having a run in progress.
///
/// The counterpart for a completed run — clearing `Running` and computing `Ready` from its outcome —
/// is only ever read off its terminal `Play`, by [`apply_terminal_play_status`]. Keeping a second
/// implementation that recomputed the same conditions from a freshly parsed recap would be a way
/// for a restart-recovered result and a normally-completed one to disagree. Input availability is a
/// separate readiness overlay because it can fail before a run exists or while one is in flight.
pub fn set_running_condition(status: &mut PlaybookPlanStatus) {
    upsert_condition(
        &mut status.conditions,
        PlaybookPlanCondition {
            type_: "Running".into(),
            status: "True".into(),
            reason: Some("JobRunning".into()),
            message: Some("the run's Job exists and has not finished".into()),
            last_transition_time: Some(chrono::Local::now().fixed_offset()),
        },
    );
}

/// Withdraws `Running` while the run's Job name is held by something that failed the identity check.
///
/// An earlier tick may have seen this run's own Job and set `Running` from it; leaving that standing
/// would seat `JobRunning`/"the run's Job exists and has not finished" beside a summary saying the
/// opposite, for as long as the contested name survives — which, since such a name is never abandoned,
/// can be indefinitely.
pub fn set_job_identity_mismatch_condition(status: &mut PlaybookPlanStatus, job_name: &str) {
    upsert_condition(
        &mut status.conditions,
        PlaybookPlanCondition {
            type_: "Running".into(),
            status: "False".into(),
            reason: Some("JobIdentityMismatch".into()),
            message: Some(format!("Job {job_name} does not carry this run's identity")),
            last_transition_time: Some(chrono::Local::now().fixed_offset()),
        },
    );
}

/// Withdraws `Running` while a run whose `Play` record is gone is being stopped before its hosts
/// are released.
///
/// The wait spans as many ticks as the Job's cancellation takes, and there is nothing else on the
/// plan that would say why: the mirror still names the run, so an earlier tick's
/// `JobRunning`/"the run's Job exists and has not finished" would otherwise stand for the whole
/// teardown and describe a run that is being killed as one that is progressing.
pub fn set_run_record_lost_condition(status: &mut PlaybookPlanStatus, job_name: &str) {
    upsert_condition(
        &mut status.conditions,
        PlaybookPlanCondition {
            type_: "Running".into(),
            status: "False".into(),
            reason: Some("RunRecordLost".into()),
            message: Some(format!(
                "the Play record of run {job_name} is gone; its Job is being cancelled before its hosts are released"
            )),
            last_transition_time: Some(chrono::Local::now().fixed_offset()),
        },
    );
}

/// Marks the plan as not ready because one of its desired inputs could not be read. The message is
/// the full diagnostic, of which the plan summary may show only a short form.
pub fn set_inputs_unavailable_condition(status: &mut PlaybookPlanStatus, message: &str) {
    set_ready_overlay(status, "InputsUnavailable", message);
}

/// Marks the plan as not ready because its schedule or time zone is invalid. The message is the
/// same diagnostic shown in the plan summary.
pub fn set_invalid_scheduling_configuration_condition(
    status: &mut PlaybookPlanStatus,
    message: &str,
) {
    set_ready_overlay(status, "InvalidSchedulingConfiguration", message);
}

/// Marks the plan as not ready while the readiness gate holds it back: its last verdict still
/// stands, but there are hosts it has not applied the current revision to and cannot reach. Without
/// this a converged plan that gains a host on a down Node keeps the `Ready=True` of its previous run.
pub fn set_nodes_not_ready_condition(status: &mut PlaybookPlanStatus, message: &str) {
    set_ready_overlay(status, "NodesNotReady", message);
}

/// Temporarily replaces the host-derived `Ready` verdict with a reason the plan cannot act on.
fn set_ready_overlay(status: &mut PlaybookPlanStatus, reason: &str, message: &str) {
    upsert_condition(
        &mut status.conditions,
        PlaybookPlanCondition {
            type_: "Ready".into(),
            status: "False".into(),
            reason: Some(reason.into()),
            message: Some(message.into()),
            last_transition_time: Some(chrono::Local::now().fixed_offset()),
        },
    );
}

/// Retires the [`set_inputs_unavailable_condition`] overlay once the desired inputs read cleanly
/// again, returning whether that overlay was present so the caller only replaces its matching plan
/// summary.
pub fn clear_inputs_unavailable_condition(
    status: &mut PlaybookPlanStatus,
    outdated_count: usize,
) -> bool {
    clear_ready_overlay(status, outdated_count, "InputsUnavailable")
}

/// Retires the invalid-scheduling overlay once the schedule and time zone are valid, returning
/// whether that overlay was present so the caller only replaces its matching plan summary.
pub fn clear_invalid_scheduling_configuration_condition(
    status: &mut PlaybookPlanStatus,
    outdated_count: usize,
) -> bool {
    clear_ready_overlay(status, outdated_count, "InvalidSchedulingConfiguration")
}

/// Retires the [`set_nodes_not_ready_condition`] overlay once the plan is no longer held, returning
/// whether that overlay was present so the caller only replaces its matching plan summary.
pub fn clear_nodes_not_ready_condition(
    status: &mut PlaybookPlanStatus,
    outdated_count: usize,
) -> bool {
    clear_ready_overlay(status, outdated_count, "NodesNotReady")
}

/// Retires one temporary readiness overlay, restating `Ready` from the plan's per-host results.
/// Returns whether the named overlay was present and therefore changed.
///
/// Needed for every mode, not only one that also restores a phase: `Ready` is a printer column, and
/// nothing else rewrites it between runs. A `Recurring` plan would advertise a resolved outage until
/// its next slot completed, which for a daily schedule is a day of a false negative.
///
/// The results are the ones [`apply_terminal_play_status`] already folded into the plan: a host is
/// current exactly when its last run succeeded at this revision, which is what `outdated_count`
/// counts the complement of. A plan that has never run has no verdict to restate — and carried no
/// `Ready` condition before the overlay — so it gets none back rather than an invented one.
///
/// It is deliberately said in its **own** reason and wording rather than borrowed from
/// [`apply_terminal_play_status`], because the two count different populations and only one of them
/// is about a run. That function reports the hosts *one run* targeted, which in `OneShot` is just the
/// ones that were outdated when it started; this reports every host the plan is responsible for.
/// Sharing `AllHostsSucceeded`/`SomeHostsDidNotSucceed` and "N/M hosts completed successfully"
/// across both made the same condition change its numbers — a plan whose last run applied 2 of 10
/// hosts and failed one read "1/2 hosts completed successfully", then "9/10 hosts completed
/// successfully" once an unrelated input outage cleared, with nothing having run in between. Nothing
/// *did* complete in between, which is why this no longer claims it did.
fn clear_ready_overlay(
    status: &mut PlaybookPlanStatus,
    outdated_count: usize,
    reason: &str,
) -> bool {
    let overlaid = status
        .conditions
        .iter()
        .any(|condition| condition.type_ == "Ready" && condition.reason.as_deref() == Some(reason));
    if !overlaid {
        return false;
    }

    if status.hosts_status.is_none() {
        status
            .conditions
            .retain(|condition| condition.type_ != "Ready");
        return true;
    }

    let total = distinct_host_count(&status.eligible_hosts);
    let current = total.saturating_sub(outdated_count);
    let now = chrono::Local::now().fixed_offset();
    let condition = PlaybookPlanCondition {
        type_: "Ready".into(),
        status: if outdated_count == 0 { "True" } else { "False" }.into(),
        reason: Some(
            if outdated_count == 0 {
                "HostsUpToDate"
            } else {
                "HostsOutdated"
            }
            .into(),
        ),
        message: Some(format!("{current}/{total} hosts on the current revision")),
        last_transition_time: Some(now),
    };

    upsert_condition(&mut status.conditions, condition);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::runtime::{reflector::store::Writer, watcher};
    use std::collections::BTreeMap;

    fn nodes_with_uids(nodes: &[(&str, &str)]) -> Store<Node> {
        let mut writer = Writer::<Node>::default();
        let reader = writer.as_reader();
        writer.apply_watcher_event(&watcher::Event::Init);
        for (name, uid) in nodes {
            writer.apply_watcher_event(&watcher::Event::InitApply(Node {
                metadata: kube::core::ObjectMeta {
                    name: Some((*name).to_string()),
                    uid: Some((*uid).to_string()),
                    ..Default::default()
                },
                ..Default::default()
            }));
        }
        writer.apply_watcher_event(&watcher::Event::InitDone);
        reader
    }

    fn no_nodes() -> Store<Node> {
        nodes_with_uids(&[])
    }

    fn hash() -> ExecutionHash {
        crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash(
            "playbook",
            std::iter::empty(),
        )
    }

    fn provided(at_version: usize, nodes: usize) -> ProvidedLabel<'static> {
        ProvidedLabel {
            key: "platform.plan.ansible.cloudbending.dev/containerd",
            version: "1.4.2",
            at_version,
            nodes,
        }
    }

    /// The `False` case is the whole point: with node labels switched off, a plan with `provides`
    /// runs perfectly and publishes nothing, so every dependent waits and looks like it has a typo
    /// in its selector. The condition is what makes that a stated cause rather than a mystery.
    ///
    /// Both cases name the key, so that the two ends of a dependency can be read against each other
    /// without going to the Nodes — and the count says how far the provider has actually got.
    #[test]
    fn a_providing_plan_says_whether_its_labels_are_reaching_nodes() {
        let mut status = PlaybookPlanStatus::default();

        set_provides_labels_condition(&mut status, Some(provided(3, 5)), true);
        let condition = status
            .conditions
            .iter()
            .find(|condition| condition.type_ == "ProvidesLabels")
            .expect("a providing plan carries the condition");
        assert_eq!(condition.status, "True");
        let message = condition.message.as_deref().unwrap();
        assert!(
            message.contains("platform.plan.ansible.cloudbending.dev/containerd=1.4.2"),
            "{message}"
        );
        assert!(message.contains("on 3 of 5 Node(s)"), "{message}");

        set_provides_labels_condition(&mut status, Some(provided(3, 5)), false);
        let condition = status
            .conditions
            .iter()
            .find(|condition| condition.type_ == "ProvidesLabels")
            .unwrap();
        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason.as_deref(), Some("NodeLabelsDisabled"));
        let message = condition.message.as_deref().unwrap();
        assert!(
            message.contains("platform.plan.ansible.cloudbending.dev/containerd"),
            "the key an admin has to clean up by hand: {message}"
        );
        assert!(
            message.contains("5 Node(s) still carry it"),
            "leftovers count whatever version they carry: {message}"
        );
    }

    /// A version bump is the normal way to re-drive a provider, and from the moment it is applied
    /// every Node still carries the key at the old value. The condition must read as a rollout that
    /// has not started, not as one that has finished.
    #[test]
    fn the_rollout_count_only_includes_nodes_on_the_declared_version() {
        let key = "platform.plan.ansible.cloudbending.dev/containerd";
        let mut writer = Writer::<Node>::default();
        let nodes = writer.as_reader();
        writer.apply_watcher_event(&watcher::Event::Init);
        for (name, value) in [
            ("node-a", "1.4.2"),
            ("node-b", "1.4.2"),
            ("node-c", "1.5.0"),
        ] {
            writer.apply_watcher_event(&watcher::Event::InitApply(Node {
                metadata: kube::core::ObjectMeta {
                    name: Some(name.to_string()),
                    labels: Some(BTreeMap::from([(key.to_string(), value.to_string())])),
                    ..Default::default()
                },
                ..Default::default()
            }));
        }
        writer.apply_watcher_event(&watcher::Event::InitDone);
        let mut status = PlaybookPlanStatus::default();

        set_provides_labels_condition(
            &mut status,
            Some(ProvidedLabel::from_nodes(key, "1.5.0", &nodes)),
            true,
        );

        let message = status
            .conditions
            .iter()
            .find(|condition| condition.type_ == "ProvidesLabels")
            .and_then(|condition| condition.message.as_deref())
            .unwrap();
        assert!(
            message.contains(&format!("{key}=1.5.0 on 1 of 3 Node(s)")),
            "{message}"
        );
    }

    /// A plan that provides nothing is not answering this question, so it must not carry a stale
    /// answer to it either — dropping `spec.provides` has to drop the condition with it.
    #[test]
    fn a_plan_that_stops_providing_drops_the_condition() {
        let mut status = PlaybookPlanStatus::default();
        set_provides_labels_condition(&mut status, Some(provided(5, 5)), true);
        set_running_condition(&mut status);

        set_provides_labels_condition(&mut status, None, true);

        assert!(
            !status
                .conditions
                .iter()
                .any(|condition| condition.type_ == "ProvidesLabels")
        );
        assert!(
            status
                .conditions
                .iter()
                .any(|condition| condition.type_ == "Running"),
            "and nothing else is disturbed"
        );
    }

    fn dependency(inventory: &str, provider: &str, waiting: usize) -> InventoryDependency {
        InventoryDependency {
            inventory: inventory.to_string(),
            dependency: DependencyStatus {
                group: "workers".into(),
                key: format!("platform.plan.ansible.cloudbending.dev/{provider}"),
                provider_namespace: "platform".into(),
                provider_name: provider.to_string(),
                requirement: "Ge 1.4.0".into(),
                waiting,
                satisfied: 1,
                ..Default::default()
            },
        }
    }

    /// The condition a dependent's author reads to tell "not yet" from "never": which inventory,
    /// which group, which provider, and how many machines are still to come.
    #[test]
    fn a_waiting_dependency_is_named_on_the_plan() {
        let mut status = PlaybookPlanStatus::default();

        set_dependencies_waiting_condition(
            &mut status,
            &[dependency("workers-ci", "containerd", 3)],
        );

        let condition = status
            .conditions
            .iter()
            .find(|condition| condition.type_ == "DependenciesWaiting")
            .expect("a plan with a dependency carries the condition");
        assert_eq!(condition.status, "True");
        assert_eq!(condition.reason.as_deref(), Some("HostsWaiting"));
        let message = condition.message.as_deref().unwrap();
        for expected in [
            "3 host(s)",
            "workers",
            "workers-ci",
            "platform/containerd",
            "Ge 1.4.0",
        ] {
            assert!(
                message.contains(expected),
                "{message} should name {expected}"
            );
        }
    }

    #[test]
    fn a_key_naming_no_plan_is_named_by_its_spelling_on_the_plan() {
        let mut status = PlaybookPlanStatus::default();
        let mut malformed = dependency("workers-ci", "x", 3);
        malformed.dependency.provider_namespace = String::new();
        malformed.dependency.provider_name = ".plan.ansible.cloudbending.dev/x".into();

        set_dependencies_waiting_condition(&mut status, &[malformed]);

        let message = status.conditions[0].message.as_deref().unwrap();
        assert!(
            message.contains("waiting for .plan.ansible.cloudbending.dev/x (Ge 1.4.0)"),
            "{message}"
        );
    }

    /// A tick that could not resolve the inventories, such as the invalid-schedule exit, must not
    /// report the plan as depending on nothing.
    #[test]
    fn a_tick_without_resolved_dependencies_keeps_the_condition() {
        let mut status = PlaybookPlanStatus {
            summary: Some("5/5 up-to-date".into()),
            ..Default::default()
        };
        restate_dependencies(
            &mut status,
            Some(&[dependency("workers-ci", "containerd", 3)]),
        );

        status.summary = Some("invalid schedule (3 host(s) waiting for dependencies)".into());
        restate_dependencies(&mut status, None);

        let condition = status
            .conditions
            .iter()
            .find(|condition| condition.type_ == "DependenciesWaiting")
            .expect("the last resolving tick's condition stands");
        assert_eq!(condition.status, "True");
        assert_eq!(status.summary.as_deref(), Some("invalid schedule"));

        restate_dependencies(&mut status, Some(&[]));
        assert!(
            status
                .conditions
                .iter()
                .all(|condition| condition.type_ != "DependenciesWaiting"),
            "a resolved empty list does mean no dependency"
        );
    }

    /// A satisfied dependency is still a dependency: the plan says so rather than going quiet, so a
    /// reader can tell "this plan depends on nothing" from "everything it depends on is done".
    #[test]
    fn a_satisfied_dependency_reports_false_rather_than_nothing() {
        let mut status = PlaybookPlanStatus::default();

        set_dependencies_waiting_condition(
            &mut status,
            &[dependency("workers-ci", "containerd", 0)],
        );

        let condition = status
            .conditions
            .iter()
            .find(|condition| condition.type_ == "DependenciesWaiting")
            .unwrap();
        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason.as_deref(), Some("DependenciesMet"));
    }

    /// A condition answering a question the plan does not pose is noise on every object that does
    /// not have the problem — which is most of them.
    #[test]
    fn a_plan_without_dependencies_carries_no_condition() {
        let mut status = PlaybookPlanStatus::default();
        set_dependencies_waiting_condition(
            &mut status,
            &[dependency("workers-ci", "containerd", 3)],
        );
        set_running_condition(&mut status);

        set_dependencies_waiting_condition(&mut status, &[]);

        assert!(
            !status
                .conditions
                .iter()
                .any(|condition| condition.type_ == "DependenciesWaiting")
        );
        assert!(
            status
                .conditions
                .iter()
                .any(|condition| condition.type_ == "Running"),
            "and nothing else is disturbed"
        );
    }

    /// A condition message is read, not parsed, so a plan gated on a dozen providers has to stop
    /// somewhere and say how much it left out.
    #[test]
    fn the_message_names_three_dependencies_and_counts_the_rest() {
        let mut status = PlaybookPlanStatus::default();
        let dependencies: Vec<InventoryDependency> = (0..5)
            .map(|index| dependency("workers-ci", &format!("provider-{index}"), 1))
            .collect();

        set_dependencies_waiting_condition(&mut status, &dependencies);

        let message = status
            .conditions
            .iter()
            .find(|condition| condition.type_ == "DependenciesWaiting")
            .and_then(|condition| condition.message.clone())
            .unwrap();
        assert!(message.contains("provider-2"));
        assert!(!message.contains("provider-3"), "{message} stops at three");
        assert!(message.ends_with("; and 2 more"), "{message}");
    }

    /// The summary says what the plan is doing; the wait qualifies it rather than replacing it. A
    /// converged plan reading `5/5 up-to-date` beside an inventory holding eight machines back is
    /// true and misleading in exactly the way this fixes.
    #[test]
    fn the_summary_clause_is_appended_to_an_idle_plan() {
        let mut status = PlaybookPlanStatus {
            summary: Some("5/5 up-to-date".into()),
            ..Default::default()
        };

        append_dependency_summary_clause(&mut status, &[dependency("workers-ci", "containerd", 3)]);

        assert_eq!(
            status.summary.as_deref(),
            Some("5/5 up-to-date (3 host(s) waiting for dependencies)")
        );
    }

    /// **The property, not the single application.** No idle path rewrites `summary` — the stored
    /// one is carried forward — so this runs against its own previous output on every tick. A clause
    /// that stacked would grow the summary by forty bytes a reconcile, and since a changed status is
    /// a write, a write is a watch event and an event is the next reconcile, it would never settle:
    /// a printer column growing until the object hits its size limit and no status can be written at
    /// all.
    #[test]
    fn restating_the_clause_every_tick_is_a_fixed_point() {
        let mut status = PlaybookPlanStatus {
            summary: Some("5/5 up-to-date".into()),
            ..Default::default()
        };
        let waiting = [dependency("workers-ci", "containerd", 3)];

        for _ in 0..3 {
            append_dependency_summary_clause(&mut status, &waiting);
            assert_eq!(
                status.summary.as_deref(),
                Some("5/5 up-to-date (3 host(s) waiting for dependencies)")
            );
        }
    }

    /// A rollout is the count moving, tick after tick, against a summary that still carries the last
    /// one. Each has to replace its predecessor rather than queue behind it.
    #[test]
    fn a_moving_count_replaces_the_clause_rather_than_stacking() {
        let mut status = PlaybookPlanStatus {
            summary: Some("5/5 up-to-date".into()),
            ..Default::default()
        };

        for remaining in [3, 2, 1] {
            append_dependency_summary_clause(
                &mut status,
                &[dependency("workers-ci", "containerd", remaining)],
            );
        }

        assert_eq!(
            status.summary.as_deref(),
            Some("5/5 up-to-date (1 host(s) waiting for dependencies)")
        );
    }

    /// The provider finishes, and the clause has to go with the wait. Stripping is the only thing
    /// that removes it: an idle tick never rewrites the summary it was appended to.
    #[test]
    fn the_clause_disappears_when_the_last_wait_clears() {
        let mut status = PlaybookPlanStatus {
            summary: Some("5/5 up-to-date".into()),
            ..Default::default()
        };

        append_dependency_summary_clause(&mut status, &[dependency("workers-ci", "containerd", 3)]);
        append_dependency_summary_clause(&mut status, &[dependency("workers-ci", "containerd", 0)]);

        assert_eq!(status.summary.as_deref(), Some("5/5 up-to-date"));
    }

    /// A status written by a version that stacked them is healed on the first tick, not one clause
    /// per reconcile — an operator upgrade must not leave a plan reporting nonsense for as long as
    /// it takes to unwind.
    #[test]
    fn a_summary_that_already_stacked_clauses_is_healed_at_once() {
        let mut status = PlaybookPlanStatus {
            summary: Some(
                "5/5 up-to-date (3 host(s) waiting for dependencies) \
                 (3 host(s) waiting for dependencies) (3 host(s) waiting for dependencies)"
                    .into(),
            ),
            ..Default::default()
        };

        append_dependency_summary_clause(&mut status, &[dependency("workers-ci", "containerd", 3)]);

        assert_eq!(
            status.summary.as_deref(),
            Some("5/5 up-to-date (3 host(s) waiting for dependencies)")
        );
    }

    /// The clause is appended after `apply_run_diagnostic`'s, so stripping must stop at the
    /// dependency clause and leave a diagnostic that happens to sit in front of it alone.
    #[test]
    fn stripping_leaves_a_run_diagnostics_clause_in_place() {
        let mut status = PlaybookPlanStatus {
            summary: Some("1/5 up-to-date (the playbook ran no task on 2 of 5 hosts)".into()),
            ..Default::default()
        };

        append_dependency_summary_clause(&mut status, &[dependency("workers-ci", "containerd", 3)]);
        append_dependency_summary_clause(&mut status, &[dependency("workers-ci", "containerd", 3)]);

        assert_eq!(
            status.summary.as_deref(),
            Some(
                "1/5 up-to-date (the playbook ran no task on 2 of 5 hosts) \
                 (3 host(s) waiting for dependencies)"
            )
        );
    }

    /// The headline case: a dependent that has never run, because its inventory resolves no host
    /// until the provider reaches one, has no summary of its own. The clause stands alone, stays a
    /// fixed point, and goes again when the wait clears.
    #[test]
    fn a_plan_with_no_summary_gets_the_clause_alone() {
        let mut status = PlaybookPlanStatus::default();
        let waiting = [dependency("workers-ci", "containerd", 3)];

        for _ in 0..3 {
            append_dependency_summary_clause(&mut status, &waiting);
            assert_eq!(
                status.summary.as_deref(),
                Some("(3 host(s) waiting for dependencies)")
            );
        }

        append_dependency_summary_clause(&mut status, &[dependency("workers-ci", "containerd", 1)]);
        assert_eq!(
            status.summary.as_deref(),
            Some("(1 host(s) waiting for dependencies)")
        );

        append_dependency_summary_clause(&mut status, &[dependency("workers-ci", "containerd", 0)]);
        assert_eq!(status.summary, None);
    }

    /// Nothing to qualify: a plan whose dependencies are all met is simply doing what its summary
    /// says.
    #[test]
    fn a_satisfied_dependency_leaves_the_summary_alone() {
        let mut status = PlaybookPlanStatus {
            summary: Some("5/5 up-to-date".into()),
            ..Default::default()
        };

        append_dependency_summary_clause(&mut status, &[dependency("workers-ci", "containerd", 0)]);

        assert_eq!(status.summary.as_deref(), Some("5/5 up-to-date"));
    }

    /// A plan mid-run has a summary about that run, which is what someone watching it wants. The
    /// wait is still on the condition, and the clause comes back when the run ends.
    #[test]
    fn a_running_plan_keeps_its_summary_about_the_run() {
        let mut status = PlaybookPlanStatus {
            summary: Some("applying to 3 hosts".into()),
            active_run: Some(crate::v1beta1::ActiveRun {
                execution_hash: "abc".into(),
                run_id: "run".into(),
                job_name: "plan-1".into(),
                play_uid: "uid".into(),
                hosts: vec!["worker-1".into()],
                run_number: 1,
                attempt: 1,
                triggered_slot: None,
            }),
            ..Default::default()
        };

        append_dependency_summary_clause(&mut status, &[dependency("workers-ci", "containerd", 3)]);

        assert_eq!(status.summary.as_deref(), Some("applying to 3 hosts"));
    }

    /// No clause outlives the tick that wrote it, not even onto a summary this function will not add
    /// one to. Every path that starts a run replaces the summary with the run's own and would carry
    /// the clause off with it — but that is an invariant across several call sites, and a stale
    /// count on a running plan would also break the exact match in
    /// `summary_unclaimed_since_adoption`. So the strip does not depend on that invariant holding.
    #[test]
    fn a_run_starting_does_not_inherit_the_idle_plans_clause() {
        let mut status = PlaybookPlanStatus {
            summary: Some("5/5 up-to-date (3 host(s) waiting for dependencies)".into()),
            active_run: Some(crate::v1beta1::ActiveRun {
                execution_hash: "abc".into(),
                run_id: "run".into(),
                job_name: "plan-1".into(),
                play_uid: "uid".into(),
                hosts: vec!["worker-1".into()],
                run_number: 1,
                attempt: 1,
                triggered_slot: None,
            }),
            ..Default::default()
        };

        append_dependency_summary_clause(&mut status, &[dependency("workers-ci", "containerd", 3)]);

        assert_eq!(status.summary.as_deref(), Some("5/5 up-to-date"));
    }

    /// The version travels with the hash and the timestamp, under one condition, so the three can
    /// never describe different runs. A host that did not succeed keeps whatever it had: the label
    /// derived from it still says "this version was applied here at some point", which a later
    /// failure does not undo.
    #[test]
    fn only_a_succeeding_host_is_given_the_runs_version() {
        let mut status = PlaybookPlanStatus::default();
        let play_status = |outcome: HostOutcome| PlayStatus {
            phase: PlayPhase::Failed,
            host_count: 2,
            hosts: BTreeMap::from([
                (
                    "worker-1".into(),
                    crate::v1beta1::PlayHostResult {
                        outcome: HostOutcome::Succeeded,
                        ..Default::default()
                    },
                ),
                (
                    "worker-2".into(),
                    crate::v1beta1::PlayHostResult {
                        outcome,
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };

        apply_terminal_play_status(
            &hash(),
            Some("1.4.2"),
            &play_status(HostOutcome::Succeeded),
            &no_nodes(),
            &mut status,
        );
        let hosts = status.hosts_status.clone().unwrap();
        assert_eq!(hosts["worker-1"].applied_version.as_deref(), Some("1.4.2"));
        assert_eq!(hosts["worker-2"].applied_version.as_deref(), Some("1.4.2"));

        // The next revision succeeds on worker-1 only.
        apply_terminal_play_status(
            &hash(),
            Some("1.5.0"),
            &play_status(HostOutcome::Failed),
            &no_nodes(),
            &mut status,
        );
        let hosts = status.hosts_status.unwrap();
        assert_eq!(hosts["worker-1"].applied_version.as_deref(), Some("1.5.0"));
        assert_eq!(
            hosts["worker-2"].applied_version.as_deref(),
            Some("1.4.2"),
            "a failed host keeps the version it did apply, like its hash"
        );
    }

    /// A plan that declares nothing must leave the field absent rather than blank it to something —
    /// `node_labels` reads "no version" as "label nothing", and that is the fail-closed answer.
    #[test]
    fn a_run_that_provides_nothing_records_no_version() {
        let mut status = PlaybookPlanStatus::default();
        let play_status = PlayStatus {
            phase: PlayPhase::Succeeded,
            host_count: 1,
            hosts: BTreeMap::from([(
                "worker-1".into(),
                crate::v1beta1::PlayHostResult {
                    outcome: HostOutcome::Succeeded,
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        apply_terminal_play_status(&hash(), None, &play_status, &no_nodes(), &mut status);

        let hosts = status.hosts_status.unwrap();
        assert_eq!(hosts["worker-1"].applied_version, None);
        assert_ne!(
            hosts["worker-1"].last_applied_hash, "",
            "the host is still converged; it just provides nothing"
        );
    }

    #[test]
    fn recovered_terminal_play_replaces_running_conditions() {
        let h = hash();
        let mut status = PlaybookPlanStatus::default();
        set_running_condition(&mut status);
        let play_status = PlayStatus {
            phase: PlayPhase::Succeeded,
            host_count: 1,
            hosts: BTreeMap::from([(
                "host-1".into(),
                crate::v1beta1::PlayHostResult {
                    outcome: HostOutcome::Succeeded,
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        apply_terminal_play_status(&h, None, &play_status, &no_nodes(), &mut status);

        let running = status
            .conditions
            .iter()
            .find(|condition| condition.type_ == "Running")
            .unwrap();
        let ready = status
            .conditions
            .iter()
            .find(|condition| condition.type_ == "Ready")
            .unwrap();
        assert_eq!(running.status, "False");
        assert_eq!(ready.status, "True");
        assert_eq!(
            status.hosts_status.unwrap()["host-1"].last_applied_hash,
            h.to_string()
        );
    }

    /// Only a host that actually succeeded is stamped with the revision. `lastAppliedHash` is the
    /// sole input to `find_outdated_hosts`, so stamping a host that failed, was never reached, or
    /// whose result could not be recovered would declare it current and retire it from every future
    /// run of this revision — the plan would report the failure once and then never touch the host
    /// again. The outcome and the timestamp are recorded for all of them regardless, because those
    /// are what report the failure; it is only the revision claim that is withheld.
    #[test]
    fn only_a_succeeded_host_is_stamped_with_the_applied_revision() {
        let h = hash();
        let mut status = PlaybookPlanStatus {
            hosts_status: Some(BTreeMap::from([(
                "failed".into(),
                crate::v1beta1::HostStatus {
                    last_applied_hash: "previous-revision".into(),
                    last_outcome: HostOutcome::Succeeded,
                    ..Default::default()
                },
            )])),
            ..Default::default()
        };
        let result = |outcome: HostOutcome| crate::v1beta1::PlayHostResult {
            outcome,
            ..Default::default()
        };
        let play_status = PlayStatus {
            phase: PlayPhase::Failed,
            host_count: 4,
            hosts: BTreeMap::from([
                ("succeeded".into(), result(HostOutcome::Succeeded)),
                ("failed".into(), result(HostOutcome::Failed)),
                ("not-reached".into(), result(HostOutcome::NotReached)),
                ("unknown".into(), result(HostOutcome::Unknown)),
            ]),
            ..Default::default()
        };

        apply_terminal_play_status(&h, None, &play_status, &no_nodes(), &mut status);

        let hosts = status.hosts_status.unwrap();
        assert_eq!(hosts["succeeded"].last_applied_hash, h.to_string());
        assert_eq!(
            hosts["failed"].last_applied_hash, "previous-revision",
            "a failed host keeps the last revision it really applied"
        );
        assert_eq!(
            hosts["not-reached"].last_applied_hash, "",
            "a host Ansible never reached has applied nothing"
        );
        assert_eq!(
            hosts["unknown"].last_applied_hash, "",
            "an unrecoverable result is not evidence the revision landed"
        );
        for host in ["succeeded", "failed", "not-reached", "unknown"] {
            assert_eq!(
                hosts[host].last_outcome, play_status.hosts[host].outcome,
                "{host} must still report what happened to it"
            );
            assert!(hosts[host].last_transition_time.is_some(), "{host}");
        }
    }

    /// `appliedAt` and `appliedNodeUid` describe the *claim*, so they move with `lastAppliedHash`
    /// and with nothing else: a host that failed keeps the date and the machine of the revision it
    /// really applied, and one that has never succeeded has neither. The pairing is what lets a
    /// replaced machine be told apart from the one the record describes (`node_recreation`) — a uid
    /// that moved on a failure would make a rebuilt Node look like it had applied something.
    #[test]
    fn the_claim_is_dated_and_identified_with_the_revision_and_only_with_it() {
        let h = hash();
        let earlier = "2026-01-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::FixedOffset>>()
            .unwrap();
        let finished = "2026-03-04T05:06:07Z"
            .parse::<chrono::DateTime<chrono::FixedOffset>>()
            .unwrap();
        let mut status = PlaybookPlanStatus {
            hosts_status: Some(BTreeMap::from([(
                "failed".into(),
                crate::v1beta1::HostStatus {
                    last_applied_hash: "previous-revision".into(),
                    last_outcome: HostOutcome::Succeeded,
                    applied_at: Some(earlier),
                    applied_node_uid: Some("uid-failed-previous".into()),
                    ..Default::default()
                },
            )])),
            ..Default::default()
        };
        let result = |outcome: HostOutcome| crate::v1beta1::PlayHostResult {
            outcome,
            ..Default::default()
        };
        let play_status = PlayStatus {
            phase: PlayPhase::Failed,
            host_count: 4,
            finished_at: Some(finished),
            hosts: BTreeMap::from([
                ("succeeded".into(), result(HostOutcome::Succeeded)),
                ("no-node".into(), result(HostOutcome::Succeeded)),
                ("failed".into(), result(HostOutcome::Failed)),
                ("not-reached".into(), result(HostOutcome::NotReached)),
            ]),
            ..Default::default()
        };
        let nodes = nodes_with_uids(&[
            ("succeeded", "uid-succeeded"),
            ("failed", "uid-failed-now"),
            ("not-reached", "uid-not-reached"),
        ]);

        apply_terminal_play_status(&h, None, &play_status, &nodes, &mut status);

        let hosts = status.hosts_status.unwrap();
        assert_eq!(
            hosts["succeeded"].applied_at,
            Some(finished),
            "the run's own finish time, so a replayed recovery dates the claim when it happened"
        );
        assert_eq!(
            hosts["succeeded"].applied_node_uid.as_deref(),
            Some("uid-succeeded")
        );
        assert_eq!(
            hosts["no-node"].applied_node_uid, None,
            "a host with no Node in the cache records no machine, which is never a replacement"
        );
        assert_eq!(
            hosts["failed"].applied_at,
            Some(earlier),
            "a failure leaves the date of the revision the host really applied"
        );
        assert_eq!(
            hosts["failed"].applied_node_uid.as_deref(),
            Some("uid-failed-previous"),
            "and the machine it applied it to"
        );
        assert_eq!(
            hosts["not-reached"].applied_at, None,
            "a host that never succeeded has no claim to date"
        );
        assert_eq!(hosts["not-reached"].applied_node_uid, None);
    }

    #[test]
    fn blocked_condition_names_the_holder_then_clears_in_place() {
        let mut status = PlaybookPlanStatus::default();

        set_blocked_condition(
            &mut status,
            Some(&BlockedBy {
                host: "homelab-ctrl-0".into(),
                holder: Some("default/oneshot-fail/87882ca3".into()),
            }),
        );
        let blocked = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Blocked")
            .unwrap();
        assert_eq!(blocked.status, "True");
        assert_eq!(blocked.reason.as_deref(), Some("HostLockHeld"));
        let message = blocked.message.as_deref().unwrap();
        assert!(message.contains("homelab-ctrl-0"), "{message}");
        assert!(
            message.contains("default/oneshot-fail/87882ca3"),
            "{message}"
        );

        set_blocked_condition(&mut status, None);
        assert_eq!(
            status
                .conditions
                .iter()
                .filter(|c| c.type_ == "Blocked")
                .count(),
            1,
            "upsert must replace the condition in place, not append a second one"
        );
        let cleared = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Blocked")
            .unwrap();
        assert_eq!(cleared.status, "False");
    }

    #[test]
    fn blocked_condition_falls_back_when_holder_unknown() {
        let mut status = PlaybookPlanStatus::default();
        set_blocked_condition(
            &mut status,
            Some(&BlockedBy {
                host: "homelab-worker-0".into(),
                holder: None,
            }),
        );
        let message = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Blocked")
            .unwrap()
            .message
            .clone()
            .unwrap();
        assert!(message.contains("another run"), "{message}");
    }

    #[test]
    fn waiting_for_nodes_condition_names_hosts_then_clears_in_place() {
        let mut status = PlaybookPlanStatus::default();

        let hosts = ["worker-1".to_string(), "worker-2".to_string()];
        set_waiting_for_nodes_condition(&mut status, Some(WaitingForNodes::ProxyPods(&hosts)));
        let waiting = status
            .conditions
            .iter()
            .find(|c| c.type_ == "WaitingForNodes")
            .unwrap();
        assert_eq!(waiting.status, "True");
        assert_eq!(waiting.reason.as_deref(), Some("ProxyPodsNotReady"));
        let message = waiting.message.as_deref().unwrap();
        assert!(message.contains("worker-1"), "{message}");
        assert!(message.contains("worker-2"), "{message}");

        // The other wait shares the condition but must be tellable apart by its reason: one happens
        // inside a run, the other instead of starting one.
        set_waiting_for_nodes_condition(&mut status, Some(WaitingForNodes::NodesNotReady(&hosts)));
        let waiting = status
            .conditions
            .iter()
            .find(|c| c.type_ == "WaitingForNodes")
            .unwrap();
        assert_eq!(waiting.status, "True");
        assert_eq!(waiting.reason.as_deref(), Some("NodesNotReady"));
        assert!(waiting.message.as_deref().unwrap().contains("worker-1"));

        set_waiting_for_nodes_condition(&mut status, None);
        assert_eq!(
            status
                .conditions
                .iter()
                .filter(|c| c.type_ == "WaitingForNodes")
                .count(),
            1,
            "upsert must replace the condition in place, not append a second one"
        );
        let cleared = status
            .conditions
            .iter()
            .find(|c| c.type_ == "WaitingForNodes")
            .unwrap();
        assert_eq!(cleared.status, "False");
    }

    /// The predicate and the writer have to agree on the same two strings, and nothing but a test
    /// makes them: a typo in either would silently turn the hold into "no hold", which reads as a
    /// working plan and re-enables the clear the guard exists to prevent.
    #[test]
    fn only_the_nodes_not_ready_hold_answers_the_hold_predicate() {
        let mut status = PlaybookPlanStatus::default();
        let hosts = ["worker-1".to_string()];

        assert!(!held_for_unready_nodes(&status), "no condition, no hold");

        set_waiting_for_nodes_condition(&mut status, Some(WaitingForNodes::ProxyPods(&hosts)));
        assert!(
            !held_for_unready_nodes(&status),
            "a run waiting on its proxy pods is not a plan held from starting one"
        );

        set_waiting_for_nodes_condition(&mut status, Some(WaitingForNodes::NodesNotReady(&hosts)));
        assert!(held_for_unready_nodes(&status));

        set_waiting_for_nodes_condition(&mut status, None);
        assert!(!held_for_unready_nodes(&status));
    }

    /// Why the caller has to ask before clearing. Re-stating the same wait is free — the condition
    /// is byte-identical, so the plan's status write is a no-op — but a round trip through `False`
    /// is not: it restamps `lastTransitionTime`, and a status that differs only in a timestamp is
    /// still a write, a `resourceVersion` bump and another reconcile, once per tick for the whole
    /// length of the wait.
    #[test]
    fn a_round_trip_through_cleared_restamps_a_wait_that_did_not_change() {
        let mut status = PlaybookPlanStatus::default();
        let hosts = ["worker-1".to_string()];

        set_waiting_for_nodes_condition(&mut status, Some(WaitingForNodes::ProxyPods(&hosts)));
        // Backdated so "kept" and "restamped" are distinguishable however coarse the clock is.
        let started = "2025-08-12T20:00:00Z"
            .parse::<chrono::DateTime<chrono::FixedOffset>>()
            .unwrap();
        status.conditions[0].last_transition_time = Some(started);

        set_waiting_for_nodes_condition(&mut status, Some(WaitingForNodes::ProxyPods(&hosts)));
        assert_eq!(
            status.conditions[0].last_transition_time,
            Some(started),
            "the same wait, re-stated, is the same wait"
        );

        set_waiting_for_nodes_condition(&mut status, None);
        set_waiting_for_nodes_condition(&mut status, Some(WaitingForNodes::ProxyPods(&hosts)));
        assert_ne!(
            status.conditions[0].last_transition_time,
            Some(started),
            "clearing and re-asserting loses when the wait began"
        );
    }

    /// A run whose recap could not be read is still reported through its terminal `Play`, not
    /// through a second condition path — `Unknown` is what carries "the Job ran, the result is
    /// lost" all the way to the plan.
    #[test]
    fn ready_condition_false_when_the_recap_is_unavailable() {
        let mut status = PlaybookPlanStatus::default();
        let play_status = PlayStatus {
            phase: PlayPhase::Unknown,
            host_count: 1,
            hosts: BTreeMap::from([(
                "host-1".into(),
                crate::v1beta1::PlayHostResult {
                    outcome: HostOutcome::Unknown,
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        apply_terminal_play_status(&hash(), None, &play_status, &no_nodes(), &mut status);

        let ready = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Ready")
            .unwrap();
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason.as_deref(), Some("RecapUnavailable"));
    }

    /// A new run flips `Running` in place and leaves the previous run's `Ready` verdict exactly
    /// as it was. `Ready` is a printer column that nothing else rewrites between runs, so blanking
    /// or restating it at the start of a run would replace the last known state of the hosts with
    /// "unknown" for the whole of that run — and a restated one would also move
    /// `lastTransitionTime` for a verdict that did not transition.
    #[test]
    fn set_running_condition_marks_the_plan_as_running() {
        let mut status = PlaybookPlanStatus::default();
        apply_terminal_play_status(
            &hash(),
            None,
            &PlayStatus {
                phase: PlayPhase::Succeeded,
                host_count: 1,
                hosts: BTreeMap::from([(
                    "host-1".into(),
                    crate::v1beta1::PlayHostResult {
                        outcome: HostOutcome::Succeeded,
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            },
            &no_nodes(),
            &mut status,
        );
        let ready_before = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Ready")
            .cloned()
            .expect("a finished run leaves a Ready verdict behind");

        set_running_condition(&mut status);

        let running = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Running")
            .unwrap();
        assert_eq!(running.status, "True");
        assert_eq!(
            status
                .conditions
                .iter()
                .filter(|c| c.type_ == "Running")
                .count(),
            1,
            "the previous run's Running=False must be replaced in place, not appended to"
        );

        let ready_after = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Ready")
            .expect("Ready shouldn't be withdrawn while the job is still running");
        assert_eq!(ready_after.status, ready_before.status);
        assert_eq!(ready_after.reason, ready_before.reason);
        assert_eq!(ready_after.message, ready_before.message);
        assert_eq!(
            ready_after.last_transition_time, ready_before.last_transition_time,
            "Ready shouldn't be re-evaluated while the job is still running"
        );
    }

    /// A run whose Job is replaced under its name after an earlier tick already saw the genuine one
    /// must not keep advertising that Job as active: the contested name is never abandoned, so the
    /// contradiction would otherwise stand for as long as the foreign Job survives.
    #[test]
    fn a_contested_job_name_withdraws_a_running_claim_made_earlier() {
        let mut status = PlaybookPlanStatus::default();
        set_running_condition(&mut status);

        set_job_identity_mismatch_condition(&mut status, "plan-abc123-1");

        let running = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Running")
            .unwrap();
        assert_eq!(running.status, "False");
        assert_eq!(running.reason.as_deref(), Some("JobIdentityMismatch"));
        assert!(
            running
                .message
                .as_deref()
                .is_some_and(|message| message.contains("plan-abc123-1"))
        );
    }

    /// A run being stopped because its record is gone must stop advertising itself as running, and
    /// must keep saying so without re-dating the claim: the cancellation is polled every few
    /// seconds, and `lastTransitionTime` is what a reader ages a stuck teardown by. Once the run is
    /// finalized, its terminal result retires the condition like any other run's.
    #[test]
    fn a_lost_record_withdraws_a_running_claim_until_the_run_is_finalized() {
        let mut status = PlaybookPlanStatus::default();
        set_running_condition(&mut status);

        set_run_record_lost_condition(&mut status, "plan-abc123-1");
        let first = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Running")
            .unwrap()
            .clone();
        assert_eq!(first.status, "False");
        assert_eq!(first.reason.as_deref(), Some("RunRecordLost"));
        assert!(
            first
                .message
                .as_deref()
                .is_some_and(|message| message.contains("plan-abc123-1"))
        );

        set_run_record_lost_condition(&mut status, "plan-abc123-1");
        let second = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Running")
            .unwrap();
        assert_eq!(second.last_transition_time, first.last_transition_time);
        assert_eq!(
            status
                .conditions
                .iter()
                .filter(|c| c.type_ == "Running")
                .count(),
            1
        );

        apply_terminal_play_status(
            &hash(),
            None,
            &PlayStatus {
                phase: PlayPhase::Unknown,
                host_count: 1,
                hosts: BTreeMap::from([(
                    "host-1".into(),
                    crate::v1beta1::PlayHostResult {
                        outcome: HostOutcome::Unknown,
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            },
            &no_nodes(),
            &mut status,
        );
        let finalized = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Running")
            .unwrap();
        assert_eq!(finalized.status, "False");
        assert_eq!(finalized.reason, None);
    }

    /// A second, *different* outage under the same reason has to replace the message. The summary is
    /// written from the same failure, so a condition that kept the first one would sit next to a
    /// summary naming a different failure — and the reader has no way to tell which is current.
    /// `lastTransitionTime` must not move for it: the status never changed, and it is what a reader
    /// ages a stuck condition by.
    #[test]
    fn a_persisting_input_outage_reports_the_current_read_failure() {
        let mut status = PlaybookPlanStatus::default();

        set_inputs_unavailable_condition(
            &mut status,
            "cannot resolve the plan's inventories: Referenced ClusterInventory \"nodes\" does not exist",
        );
        let first = status
            .conditions
            .iter()
            .find(|condition| condition.type_ == "Ready")
            .unwrap()
            .clone();

        set_inputs_unavailable_condition(
            &mut status,
            "cannot read referenced Secrets: Referenced Secret \"vars\" does not exist",
        );
        let second = status
            .conditions
            .iter()
            .find(|condition| condition.type_ == "Ready")
            .unwrap();

        assert_eq!(
            status
                .conditions
                .iter()
                .filter(|condition| condition.type_ == "Ready")
                .count(),
            1,
            "the condition is replaced in place, never appended twice"
        );
        assert!(
            second
                .message
                .as_deref()
                .is_some_and(|message| message.contains("vars")),
            "the message must name the read that is failing now, not the first one: {:?}",
            second.message
        );
        assert_eq!(
            second.last_transition_time, first.last_transition_time,
            "the status did not change, so this is not a transition"
        );
    }

    fn plan_with_results(hosts: &[(&str, HostOutcome)], applied: &str) -> PlaybookPlanStatus {
        PlaybookPlanStatus {
            eligible_hosts: vec![crate::v1beta1::ResolvedHosts {
                name: "workers".into(),
                hosts: hosts.iter().map(|(host, _)| (*host).into()).collect(),
            }],
            hosts_status: Some(
                hosts
                    .iter()
                    .map(|(host, outcome)| {
                        (
                            (*host).to_string(),
                            crate::v1beta1::HostStatus {
                                last_applied_hash: match outcome {
                                    HostOutcome::Succeeded => applied.to_string(),
                                    _ => String::new(),
                                },
                                last_outcome: outcome.clone(),
                                ..Default::default()
                            },
                        )
                    })
                    .collect(),
            ),
            ..Default::default()
        }
    }

    /// The overlay is retired for every mode, not only the one whose phase can also be restored: a
    /// `Recurring` plan between slots has no terminal `Play` to rewrite `Ready` for it.
    #[test]
    fn recovered_inputs_restate_the_verdict_from_recorded_results() {
        let mut status = plan_with_results(&[("worker-1", HostOutcome::Succeeded)], "1");
        set_inputs_unavailable_condition(&mut status, "cannot read referenced Secrets: nope");

        assert!(clear_inputs_unavailable_condition(&mut status, 0));

        let ready = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Ready")
            .unwrap();
        assert_eq!(ready.status, "True");
        assert_eq!(ready.reason.as_deref(), Some("HostsUpToDate"));
        assert_eq!(
            ready.message.as_deref(),
            Some("1/1 hosts on the current revision")
        );
    }

    /// The restatement counts every host the plan is responsible for, while a terminal `Play` counts
    /// the ones one run targeted. They are said in different words for that reason: sharing them let
    /// the same condition change its numbers on a tick where nothing ran.
    #[test]
    fn a_restated_verdict_is_not_worded_as_a_run_result() {
        // A OneShot plan with four hosts whose last run applied only the two that were outdated,
        // and failed one of them.
        let mut status = plan_with_results(
            &[
                ("worker-1", HostOutcome::Succeeded),
                ("worker-2", HostOutcome::Succeeded),
                ("worker-3", HostOutcome::Succeeded),
                ("worker-4", HostOutcome::Failed),
            ],
            "1",
        );
        apply_terminal_play_status(
            &hash(),
            None,
            &PlayStatus {
                phase: PlayPhase::Failed,
                host_count: 2,
                hosts: BTreeMap::from([
                    (
                        "worker-3".into(),
                        crate::v1beta1::PlayHostResult {
                            outcome: HostOutcome::Succeeded,
                            ..Default::default()
                        },
                    ),
                    (
                        "worker-4".into(),
                        crate::v1beta1::PlayHostResult {
                            outcome: HostOutcome::Failed,
                            ..Default::default()
                        },
                    ),
                ]),
                ..Default::default()
            },
            &no_nodes(),
            &mut status,
        );
        let ran = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Ready")
            .unwrap()
            .clone();
        assert_eq!(ran.reason.as_deref(), Some("SomeHostsDidNotSucceed"));
        assert_eq!(
            ran.message.as_deref(),
            Some("1/2 hosts completed successfully"),
            "a run reports the hosts it targeted"
        );

        // An input outage and its recovery, with nothing having run in between.
        set_inputs_unavailable_condition(&mut status, "cannot read referenced Secrets: nope");
        clear_inputs_unavailable_condition(&mut status, 1);

        let restated = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Ready")
            .unwrap();
        assert_eq!(restated.reason.as_deref(), Some("HostsOutdated"));
        assert_eq!(
            restated.message.as_deref(),
            Some("3/4 hosts on the current revision"),
            "the restatement covers the whole plan and must not claim anything completed"
        );
    }

    /// Recovering the inputs says nothing about the hosts: one that is not at this revision leaves
    /// the plan not ready, for the reason that is actually true of it.
    #[test]
    fn recovered_inputs_do_not_claim_success_for_outdated_hosts() {
        let mut status = plan_with_results(
            &[
                ("worker-1", HostOutcome::Succeeded),
                ("worker-2", HostOutcome::Failed),
            ],
            "1",
        );
        set_inputs_unavailable_condition(
            &mut status,
            "cannot resolve the plan's inventories: nope",
        );

        clear_inputs_unavailable_condition(&mut status, 1);

        let ready = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Ready")
            .unwrap();
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason.as_deref(), Some("HostsOutdated"));
        assert_eq!(
            ready.message.as_deref(),
            Some("1/2 hosts on the current revision")
        );
    }

    /// A plan that never ran carried no `Ready` at all before the outage, so it gets none back —
    /// inventing `True` would advertise a success that never happened, and leaving `False` standing
    /// is the stale overlay this clears.
    #[test]
    fn recovered_inputs_leave_a_plan_that_never_ran_without_a_verdict() {
        let mut status = PlaybookPlanStatus::default();
        set_inputs_unavailable_condition(
            &mut status,
            "cannot resolve the plan's inventories: nope",
        );

        assert!(clear_inputs_unavailable_condition(&mut status, 0));

        assert!(status.conditions.iter().all(|c| c.type_ != "Ready"));
    }

    /// Only the overlay is retired. A verdict a terminal `Play` wrote earlier in the same tick is
    /// the real one and must survive.
    #[test]
    fn recovered_inputs_do_not_overwrite_a_real_verdict() {
        let mut status = PlaybookPlanStatus::default();
        let play_status = PlayStatus {
            phase: PlayPhase::Failed,
            host_count: 2,
            hosts: BTreeMap::from([(
                "worker-1".into(),
                crate::v1beta1::PlayHostResult {
                    outcome: HostOutcome::Failed,
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        apply_terminal_play_status(&hash(), None, &play_status, &no_nodes(), &mut status);

        assert!(!clear_inputs_unavailable_condition(&mut status, 0));

        let ready = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Ready")
            .unwrap();
        assert_eq!(ready.reason.as_deref(), Some("SomeHostsDidNotSucceed"));
        assert_eq!(
            ready.message.as_deref(),
            Some("0/2 hosts completed successfully")
        );
    }
}
