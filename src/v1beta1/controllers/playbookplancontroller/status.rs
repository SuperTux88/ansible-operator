use k8s_openapi::api::batch;

use crate::{
    utils::upsert_condition,
    v1beta1::{HostOutcome, PlayPhase, PlayStatus, PlaybookPlanCondition, PlaybookPlanStatus},
};

use super::{execution_evaluator::ExecutionHash, locking::BlockedBy};

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
pub fn apply_terminal_play_status(
    execution_hash: &ExecutionHash,
    play_status: &PlayStatus,
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

    clear_attempt_conditions(status);
    let hosts_status = status.hosts_status.get_or_insert_default();
    for (host, result) in &play_status.hosts {
        let entry = hosts_status.entry(host.clone()).or_default();
        if result.outcome == HostOutcome::Succeeded {
            entry.last_applied_hash = execution_hash.to_string();
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

/// Sets the plan-level `Blocked` condition, which reports whether this run is currently waiting on
/// a per-host lock held by another run (locks are global per node — see `locking::ensure_locks`).
/// `Some(blocked)` sets it `True` with the offending host and, when known, the holding run named in
/// the message; `None` — the run holds (or could take) all its locks — sets it `False`. The `phase`
/// stays whatever it was (typically `Scheduled`): being blocked is an orthogonal, transient overlay
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

/// Sets the plan-level `WaitingForNodes` condition, reporting whether this run is currently waiting
/// for managed-ssh proxy pods to become Ready on one or more target nodes (a node may be `NotReady`
/// or its proxy pod still starting). `Some(hosts)` sets it `True` naming the pending hosts; `None` —
/// the proxies are all Ready, or timed out and the run is proceeding — sets it `False`. Like
/// `Blocked`, this is an orthogonal transient overlay on the plan's lifecycle, not a phase of its own,
/// so a condition models it better than a phase would.
pub fn set_waiting_for_nodes_condition(
    status: &mut PlaybookPlanStatus,
    waiting: Option<&[String]>,
) {
    let now = chrono::Local::now().fixed_offset();

    let condition = match waiting {
        Some(hosts) => PlaybookPlanCondition {
            type_: "WaitingForNodes".into(),
            status: "True".into(),
            reason: Some("ProxyPodsNotReady".into()),
            message: Some(format!(
                "waiting for managed-ssh proxy pods on host(s): {}",
                hosts.join(", ")
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

pub fn clear_attempt_conditions(status: &mut PlaybookPlanStatus) {
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
            message: Some("the run's Job is still active".into()),
            last_transition_time: Some(chrono::Local::now().fixed_offset()),
        },
    );
}

/// Withdraws `Running` while the run's Job name is held by something that failed the identity check.
///
/// An earlier tick may have seen this run's own Job and set `Running` from it; leaving that standing
/// would seat `JobRunning`/"the run's Job is still active" beside a summary saying the opposite, for
/// as long as the contested name survives — which, since such a name is never abandoned, can be
/// indefinitely.
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
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn hash() -> ExecutionHash {
        crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash(
            "playbook",
            std::iter::empty(),
        )
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

        apply_terminal_play_status(&h, &play_status, &mut status);

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

        set_waiting_for_nodes_condition(
            &mut status,
            Some(&["worker-1".to_string(), "worker-2".to_string()]),
        );
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

        apply_terminal_play_status(&hash(), &play_status, &mut status);

        let ready = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Ready")
            .unwrap();
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason.as_deref(), Some("RecapUnavailable"));
    }

    #[test]
    fn set_running_condition_marks_the_plan_as_running() {
        let mut status = PlaybookPlanStatus::default();
        set_running_condition(&mut status);

        let running = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Running")
            .unwrap();
        assert_eq!(running.status, "True");
        assert!(
            status.conditions.iter().all(|c| c.type_ != "Ready"),
            "Ready shouldn't be evaluated while the job is still running"
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
}
