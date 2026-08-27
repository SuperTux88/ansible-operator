use std::collections::BTreeMap;

use k8s_openapi::api::batch;

use crate::{
    utils::upsert_condition,
    v1beta1::{HostOutcome, PlaybookPlanCondition, PlaybookPlanStatus},
};

use super::{
    callback_output::CallbackOutput, execution_evaluator::ExecutionHash, locking::BlockedBy,
};

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

/// Updates `hosts_status` for every host targeted this run, from the parsed callback output (or
/// `Unknown` for all of them if it couldn't be parsed). Only `Succeeded` outcomes bump
/// `last_applied_hash`, which is what `find_outdated_hosts` reads for retry/idempotency.
pub fn evaluate_host_outcomes(
    target_hosts: &[String],
    parsed: Option<&CallbackOutput>,
    hash: &ExecutionHash,
    status: &mut PlaybookPlanStatus,
) {
    let hosts_status = status.hosts_status.get_or_insert_with(BTreeMap::new);
    let now = chrono::Local::now().fixed_offset();

    for host in target_hosts {
        let outcome = match parsed {
            None => HostOutcome::Unknown,
            Some(output) => match output.processed.get(host) {
                None => HostOutcome::NotReached,
                Some(stats) if stats.is_failure() => HostOutcome::Failed,
                Some(_) => HostOutcome::Succeeded,
            },
        };

        let entry = hosts_status.entry(host.clone()).or_default();

        if outcome == HostOutcome::Succeeded {
            entry.last_applied_hash = hash.to_string();
        }

        entry.last_outcome = outcome;
        entry.last_transition_time = Some(now);
    }
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

/// Recomputes the plan-level `Running`/`Ready` conditions from this run's host-outcome tally,
/// using the parsed callback output as the only host-level signal (there's exactly one Job per
/// run now, so there's nothing to count across Jobs).
pub fn evaluate_playbookplan_conditions(
    target_hosts: &[String],
    job_is_finished: bool,
    parsed: Option<&CallbackOutput>,
    status: &mut PlaybookPlanStatus,
) {
    let now = chrono::Local::now().fixed_offset();

    let running_condition = if !job_is_finished {
        PlaybookPlanCondition {
            type_: "Running".into(),
            status: "True".into(),
            reason: Some("JobRunning".into()),
            message: Some("the run's Job is still active".into()),
            last_transition_time: Some(now),
        }
    } else {
        PlaybookPlanCondition {
            type_: "Running".into(),
            status: "False".into(),
            reason: None,
            message: None,
            last_transition_time: Some(now),
        }
    };

    upsert_condition(&mut status.conditions, running_condition);

    if !job_is_finished {
        return;
    }

    let ready_condition = match parsed {
        None => PlaybookPlanCondition {
            type_: "Ready".into(),
            status: "False".into(),
            reason: Some("RecapUnavailable".into()),
            message: Some(
                "the operator could not parse per-host results for this run's Job logs".into(),
            ),
            last_transition_time: Some(now),
        },
        Some(output) => {
            let total = target_hosts.len();
            let succeeded = target_hosts
                .iter()
                .filter(|host| {
                    output
                        .processed
                        .get(*host)
                        .map(|stats| !stats.is_failure())
                        .unwrap_or(false)
                })
                .count();

            if total > 0 && succeeded == total {
                PlaybookPlanCondition {
                    type_: "Ready".into(),
                    status: "True".into(),
                    reason: Some("AllHostsSucceeded".into()),
                    message: Some(format!("{succeeded}/{total} hosts completed successfully")),
                    last_transition_time: Some(now),
                }
            } else {
                PlaybookPlanCondition {
                    type_: "Ready".into(),
                    status: "False".into(),
                    reason: Some("SomeHostsDidNotSucceed".into()),
                    message: Some(format!("{succeeded}/{total} hosts completed successfully")),
                    last_transition_time: Some(now),
                }
            }
        }
    };

    upsert_condition(&mut status.conditions, ready_condition);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1beta1::controllers::playbookplancontroller::callback_output::HostStats;

    fn hash() -> ExecutionHash {
        crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash(
            "playbook",
            std::iter::empty(),
        )
    }

    #[test]
    fn succeeded_host_bumps_hash_others_do_not() {
        let mut status = PlaybookPlanStatus::default();
        let mut processed = BTreeMap::new();
        processed.insert(
            "host-1".to_string(),
            HostStats {
                ok: 1,
                ..Default::default()
            },
        );
        processed.insert(
            "host-2".to_string(),
            HostStats {
                failed: 1,
                ..Default::default()
            },
        );
        let output = CallbackOutput { processed };
        let h = hash();

        evaluate_host_outcomes(
            &[
                "host-1".to_string(),
                "host-2".to_string(),
                "host-3".to_string(),
            ],
            Some(&output),
            &h,
            &mut status,
        );

        let hosts_status = status.hosts_status.unwrap();
        assert_eq!(hosts_status["host-1"].last_outcome, HostOutcome::Succeeded);
        assert_eq!(hosts_status["host-1"].last_applied_hash, h.to_string());

        assert_eq!(hosts_status["host-2"].last_outcome, HostOutcome::Failed);
        assert_eq!(hosts_status["host-2"].last_applied_hash, "");

        assert_eq!(hosts_status["host-3"].last_outcome, HostOutcome::NotReached);
        assert_eq!(hosts_status["host-3"].last_applied_hash, "");
    }

    #[test]
    fn missing_callback_output_marks_everything_unknown() {
        let mut status = PlaybookPlanStatus::default();
        let h = hash();

        evaluate_host_outcomes(&["host-1".to_string()], None, &h, &mut status);

        let hosts_status = status.hosts_status.unwrap();
        assert_eq!(hosts_status["host-1"].last_outcome, HostOutcome::Unknown);
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

    #[test]
    fn ready_condition_false_when_callback_output_missing() {
        let mut status = PlaybookPlanStatus::default();
        evaluate_playbookplan_conditions(&["host-1".to_string()], true, None, &mut status);

        let ready = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Ready")
            .unwrap();
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason.as_deref(), Some("RecapUnavailable"));
    }

    #[test]
    fn running_condition_true_while_job_not_finished() {
        let mut status = PlaybookPlanStatus::default();
        evaluate_playbookplan_conditions(&["host-1".to_string()], false, None, &mut status);

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
