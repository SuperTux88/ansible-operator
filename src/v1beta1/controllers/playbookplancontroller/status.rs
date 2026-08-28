use k8s_openapi::api::batch;

use crate::{
    utils::upsert_condition,
    v1beta1::{HostOutcome, PlayPhase, PlayStatus, PlaybookPlanCondition, PlaybookPlanStatus},
};

use super::{
    execution_evaluator::{ExecutionHash, distinct_host_count},
    locking::BlockedBy,
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

    clear_run_conditions(status);
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

/// Marks the plan as not ready because one of its desired inputs could not be read. The message is
/// the same diagnostic shown in the plan summary.
pub fn set_inputs_unavailable_condition(status: &mut PlaybookPlanStatus, message: &str) {
    upsert_condition(
        &mut status.conditions,
        PlaybookPlanCondition {
            type_: "Ready".into(),
            status: "False".into(),
            reason: Some("InputsUnavailable".into()),
            message: Some(message.into()),
            last_transition_time: Some(chrono::Local::now().fixed_offset()),
        },
    );
}

/// Retires the [`set_inputs_unavailable_condition`] overlay once the desired inputs read cleanly
/// again, restating `Ready` from the plan's own per-host results.
///
/// Needed for every mode, not only the one that can also restore a phase: `Ready` is a printer
/// column, and nothing else rewrites it between runs. A `Recurring` plan would advertise a resolved
/// outage until its next slot completed, which for a daily schedule is a day of a false negative.
///
/// The results are the ones [`apply_terminal_play_status`] already folded into the plan: a host is
/// current exactly when its last run succeeded at this revision, which is what `outdated_count`
/// counts the complement of. A plan that has never run has no verdict to restate — and carried no
/// `Ready` condition before the outage — so it gets none back rather than an invented one.
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
pub fn clear_inputs_unavailable_condition(status: &mut PlaybookPlanStatus, outdated_count: usize) {
    let overlaid = status.conditions.iter().any(|condition| {
        condition.type_ == "Ready" && condition.reason.as_deref() == Some("InputsUnavailable")
    });
    if !overlaid {
        return;
    }

    if status.hosts_status.is_none() {
        status
            .conditions
            .retain(|condition| condition.type_ != "Ready");
        return;
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

        apply_terminal_play_status(&h, &play_status, &mut status);

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

    /// A second, *different* outage under the same reason has to replace the message. The summary is
    /// written from the same diagnostic, so a condition that kept the first one would sit next to a
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

        clear_inputs_unavailable_condition(&mut status, 0);

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

        clear_inputs_unavailable_condition(&mut status, 0);

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
        apply_terminal_play_status(&hash(), &play_status, &mut status);

        clear_inputs_unavailable_condition(&mut status, 0);

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
