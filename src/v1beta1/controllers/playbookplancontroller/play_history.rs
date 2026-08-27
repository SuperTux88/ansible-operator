//! Writes and prunes `Play` history records. A `Play` is a durable, per-attempt receipt of one
//! ansible execution (1:1 with its backing Job) so a run's Ansible recap survives the Job/pod's
//! short TTL and shows up in `kubectl get plays`. The operator only *writes* these — nothing
//! reconciles a `Play` into further cluster state — so this lives beside the reconciler rather than
//! being its own controller. Retention is bounded per plan by the success/failure history limits.

use std::collections::BTreeMap;

use kube::{
    Api,
    api::{DeleteParams, ListParams, Patch, PatchParams, PostParams},
};
use tracing::debug;

use crate::v1beta1::{
    HostOutcome, Play, PlayHostResult, PlayPhase, PlayRecap, PlaySpec, PlayStatus, PlaybookPlan,
    ResolvedHosts,
    controllers::reconcile_error::{ReconcileError, is_conflict, is_not_found},
    labels,
    playbookplancontroller::{
        callback_output::{CallbackOutput, HostStats},
        execution_evaluator::ExecutionHash,
        reconciler::playbookplan_owner_ref,
    },
};

/// Default retention when a plan doesn't set `spec.successfulPlaysHistoryLimit`.
pub const DEFAULT_SUCCESSFUL_PLAYS_HISTORY_LIMIT: u32 = 3;
/// Default retention when a plan doesn't set `spec.failedPlaysHistoryLimit`.
pub const DEFAULT_FAILED_PLAYS_HISTORY_LIMIT: u32 = 10;

const FIELD_MANAGER: &str = "ansible-operator";

/// Identifies one run attempt for the history calls: the plan it belongs to, the backing Job's name
/// (which is also the Play's name), the execution hash, the attempt/retry number, the inventory it
/// targeted (grouped, for the Play spec), and the flat host list (for per-host status).
pub struct PlayRef<'a> {
    pub plan: &'a PlaybookPlan,
    pub job_name: &'a str,
    pub hash: &'a ExecutionHash,
    pub attempt: u32,
    pub inventory: &'a [ResolvedHosts],
    pub hosts: &'a [String],
}

/// Records that a run has started: creates the `Play` (phase `Running`) if it doesn't exist yet,
/// named after the backing Job so the two correlate 1:1 without a separate mapping. A no-op if the
/// Play already exists, so it never reverts a terminal Play back to `Running` (e.g. when the same
/// Job is re-adopted on a later tick).
pub async fn record_running(
    client: &kube::Client,
    namespace: &str,
    play: &PlayRef<'_>,
) -> Result<(), ReconcileError> {
    let api = Api::<Play>::namespaced(client.clone(), namespace);

    if api.get_opt(play.job_name).await?.is_some() {
        return Ok(());
    }

    let object = build_play(play)?;
    match api.create(&post_params(), &object).await {
        Ok(_) => {}
        // Created concurrently by another tick — leave whatever status it already has.
        Err(err) if is_conflict(&err) => return Ok(()),
        Err(err) => return Err(err.into()),
    }

    // A status subresource is not persisted by `create`; set the initial status separately.
    let status = PlayStatus {
        phase: PlayPhase::Running,
        job_name: Some(play.job_name.to_string()),
        host_count: play.hosts.len() as u32,
        ..Default::default()
    };
    patch_status(&api, play.job_name, &status).await
}

/// Stamps the terminal outcome (phase, recap totals, per-host results, finish time) onto the run's
/// `Play`. Reconstructs the Play first if it's missing — the `Running` record can be lost if the
/// operator restarted mid-run — so a finished run always leaves a record.
pub async fn record_finished(
    client: &kube::Client,
    namespace: &str,
    play: &PlayRef<'_>,
    parsed: Option<&CallbackOutput>,
) -> Result<(), ReconcileError> {
    let api = Api::<Play>::namespaced(client.clone(), namespace);

    if api.get_opt(play.job_name).await?.is_none() {
        let object = build_play(play)?;
        match api.create(&post_params(), &object).await {
            Ok(_) => {}
            Err(err) if is_conflict(&err) => {}
            Err(err) => return Err(err.into()),
        }
    }

    let status = terminal_status(play.job_name, play.hosts, parsed);
    patch_status(&api, play.job_name, &status).await
}

/// Deletes the oldest `Play`s for `plan` beyond its success/failure history limits.
pub async fn prune(
    client: &kube::Client,
    namespace: &str,
    plan: &PlaybookPlan,
) -> Result<(), ReconcileError> {
    use kube::runtime::reflector::Lookup as _;

    let plan_name = plan
        .name()
        .ok_or(ReconcileError::PreconditionFailed("name not set"))?;

    let api = Api::<Play>::namespaced(client.clone(), namespace);
    let plays = api
        .list(&ListParams::default().labels(&format!("{}={plan_name}", labels::PLAYBOOKPLAN_NAME)))
        .await?;

    let (successful_limit, failed_limit) = effective_limits(plan);

    for play in plays_to_prune(&plays.items, successful_limit, failed_limit) {
        let Some(name) = play.metadata.name.as_deref() else {
            continue;
        };
        debug!("Pruning old Play {name}");
        // Tolerate a concurrent delete: another tick (or GC) may have removed it already.
        if let Err(err) = api.delete(name, &DeleteParams::default()).await
            && !is_not_found(&err)
        {
            return Err(err.into());
        }
    }

    Ok(())
}

/// Effective (defaulted) `(successful, failed)` history limits for a plan.
fn effective_limits(plan: &PlaybookPlan) -> (u32, u32) {
    (
        plan.spec
            .successful_plays_history_limit
            .unwrap_or(DEFAULT_SUCCESSFUL_PLAYS_HISTORY_LIMIT),
        plan.spec
            .failed_plays_history_limit
            .unwrap_or(DEFAULT_FAILED_PLAYS_HISTORY_LIMIT),
    )
}

/// Given all `Play`s belonging to one plan, returns those to delete to satisfy the history limits.
/// Pure so retention is unit-testable without a kube client:
///   - `Running` Plays (or any without a status yet) are in-flight and never pruned.
///   - `Succeeded` Plays fill the `successful_limit` bucket.
///   - `Failed` and `Unknown` Plays share the `failed_limit` bucket — `Unknown` is a finished run
///     whose recap was lost, kept in the problem bucket rather than discarded as a success.
///
/// Within each bucket the newest (by `creationTimestamp`) are kept; the oldest beyond the limit are
/// returned for deletion.
fn plays_to_prune(plays: &[Play], successful_limit: u32, failed_limit: u32) -> Vec<&Play> {
    let mut succeeded: Vec<&Play> = Vec::new();
    let mut failed: Vec<&Play> = Vec::new();

    for play in plays {
        match play.status.as_ref().map(|s| &s.phase) {
            Some(PlayPhase::Succeeded) => succeeded.push(play),
            Some(PlayPhase::Failed | PlayPhase::Unknown) => failed.push(play),
            // Running or no status yet — in-flight, never pruned.
            _ => {}
        }
    }

    let mut to_prune = Vec::new();
    for (mut bucket, limit) in [(succeeded, successful_limit), (failed, failed_limit)] {
        // Newest first, so everything past `limit` is the oldest.
        bucket.sort_by_key(|p| {
            std::cmp::Reverse(p.metadata.creation_timestamp.as_ref().map(|t| t.0))
        });
        to_prune.extend(bucket.into_iter().skip(limit as usize));
    }

    to_prune
}

/// Builds the `Play` object (spec + metadata only — status is set separately via `patch_status`,
/// since a `create` never persists a status subresource). Owned by its `PlaybookPlan` for cascade
/// deletion and labelled with the plan name so `prune` can list a plan's Plays.
fn build_play(play: &PlayRef<'_>) -> Result<Play, ReconcileError> {
    use kube::runtime::reflector::Lookup as _;

    let plan_name = play
        .plan
        .name()
        .ok_or(ReconcileError::PreconditionFailed("name not set"))?;

    let mut object = Play::new(
        play.job_name,
        PlaySpec {
            playbook_plan: plan_name.to_string(),
            execution_hash: play.hash.to_string(),
            attempt: play.attempt,
            inventory: play.inventory.to_vec(),
        },
    );
    object.metadata.labels = Some(BTreeMap::from([(
        labels::PLAYBOOKPLAN_NAME.to_string(),
        plan_name.to_string(),
    )]));
    object.metadata.owner_references = Some(vec![playbookplan_owner_ref(play.plan)?]);

    Ok(object)
}

/// The terminal `PlayStatus` for a finished run, derived purely from the parsed recap:
///   - no recap at all (`None`) -> `Unknown` for the run and every host;
///   - every targeted host present and not a failure -> `Succeeded`;
///   - otherwise `Failed` (a failed/unreachable host, or one Ansible never reached).
fn terminal_status(
    job_name: &str,
    hosts: &[String],
    parsed: Option<&CallbackOutput>,
) -> PlayStatus {
    let host_results = host_results(parsed, hosts);
    let succeeded = host_results
        .values()
        .filter(|r| r.outcome == HostOutcome::Succeeded)
        .count();

    let phase = match parsed {
        None => PlayPhase::Unknown,
        Some(_) if succeeded == hosts.len() && !hosts.is_empty() => PlayPhase::Succeeded,
        Some(_) => PlayPhase::Failed,
    };

    PlayStatus {
        phase,
        job_name: Some(job_name.to_string()),
        finished_at: Some(chrono::Local::now().fixed_offset()),
        host_count: hosts.len() as u32,
        failed_host_count: (hosts.len() - succeeded) as u32,
        recap: sum_recap(parsed),
        hosts: host_results,
    }
}

/// The run's recap: the seven counters summed across every host Ansible processed.
fn sum_recap(parsed: Option<&CallbackOutput>) -> PlayRecap {
    let mut total = PlayRecap::default();
    if let Some(output) = parsed {
        for s in output.processed.values() {
            total.ok += s.ok;
            total.changed += s.changed;
            total.unreachable += s.unreachable;
            total.failed += s.failed;
            total.skipped += s.skipped;
            total.rescued += s.rescued;
            total.ignored += s.ignored;
        }
    }
    total
}

/// Per-host recap + outcome for every targeted host — mirrors `status::evaluate_host_outcomes`:
/// absent from the recap means `NotReached`, no recap at all means `Unknown`.
fn host_results(
    parsed: Option<&CallbackOutput>,
    hosts: &[String],
) -> BTreeMap<String, PlayHostResult> {
    hosts
        .iter()
        .map(|host| {
            let result = match parsed {
                None => PlayHostResult {
                    recap: PlayRecap::default(),
                    outcome: HostOutcome::Unknown,
                },
                Some(output) => match output.processed.get(host) {
                    None => PlayHostResult {
                        recap: PlayRecap::default(),
                        outcome: HostOutcome::NotReached,
                    },
                    Some(stats) => PlayHostResult {
                        recap: recap_from_stats(stats),
                        outcome: if stats.is_failure() {
                            HostOutcome::Failed
                        } else {
                            HostOutcome::Succeeded
                        },
                    },
                },
            };
            (host.clone(), result)
        })
        .collect()
}

fn recap_from_stats(s: &HostStats) -> PlayRecap {
    PlayRecap {
        ok: s.ok,
        changed: s.changed,
        unreachable: s.unreachable,
        failed: s.failed,
        skipped: s.skipped,
        rescued: s.rescued,
        ignored: s.ignored,
    }
}

async fn patch_status(
    api: &Api<Play>,
    name: &str,
    status: &PlayStatus,
) -> Result<(), ReconcileError> {
    api.patch_status(
        name,
        &PatchParams::default(),
        &Patch::Merge(serde_json::json!({ "status": status })),
    )
    .await?;
    Ok(())
}

fn post_params() -> PostParams {
    PostParams {
        field_manager: Some(FIELD_MANAGER.to_string()),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use k8s_openapi::jiff::Timestamp;

    fn output(entries: &[(&str, HostStats)]) -> CallbackOutput {
        CallbackOutput {
            processed: entries
                .iter()
                .map(|(h, s)| (h.to_string(), s.clone()))
                .collect(),
        }
    }

    #[test]
    fn sum_recap_totals_across_hosts_and_is_zero_without_a_recap() {
        let out = output(&[
            (
                "a",
                HostStats {
                    ok: 2,
                    changed: 1,
                    ..Default::default()
                },
            ),
            (
                "b",
                HostStats {
                    ok: 3,
                    failed: 1,
                    ..Default::default()
                },
            ),
        ]);

        let recap = sum_recap(Some(&out));
        assert_eq!(recap.ok, 5);
        assert_eq!(recap.changed, 1);
        assert_eq!(recap.failed, 1);

        assert_eq!(sum_recap(None), PlayRecap::default());
    }

    #[test]
    fn terminal_status_phase_reflects_host_outcomes() {
        let hosts = vec!["a".to_string(), "b".to_string()];

        // All present and clean -> Succeeded.
        let clean = output(&[
            (
                "a",
                HostStats {
                    ok: 1,
                    ..Default::default()
                },
            ),
            (
                "b",
                HostStats {
                    ok: 1,
                    ..Default::default()
                },
            ),
        ]);
        let s = terminal_status("job", &hosts, Some(&clean));
        assert_eq!(s.phase, PlayPhase::Succeeded);
        assert_eq!(s.failed_host_count, 0);

        // One failed host -> Failed.
        let bad = output(&[
            (
                "a",
                HostStats {
                    ok: 1,
                    ..Default::default()
                },
            ),
            (
                "b",
                HostStats {
                    failed: 1,
                    ..Default::default()
                },
            ),
        ]);
        let s = terminal_status("job", &hosts, Some(&bad));
        assert_eq!(s.phase, PlayPhase::Failed);
        assert_eq!(s.failed_host_count, 1);
        assert_eq!(s.hosts["b"].outcome, HostOutcome::Failed);

        // A targeted host missing from the recap -> NotReached, and the run is Failed.
        let partial = output(&[(
            "a",
            HostStats {
                ok: 1,
                ..Default::default()
            },
        )]);
        let s = terminal_status("job", &hosts, Some(&partial));
        assert_eq!(s.phase, PlayPhase::Failed);
        assert_eq!(s.hosts["b"].outcome, HostOutcome::NotReached);

        // No recap at all -> Unknown for the run and every host.
        let s = terminal_status("job", &hosts, None);
        assert_eq!(s.phase, PlayPhase::Unknown);
        assert_eq!(s.hosts["a"].outcome, HostOutcome::Unknown);
        assert_eq!(s.failed_host_count, 2);
    }

    #[test]
    fn plays_to_prune_keeps_newest_per_bucket_and_never_prunes_running() {
        fn play(name: &str, created: i64, phase: PlayPhase) -> Play {
            let mut p = Play::new(name, PlaySpec::default());
            p.metadata.creation_timestamp = Some(Time(Timestamp::from_second(created).unwrap()));
            p.status = Some(PlayStatus {
                phase,
                ..Default::default()
            });
            p
        }

        let plays = vec![
            play("s-old", 100, PlayPhase::Succeeded),
            play("s-mid", 200, PlayPhase::Succeeded),
            play("s-new", 300, PlayPhase::Succeeded),
            play("f-old", 100, PlayPhase::Failed),
            play("u-mid", 150, PlayPhase::Unknown),
            play("running", 500, PlayPhase::Running),
        ];

        let names: Vec<String> = plays_to_prune(&plays, 1, 1)
            .iter()
            .map(|p| p.metadata.name.clone().unwrap())
            .collect();

        // Success bucket keeps s-new -> prunes s-mid, s-old. Failed bucket {f-old, u-mid} keeps the
        // newest (u-mid) -> prunes f-old. Running is never pruned.
        assert_eq!(
            names,
            vec![
                "s-mid".to_string(),
                "s-old".to_string(),
                "f-old".to_string()
            ]
        );

        // Within limits -> nothing pruned.
        assert!(plays_to_prune(&plays, 10, 10).is_empty());
    }
}
