//! Writes and prunes `Play` recovery/history records. A Play is a durable, per-run receipt of
//! one Ansible run. It begins before Job creation, so a run abandoned during preparation has
//! no backing Job; once launched, it is 1:1 with its Job. Run identity survives status-write failures
//! and the recap survives the Job/pod's short TTL. Retention is bounded by the history limits.
//!
//! The PlaybookPlan reconciler drives the state machine these functions implement, one step per
//! call, each written down before the thing it describes is created:
//!
//! ```text
//! record_prepared  -> Prepared    nothing exists for the run yet; freely abortable
//! commit_starting  -> Starting    host Leases held, privileged proxy infra being built
//! commit_launching -> Launching   live authorization passed; Job creation is committed
//! record_running   -> Running     the Job has been created or independently observed
//! record_finished  -> Succeeded | Failed | Unknown
//! abort_unlaunched -> Aborted     superseded (or deauthorized) before its Job existed
//! ```
//!
//! Phases are not simply monotonic — `Aborted` is a terminal-but-not-finished side exit whose
//! record must outlive its own cleanup, since that record is what keeps the cleanup retryable.
//! Every transition reads the object fresh and writes it back through `replace_status`, so it
//! carries a `resourceVersion` precondition; `decide_transition` makes replaying a step that
//! already landed a no-op, while a record that moved somewhere else entirely fails loudly. Losing
//! that precondition (a 409) is not a failure but a stale read, so `transition_phase` re-reads and
//! re-decides once rather than surfacing it to the reconciler as an error.

use std::collections::BTreeMap;

use kube::{
    Api,
    api::{DeleteParams, ListParams, PostParams, Preconditions},
};
use tracing::debug;

use crate::v1beta1::{
    HostOutcome, Play, PlayHostResult, PlayPhase, PlayRecap, PlaySpec, PlayStatus, PlaybookPlan,
    ResolvedHosts, UnreachableHost,
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

/// Identifies one run for the history calls: the plan it belongs to, the backing Job's name
/// (which is also the Play's name), the execution hash, the run number, its attempt within the
/// execution, and the inventory it targeted (grouped, for the Play spec).
pub struct PlayRef<'a> {
    pub plan: &'a PlaybookPlan,
    pub job_name: &'a str,
    pub hash: &'a ExecutionHash,
    pub run_id: &'a str,
    pub preparation_fingerprint: &'a str,
    pub run_number: u32,
    pub attempt: u32,
    pub inventory: &'a [ResolvedHosts],
    pub triggered_slot: Option<chrono::DateTime<chrono::FixedOffset>>,
}

/// Records immutable run metadata before creating any run infrastructure. `Prepared` means Job
/// creation has not been committed, so recovery may safely resume preparation or atomically abort.
pub async fn record_prepared(
    client: &kube::Client,
    namespace: &str,
    play: &PlayRef<'_>,
) -> Result<Play, ReconcileError> {
    let api = Api::<Play>::namespaced(client.clone(), namespace);
    let desired = build_play(play)?;

    let object = match api.get_opt(play.job_name).await? {
        Some(existing) if !same_run_record(&existing, &desired) => {
            return Err(ReconcileError::PreconditionFailed(
                "existing Play does not belong to the selected run",
            ));
        }
        // Includes a statusless record: `same_run_record` has just proved it is *this* run's, and
        // a statusless record is exactly the artifact a lost `create` response leaves behind. Falling
        // through initializes it below instead of wedging the run on its own crash artifact.
        Some(existing) => existing,
        None => match api.create(&post_params(), &desired).await {
            Ok(created) => created,
            Err(err) if is_conflict(&err) => {
                let existing = api.get(play.job_name).await?;
                if !same_run_record(&existing, &desired) {
                    return Err(ReconcileError::PreconditionFailed(
                        "conflicting Play does not belong to the selected run",
                    ));
                }
                existing
            }
            Err(err) => return Err(err.into()),
        },
    };

    match object.status.as_ref().map(|status| &status.phase) {
        None => replace_status(&api, object, prepared_status(play)).await,
        Some(
            PlayPhase::Prepared | PlayPhase::Starting | PlayPhase::Launching | PlayPhase::Running,
        ) => Ok(object),
        Some(
            PlayPhase::Succeeded | PlayPhase::Failed | PlayPhase::Unknown | PlayPhase::Aborted,
        ) => Err(ReconcileError::PreconditionFailed(
            "selected Play is already terminal",
        )),
    }
}

fn prepared_status(play: &PlayRef<'_>) -> PlayStatus {
    PlayStatus {
        phase: PlayPhase::Prepared,
        job_name: Some(play.job_name.to_string()),
        host_count: distinct_host_count(play.inventory),
        ..Default::default()
    }
}

/// How many *distinct* hosts an inventory targets. Counted distinctly to match `terminal_status`,
/// which reports per host: a node reachable through two inventory groups appears in the flat list
/// twice but is one host to Ansible, so a count that said otherwise would make a clean run look
/// partially failed for as long as the record stayed non-terminal.
fn distinct_host_count(inventory: &[ResolvedHosts]) -> u32 {
    crate::v1beta1::distinct_host_count(inventory) as u32
}

/// Marks a `Launching` run as running after its exact Job has been created or independently
/// observed. A record that has not yet committed to start (`Prepared`, `Starting`) is rejected: the
/// point of `commit_launching` is that live authorization passed *before* a Job could exist, so a
/// caller holding one that skipped it is describing a Job this protocol never allowed.
/// Terminal status is monotonic: a stale starter never changes a finished Play back to `Running`.
pub async fn record_running(
    client: &kube::Client,
    namespace: &str,
    play_name: &str,
    play_uid: &str,
) -> Result<Play, ReconcileError> {
    let api = Api::<Play>::namespaced(client.clone(), namespace);
    let object = api.get(play_name).await?;
    let status = object
        .status
        .as_ref()
        .ok_or(ReconcileError::PreconditionFailed(
            "prepared Play has no status",
        ))?;

    verify_play_uid(&object, play_uid)?;
    match status.phase {
        PlayPhase::Launching => {
            let mut next = status.clone();
            next.phase = PlayPhase::Running;
            replace_status(&api, object, next).await
        }
        PlayPhase::Running | PlayPhase::Succeeded | PlayPhase::Failed | PlayPhase::Unknown => {
            Ok(object)
        }
        PlayPhase::Prepared | PlayPhase::Starting | PlayPhase::Aborted => Err(
            ReconcileError::PreconditionFailed("Play is not committed to start"),
        ),
    }
}

pub async fn commit_starting(
    client: &kube::Client,
    namespace: &str,
    play_name: &str,
    play_uid: &str,
) -> Result<Play, ReconcileError> {
    transition_phase(
        client,
        namespace,
        play_name,
        play_uid,
        PlayPhase::Prepared,
        PlayPhase::Starting,
        None,
    )
    .await
}

/// Commits the run to creating its Job, recording the hosts it is launching without — see
/// [`PlayStatus::unreachable_hosts`].
///
/// This is the transition that means "the infrastructure has settled", which is the moment the set
/// is both known and still true, so it is written here rather than observed later. A replay of a
/// commit that already landed stays the no-op every step of this protocol is, so the set the first
/// commit recorded is the one that stands — which is the intended reading of "at launch".
pub async fn commit_launching(
    client: &kube::Client,
    namespace: &str,
    play_name: &str,
    play_uid: &str,
    unreachable_hosts: &[UnreachableHost],
) -> Result<Play, ReconcileError> {
    transition_phase(
        client,
        namespace,
        play_name,
        play_uid,
        PlayPhase::Starting,
        PlayPhase::Launching,
        Some(unreachable_hosts),
    )
    .await
}

/// Abandons a run that has not launched its Job, from whichever pre-`Running` phase it is in.
///
/// `from` is the phase the caller observed, and it is passed rather than inferred so the transition
/// keeps its precondition: a record that has moved on since the caller looked must fail loudly
/// instead of being force-aborted from under whoever moved it. Aborting from `Launching` is only
/// legitimate once the backing Job has been shown not to exist — a run whose Job is already out
/// there is adopted and allowed to finish instead.
pub async fn abort_unlaunched(
    client: &kube::Client,
    namespace: &str,
    play_name: &str,
    play_uid: &str,
    from: PlayPhase,
) -> Result<Play, ReconcileError> {
    if !is_unlaunched(&from) {
        return Err(ReconcileError::PreconditionFailed(
            "only an unlaunched Play can be aborted",
        ));
    }
    transition_phase(
        client,
        namespace,
        play_name,
        play_uid,
        from,
        PlayPhase::Aborted,
        None,
    )
    .await
}

/// How many times a phase transition re-reads and retries after losing an optimistic-concurrency
/// race. One retry is enough: a 409 here means somebody else wrote the record's status between our
/// read and our write, and `decide_transition` re-decides against the value that actually landed —
/// either accepting it as already-done, or failing loudly because the record moved elsewhere.
const TRANSITION_CONFLICT_RETRIES: usize = 1;

/// Whether a phase is one in which the run's Job does not exist yet. Pure so the set stays
/// pinned: a new phase added on the wrong side of this line would let a run with a live Job be
/// abandoned as if nothing had been created for it.
fn is_unlaunched(phase: &PlayPhase) -> bool {
    match phase {
        PlayPhase::Prepared | PlayPhase::Starting | PlayPhase::Launching => true,
        PlayPhase::Running
        | PlayPhase::Succeeded
        | PlayPhase::Failed
        | PlayPhase::Unknown
        | PlayPhase::Aborted => false,
    }
}

async fn transition_phase(
    client: &kube::Client,
    namespace: &str,
    play_name: &str,
    play_uid: &str,
    expected: PlayPhase,
    next: PlayPhase,
    unreachable_hosts: Option<&[UnreachableHost]>,
) -> Result<Play, ReconcileError> {
    let api = Api::<Play>::namespaced(client.clone(), namespace);

    for attempt in 0..=TRANSITION_CONFLICT_RETRIES {
        let object = api.get(play_name).await?;
        verify_play_uid(&object, play_uid)?;
        let status = object
            .status
            .as_ref()
            .ok_or(ReconcileError::PreconditionFailed("Play has no status"))?;

        let Some(status) = decide_transition(status, &expected, next.clone(), unreachable_hosts)?
        else {
            return Ok(object);
        };
        match replace_status(&api, object, status).await {
            Err(error) if error.is_conflict() && attempt < TRANSITION_CONFLICT_RETRIES => {
                debug!("Lost a write race transitioning Play {play_name}; re-reading and retrying");
            }
            result => return result,
        }
    }

    unreachable!("the loop returns on its last iteration")
}

/// The pure decision behind [`transition_phase`]: `Some(status)` to write, `None` if the record is
/// already there, `Err` if it moved somewhere else.
///
/// Idempotence is the point. Every caller is a step in a crash-recoverable protocol that may be
/// replayed after the write landed but before the operator observed it, so re-running a transition
/// that already happened has to be a no-op rather than an error — while a record that advanced to
/// some *third* phase must still fail loudly, because that means another writer is driving the same
/// run.
///
/// The whole status is carried forward and only the phase — plus, for the launch commit, the
/// excluded hosts — is replaced, so every field a later transition inherits survives to the
/// terminal write.
fn decide_transition(
    status: &PlayStatus,
    expected: &PlayPhase,
    next: PlayPhase,
    unreachable_hosts: Option<&[UnreachableHost]>,
) -> Result<Option<PlayStatus>, ReconcileError> {
    if status.phase == next {
        return Ok(None);
    }
    if status.phase != *expected {
        return Err(ReconcileError::PreconditionFailed(
            "Play phase changed before transition",
        ));
    }
    let mut next_status = status.clone();
    next_status.phase = next;
    if let Some(unreachable_hosts) = unreachable_hosts {
        next_status.unreachable_hosts = unreachable_hosts.to_vec();
    }
    Ok(Some(next_status))
}

/// Whether an object already at this run's name *is* this run's record.
///
/// Compared on identity, not on the whole spec. The identity fields are sufficient and narrower:
/// `run_id` is minted per run and never re-derived, so no other run can present the same
/// one, and `preparation_fingerprint` already reduces the plan spec plus the resolved run groups to
/// a single value. Matching field-by-field on everything else would buy nothing and would be the
/// same brittleness `validate_selected_job` deliberately avoids for Jobs: any server-side
/// normalization the operator failed to predict would make the comparison fail forever, and the
/// failure mode is an unrepairable `PreconditionFailed` on that run number.
fn same_run_record(existing: &Play, desired: &Play) -> bool {
    existing_owner_matches(existing, desired)
        && play_belongs_to_plan(
            existing,
            &desired.spec.playbook_plan,
            &desired.spec.playbook_plan_uid,
        )
        && existing.spec.execution_hash == desired.spec.execution_hash
        && existing.spec.run_id == desired.spec.run_id
        && existing.spec.run_number == desired.spec.run_number
        && existing.spec.preparation_fingerprint == desired.spec.preparation_fingerprint
}

pub(super) fn play_belongs_to_plan(play: &Play, plan_name: &str, plan_uid: &str) -> bool {
    play.spec.playbook_plan == plan_name && play.spec.playbook_plan_uid == plan_uid
}

fn existing_owner_matches(existing: &Play, desired: &Play) -> bool {
    let Some(desired_owner) = desired
        .metadata
        .owner_references
        .as_ref()
        .and_then(|owners| owners.first())
    else {
        return false;
    };
    existing
        .metadata
        .owner_references
        .as_ref()
        .is_some_and(|owners| {
            owners.iter().any(|owner| {
                owner.api_version == desired_owner.api_version
                    && owner.kind == desired_owner.kind
                    && owner.name == desired_owner.name
                    && owner.uid == desired_owner.uid
            })
        })
}

pub fn needs_recovery(play: &Play) -> bool {
    play_is_terminal(play)
        && play
            .status
            .as_ref()
            .is_some_and(|status| !status.plan_status_recorded)
}

/// Marks a terminal record's result as folded into its plan, which is what stops it being drained a
/// second time and what releases it to retention.
///
/// Strict about the record still being there: a caller only reaches this having read the result off
/// that very record this tick, so a name that is now empty — or now holds a different object — means
/// something outside the protocol removed the receipt for a privileged run between the read and the
/// acknowledgement. That is worth one failed tick to say out loud. It costs no more than that: the
/// plan's own complete status was already patched before this call, so replaying the record on the
/// next tick is idempotent. Callers that *know* there is nothing to acknowledge pass
/// `TerminalRecord::Lost` and never come here.
pub async fn acknowledge_finished(
    client: &kube::Client,
    namespace: &str,
    play_name: &str,
    play_uid: &str,
) -> Result<(), ReconcileError> {
    let api = Api::<Play>::namespaced(client.clone(), namespace);
    let object = api
        .get_opt(play_name)
        .await?
        .ok_or(ReconcileError::PreconditionFailed(
            "finished Play disappeared before it could be acknowledged",
        ))?;
    verify_play_uid(&object, play_uid)?;
    let status = object
        .status
        .as_ref()
        .ok_or(ReconcileError::PreconditionFailed(
            "finished Play has no status",
        ))?;
    if !matches!(
        status.phase,
        PlayPhase::Succeeded | PlayPhase::Failed | PlayPhase::Unknown
    ) {
        return Err(ReconcileError::PreconditionFailed(
            "cannot acknowledge a nonterminal Play",
        ));
    }
    if status.plan_status_recorded {
        return Ok(());
    }

    let mut next = status.clone();
    next.plan_status_recorded = true;
    replace_status(&api, object, next).await?;
    Ok(())
}

/// Deletes an incomplete statusless record. No run infrastructure may be derived from such an
/// object because it has not crossed the operator-owned status-subresource trust boundary.
pub async fn delete_uninitialized(
    client: &kube::Client,
    namespace: &str,
    play: &Play,
) -> Result<(), ReconcileError> {
    let api = Api::<Play>::namespaced(client.clone(), namespace);
    let play_name = play
        .metadata
        .name
        .as_deref()
        .ok_or(ReconcileError::PreconditionFailed("Play name not set"))?;
    let params = DeleteParams::default().preconditions(Preconditions {
        uid: play.metadata.uid.clone(),
        resource_version: play.metadata.resource_version.clone(),
    });
    // A conflict is tolerated alongside a not-found: the `resourceVersion` precondition is what makes
    // this delete safe, and losing it means the record changed after the caller classified it —
    // most often because the status write that was interrupted mid-`record_prepared` has since
    // landed, which makes the object no longer uninitialized at all. Failing the tick over that
    // would report a spurious "run recovery failed" on the plan; the next tick simply re-reads and
    // reclassifies it.
    if let Err(error) = api.delete(play_name, &params).await
        && !is_not_found(&error)
        && !is_conflict(&error)
    {
        return Err(error.into());
    }
    Ok(())
}

/// Deletes an aborted record after cleanup and plan-status persistence complete.
pub async fn delete_aborted(
    client: &kube::Client,
    namespace: &str,
    play_name: &str,
    play_uid: &str,
) -> Result<(), ReconcileError> {
    let api = Api::<Play>::namespaced(client.clone(), namespace);
    let Some(object) = api.get_opt(play_name).await? else {
        return Ok(());
    };
    verify_play_uid(&object, play_uid)?;
    if object.status.as_ref().map(|status| &status.phase) != Some(&PlayPhase::Aborted) {
        return Err(ReconcileError::PreconditionFailed(
            "aborted Play changed before it could be deleted",
        ));
    }
    let params = DeleteParams::default().preconditions(Preconditions {
        uid: object.metadata.uid.clone(),
        resource_version: object.metadata.resource_version.clone(),
    });
    if let Err(error) = api.delete(play_name, &params).await
        && !is_not_found(&error)
    {
        return Err(error.into());
    }
    Ok(())
}

/// The terminal status of a run whose `Play` was deleted mid-flight: no recap can be read for it any
/// more, so every host it targeted falls to `Unknown`, exactly as for a run whose Job was reaped
/// before the operator saw its recap.
pub fn lost_run_status(job_name: &str, hosts: &[String]) -> PlayStatus {
    // No record, so nothing is known about which hosts it excluded either.
    terminal_status(job_name, hosts, None, Vec::new())
}

/// Stamps the terminal outcome onto the run's existing immutable recovery record.
pub async fn record_finished(
    api: &Api<Play>,
    object: Play,
    play_uid: &str,
    hosts: &[String],
    parsed: Option<&CallbackOutput>,
) -> Result<Play, ReconcileError> {
    verify_play_uid(&object, play_uid)?;
    let job_name = object
        .metadata
        .name
        .clone()
        .ok_or(ReconcileError::PreconditionFailed("Play name not set"))?;
    // The terminal status is built fresh rather than derived from the record, so anything the run
    // wrote down about itself has to be carried across explicitly.
    let unreachable_hosts = object
        .status
        .as_ref()
        .map(|status| status.unreachable_hosts.clone())
        .unwrap_or_default();
    let status = terminal_status(&job_name, hosts, parsed, unreachable_hosts);
    match object.status.as_ref().map(|status| &status.phase) {
        Some(PlayPhase::Launching | PlayPhase::Running) => {
            replace_status(api, object, status).await
        }
        Some(PlayPhase::Succeeded | PlayPhase::Failed | PlayPhase::Unknown) => Ok(object),
        Some(PlayPhase::Prepared | PlayPhase::Starting | PlayPhase::Aborted) => Err(
            ReconcileError::PreconditionFailed("cannot finish a run that did not start"),
        ),
        None => Err(ReconcileError::PreconditionFailed(
            "cannot finish an uninitialized Play",
        )),
    }
}

/// Deletes the oldest `Play`s for `plan` beyond its success/failure history limits.
///
/// Returns whether a concurrent update skipped a deletion and retention should be retried soon.
pub async fn prune(
    client: &kube::Client,
    namespace: &str,
    plan: &PlaybookPlan,
) -> Result<bool, ReconcileError> {
    use kube::runtime::reflector::Lookup as _;

    let plan_name = plan
        .name()
        .ok_or(ReconcileError::PreconditionFailed("name not set"))?;
    let plan_uid = plan
        .uid()
        .ok_or(ReconcileError::PreconditionFailed("uid not set"))?;

    let api = Api::<Play>::namespaced(client.clone(), namespace);
    let mut plays = api
        .list(&ListParams::default().labels(&format!("{}={plan_name}", labels::PLAYBOOKPLAN_NAME)))
        .await?;
    // The label is only a discovery index: a plan name can be reused after deletion.
    plays
        .items
        .retain(|play| play_belongs_to_plan(play, plan_name.as_ref(), plan_uid.as_ref()));

    let (successful_limit, failed_limit) = effective_limits(plan);

    let mut retry = false;
    for play in plays_to_prune(&plays.items, successful_limit, failed_limit) {
        let Some(name) = play.metadata.name.as_deref() else {
            continue;
        };
        debug!("Pruning old Play {name}");
        let params = DeleteParams::default().preconditions(Preconditions {
            uid: play.metadata.uid.clone(),
            resource_version: play.metadata.resource_version.clone(),
        });
        // The list may be stale: never delete a replacement at this name, and let a concurrent
        // update or delete be re-evaluated on the next retention pass.
        match api.delete(name, &params).await {
            Ok(_) => {}
            Err(err) if is_not_found(&err) => {}
            Err(err) if is_conflict(&err) => retry = true,
            Err(err) => return Err(err.into()),
        }
    }

    Ok(retry)
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
///   - `Prepared`/`Starting`/`Launching`/`Running` Plays (and any without a status yet) are
///     in-flight and never pruned. Neither are `Aborted` ones: an aborted run may still hold host
///     Leases and proxy pods, and its record is what keeps that cleanup retryable, so it must
///     outlive every step that can fail (`delete_aborted` removes it once cleanup has completed).
///   - A terminal Play whose result has not been folded into the plan yet (`needs_recovery`) is
///     likewise never pruned: that record is the *only* copy of the recap,
///     and deleting it would send the next reconcile down `finalize_lost_run`, discarding a
///     successful run's results and reporting every host `Unknown`. Callers happen to acknowledge
///     before pruning, but retention must not depend on that ordering.
///   - Terminal Plays without a creation timestamp are not classified for pruning and are kept.
///   - `Succeeded` Plays fill the `successful_limit` bucket.
///   - `Failed` and `Unknown` Plays share the `failed_limit` bucket — `Unknown` is a finished run
///     whose recap was lost, kept in the problem bucket rather than discarded as a success.
///
/// Within each bucket the newest (by `creationTimestamp`, then `run_number`) are kept; the oldest
/// beyond the limit are returned for deletion.
fn plays_to_prune(plays: &[Play], successful_limit: u32, failed_limit: u32) -> Vec<&Play> {
    let mut succeeded: Vec<&Play> = Vec::new();
    let mut failed: Vec<&Play> = Vec::new();

    for play in plays {
        if play.metadata.creation_timestamp.is_none() {
            continue;
        }
        // Its recap has not reached the plan yet — treat it as in-flight, not as history.
        if needs_recovery(play) {
            continue;
        }
        match play.status.as_ref().map(|s| &s.phase) {
            Some(PlayPhase::Succeeded) => succeeded.push(play),
            Some(PlayPhase::Failed | PlayPhase::Unknown) => failed.push(play),
            // In-flight, aborted-but-not-yet-cleaned-up, or no status yet — never pruned.
            _ => {}
        }
    }

    let mut to_prune = Vec::new();
    for (mut bucket, limit) in [(succeeded, successful_limit), (failed, failed_limit)] {
        // Newest first, so everything past `limit` is the oldest.
        bucket.sort_by_key(|p| {
            std::cmp::Reverse((
                p.metadata.creation_timestamp.as_ref().map(|t| t.0),
                p.spec.run_number,
            ))
        });
        to_prune.extend(bucket.into_iter().skip(limit as usize));
    }

    to_prune
}

/// Builds the `Play` object (spec + metadata only — status is set separately via `replace_status`,
/// since a `create` never persists a status subresource). Owned by its `PlaybookPlan` for cascade
/// deletion and labelled with the plan name so `prune` can list a plan's Plays.
fn build_play(play: &PlayRef<'_>) -> Result<Play, ReconcileError> {
    use kube::runtime::reflector::Lookup as _;

    let plan_name = play
        .plan
        .name()
        .ok_or(ReconcileError::PreconditionFailed("name not set"))?;
    let plan_uid = play
        .plan
        .uid()
        .ok_or(ReconcileError::PreconditionFailed("uid not set"))?;

    let mut object = Play::new(
        play.job_name,
        PlaySpec {
            playbook_plan: plan_name.to_string(),
            playbook_plan_uid: plan_uid.to_string(),
            execution_hash: play.hash.to_string(),
            run_id: play.run_id.to_string(),
            preparation_fingerprint: play.preparation_fingerprint.to_string(),
            run_number: play.run_number,
            attempt: play.attempt,
            inventory: play.inventory.to_vec(),
            triggered_slot: play.triggered_slot,
        },
    );
    object.metadata.labels = Some(BTreeMap::from([
        (labels::PLAYBOOKPLAN_NAME.to_string(), plan_name.to_string()),
        (labels::PLAYBOOKPLAN_HASH.to_string(), play.hash.to_string()),
    ]));
    object.metadata.owner_references = Some(vec![playbookplan_owner_ref(play.plan)?]);

    Ok(object)
}

/// The terminal `PlayStatus` for a finished run, derived purely from the parsed recap:
///   - no recap at all (`None`) -> `Unknown` for the run and every host;
///   - every targeted host present and not a failure -> `Succeeded`;
///   - otherwise `Failed` (a failed/unreachable host, or one Ansible never reached).
///
/// Counted over the *distinct* hosts, not over `hosts` itself: a node listed by two inventory groups
/// is flattened into that slice twice, and comparing a deduplicated success count against the raw
/// length would report a clean run as `Failed` — leaving its hosts outdated and re-running forever.
///
/// `unreachable_hosts` is the exception to "derived from the recap": it is what the run wrote down
/// at its launch commit and is passed back in, because a status built from scratch would otherwise
/// drop the one thing the recap cannot say.
fn terminal_status(
    job_name: &str,
    hosts: &[String],
    parsed: Option<&CallbackOutput>,
    unreachable_hosts: Vec<UnreachableHost>,
) -> PlayStatus {
    let host_results = host_results(parsed, hosts, &unreachable_hosts);
    let host_count = host_results.len();
    let succeeded = host_results
        .values()
        .filter(|r| r.outcome == HostOutcome::Succeeded)
        .count();

    let phase = match parsed {
        Some(_) if succeeded == host_count && host_count != 0 => PlayPhase::Succeeded,
        Some(_) => PlayPhase::Failed,
        // A run that excluded every host it targeted never launched a Job and has no recap to be
        // missing: the exclusions settle its outcome on their own. `Unknown` is for a run that ran
        // and whose result could not be read, and reporting that here would deny the plan the one
        // thing it does know — that nobody could be reached.
        //
        // Asked over membership in `unreachable_hosts`, not over the outcome, because the outcome no
        // longer answers it: `host_results` splits an exclusion into `Unreachable` or `NotReached`
        // depending on whether the Node was down, so one `Ready`-Node proxy failure among the
        // exclusions would drop an entirely known run into `Unknown` — misreporting it and denying
        // the refund, the two things this arm exists to prevent. Membership is the question that was
        // always meant: was every host excluded before the run?
        None if host_count != 0
            && host_results
                .keys()
                .all(|host| unreachable_hosts.iter().any(|entry| entry.host == *host)) =>
        {
            PlayPhase::Failed
        }
        None => PlayPhase::Unknown,
    };

    PlayStatus {
        phase,
        plan_status_recorded: false,
        job_name: Some(job_name.to_string()),
        finished_at: Some(chrono::Local::now().fixed_offset()),
        host_count: host_count as u32,
        failed_host_count: (host_count - succeeded) as u32,
        recap: sum_recap(parsed, &unreachable_hosts),
        hosts: host_results,
        unreachable_hosts,
    }
}

/// The run's recap: the seven counters the user's **own** playbook would have printed, running
/// unmodified against the same fleet in the same condition.
///
/// That is the standard, and it is deliberately neither of the two things closer to hand. It is not
/// the pod's `PLAY RECAP`, which counts the *operator's* playbook — the appended completion marker
/// inflates every host's `ok`, and the hosts the run excluded are missing entirely. Nor is it a sum
/// over [`host_results`], which is keyed by the run's own host list and so silently drops every host
/// Ansible processed that is not an inventory host of the plan: the implicit localhost of a
/// `hosts: localhost` play, an `add_host` target.
///
/// So it is summed from two sources, one per kind of host:
///
/// - the parsed recap, which is already the author's own counters — the callback subtracts the
///   marker's `ok` per host, gated on the same per-host flag that records it, so a host that never
///   ran the marker has nothing subtracted;
/// - one `unreachable` per excluded host, which no recap can supply: the run passed
///   `--limit '!<host>'`, so Ansible never processed it and never counted it. Without this the total
///   would claim the run reached every host it targeted.
///
/// The two cannot overlap, which is what makes adding them safe: `--limit` keeps an excluded host
/// out of every play, so it is never in `processed` — not even if the playbook `add_host`s a host of
/// that name, since the limit still applies to it. A run that excluded *everything* has no recap at
/// all and falls out as `0 + N`, which is again what the user's own playbook would print with every
/// host down.
///
/// The consequence is that the total can exceed what the rows in `.status.hosts` account for, and
/// that is correct rather than an inconsistency: `hostCount` counts the hosts the run targeted while
/// the recap counts what the playbook did, and a `localhost` play has made those differ for as long
/// as playbooks have had one.
fn sum_recap(parsed: Option<&CallbackOutput>, unreachable_hosts: &[UnreachableHost]) -> PlayRecap {
    let mut total = PlayRecap::default();
    for s in parsed.iter().flat_map(|output| output.processed.values()) {
        total.ok += s.ok;
        total.changed += s.changed;
        total.unreachable += s.unreachable;
        total.failed += s.failed;
        total.skipped += s.skipped;
        total.rescued += s.rescued;
        total.ignored += s.ignored;
    }
    total.unreachable += unreachable_hosts.len() as u32;
    total
}

/// Per-host recap + outcome for every targeted host. These outcomes are what
/// `status::apply_terminal_play_status` later folds into the plan, so this is where the mapping is
/// decided: absent from the recap means `NotReached`, no recap at all means `Unknown`, and a host
/// the recap does carry is classified from its own counters by [`outcome_from_stats`].
///
/// A host the run excluded is the one outcome not read off the recap. It is absent from it — the
/// run passed `--limit '!<host>'` precisely so nothing would be attempted against it — so what it
/// gets is what the operator established before the run began, rather than something inferred from
/// an address chosen to fail.
///
/// **Which** exclusion it was decides the outcome, because the two are recovered from in different
/// places and only one of them can be recovered from at all by a Node coming back:
///
/// - the Node itself was not `Ready` (`node_not_ready`) — nothing could connect to it, and its next
///   `Ready` heartbeat is exactly what fixes that. `Unreachable`, which is in the Node watch's wake
///   set (`mappers::plan_awaits_node`) so the plan retries the moment the Node returns.
/// - the Node was `Ready` and its proxy pod never came up anyway — an untolerated taint, a failing
///   image pull, a rejecting admission webhook. The Node is already `Ready`, so no Node event will
///   ever resolve it; only the pod spec will. `NotReached` — the same answer `mappers` gives a host
///   a `serial` batch stopped short of, and for the same reason: this host's own heartbeats carry no
///   news. Left `Unreachable`, it would wake the plan once per kubelet heartbeat for the plan's
///   whole life, re-resolving both inventory kinds, re-reading every referenced Secret and listing
///   every Node, long after the attempt budget stopped it acting.
///
/// Both keep `unreachable: 1` in the recap: the counter records that nothing connected, which is
/// true either way, and it is what stops [`sum_recap`] reporting the run as having reached every
/// host it targeted. The outcome records whose problem it is; they answer different questions.
fn host_results(
    parsed: Option<&CallbackOutput>,
    hosts: &[String],
    unreachable_hosts: &[UnreachableHost],
) -> BTreeMap<String, PlayHostResult> {
    hosts
        .iter()
        .map(|host| {
            let excluded = unreachable_hosts.iter().find(|entry| entry.host == *host);
            let result = if let Some(entry) = excluded {
                PlayHostResult {
                    recap: PlayRecap {
                        unreachable: 1,
                        ..PlayRecap::default()
                    },
                    outcome: if entry.node_not_ready {
                        HostOutcome::Unreachable
                    } else {
                        HostOutcome::NotReached
                    },
                }
            } else {
                match parsed {
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
                            outcome: outcome_from_stats(stats),
                        },
                    },
                }
            };
            (host.clone(), result)
        })
        .collect()
}

/// The outcome a host's own recap counters describe.
///
/// Success is asked as `is_failure`, not re-derived from the counters, so that this and the run's
/// verdict — which counts the hosts that came out `Succeeded` — can never disagree about what a
/// success is. Only the failing half is split further: a host with no failed tasks that Ansible
/// could not connect to at all is `Unreachable`. Reporting that as `Failed` would send an operator
/// looking for a broken task.
///
/// A host carrying both counters is `Failed`: tasks did run and did fail before the connection went,
/// and the playbook failure is the more actionable of the two.
///
/// Clean counters are the case the counters get wrong on their own, and where completion decides:
/// a host the playbook stopped short of reports exactly what a host that ran every task reports.
/// Trusting the counters there is what recorded a partially applied host as converged, permanently.
/// Completion is only consulted on that branch — a host that did fail is `Failed` whether or not
/// the run got as far as asking, and its failure is the actionable thing either way.
///
/// **A host that is in the recap but not in the plan's inventory would classify `Incomplete` here,
/// and two things have to keep holding for that never to happen.** The implicit localhost of a
/// `hosts: localhost` play is in the recap with `completed = false`, because the marker play targets
/// `all` and `all` never matches an implicit localhost. It reaches no verdict only because
/// [`host_results`] iterates the *run's* host list, so no outcome is computed for it at all. Widen
/// either side — a marker play that also took `localhost`, or a `host_results` keyed off the recap —
/// and a plain `localhost` play starts reporting a host as `Incomplete`, which is the operator's way
/// of saying nothing converged.
fn outcome_from_stats(stats: &HostStats) -> HostOutcome {
    if !stats.is_failure() {
        if stats.completed {
            HostOutcome::Succeeded
        } else {
            HostOutcome::Incomplete
        }
    } else if stats.failed == 0 {
        HostOutcome::Unreachable
    } else {
        HostOutcome::Failed
    }
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

async fn replace_status(
    api: &Api<Play>,
    mut object: Play,
    status: PlayStatus,
) -> Result<Play, ReconcileError> {
    let name = object
        .metadata
        .name
        .clone()
        .ok_or(ReconcileError::PreconditionFailed("Play name not set"))?;
    object.status = Some(status);
    Ok(api
        .replace_status(&name, &PostParams::default(), &object)
        .await?)
}

fn play_is_terminal(play: &Play) -> bool {
    play.status.as_ref().is_some_and(|status| {
        matches!(
            status.phase,
            PlayPhase::Succeeded | PlayPhase::Failed | PlayPhase::Unknown
        )
    })
}

fn verify_play_uid(play: &Play, expected_uid: &str) -> Result<(), ReconcileError> {
    if play.metadata.uid.as_deref() != Some(expected_uid) {
        return Err(ReconcileError::PreconditionFailed("Play UID changed"));
    }
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

    fn unreachable_host(host: &str, node_not_ready: bool) -> UnreachableHost {
        UnreachableHost {
            host: host.to_string(),
            node_not_ready,
        }
    }

    /// A minimal plan with a name/UID, enough for `build_play`'s owner reference.
    fn plan(name: &str, uid: &str) -> PlaybookPlan {
        let mut plan = PlaybookPlan::new(name, Default::default());
        plan.metadata.namespace = Some("team".into());
        plan.metadata.uid = Some(uid.into());
        plan
    }

    fn play_ref<'a>(
        plan: &'a PlaybookPlan,
        hash: &'a ExecutionHash,
        run_id: &'a str,
        fingerprint: &'a str,
        run_number: u32,
        inventory: &'a [ResolvedHosts],
    ) -> PlayRef<'a> {
        PlayRef {
            plan,
            job_name: "apply-web-abc-1",
            hash,
            run_id,
            preparation_fingerprint: fingerprint,
            run_number,
            attempt: 1,
            inventory,
            triggered_slot: None,
        }
    }

    fn hash() -> ExecutionHash {
        ExecutionHash::from_hex("1").unwrap()
    }

    #[test]
    fn build_play_records_the_identity_recovery_reads_back() {
        let plan = plan("web", "plan-uid");
        let hash = hash();
        let inventory = vec![ResolvedHosts {
            name: "nodes".into(),
            hosts: vec!["a".into(), "b".into()],
        }];
        let built = build_play(&play_ref(&plan, &hash, "run-1", "fp-1", 3, &inventory)).unwrap();

        assert_eq!(built.metadata.name.as_deref(), Some("apply-web-abc-1"));
        assert_eq!(built.spec.playbook_plan, "web");
        assert_eq!(built.spec.playbook_plan_uid, "plan-uid");
        assert_eq!(built.spec.run_id, "run-1");
        assert_eq!(built.spec.preparation_fingerprint, "fp-1");
        assert_eq!(built.spec.run_number, 3);
        assert_eq!(built.spec.attempt, 1);
        assert_eq!(built.spec.inventory, inventory);

        // The plan-name label is what `prune` and the recovery scan list on.
        let labels = built.metadata.labels.as_ref().unwrap();
        assert_eq!(labels[labels::PLAYBOOKPLAN_NAME], "web");

        // The owner reference is what makes the record cascade with its plan.
        let owner = &built.metadata.owner_references.as_ref().unwrap()[0];
        assert_eq!(owner.kind, "PlaybookPlan");
        assert_eq!(owner.uid, "plan-uid");

        // A create never persists a status; `record_prepared` initializes it separately.
        assert!(built.status.is_none());
    }

    /// The anti-adoption property the whole write-ahead protocol rests on: an object sitting at this
    /// run's name is only *this* run's record if its identity matches. Compared on identity
    /// rather than the whole spec, so that a field the apiserver normalizes on the way in can never
    /// wedge the run permanently.
    #[test]
    fn same_run_record_accepts_only_this_runs_identity() {
        let hash = hash();
        let inventory = vec![ResolvedHosts {
            name: "nodes".into(),
            hosts: vec!["a".into()],
        }];
        let build = |run_id: &str, fp: &str, run_number: u32, uid: &str| {
            let plan = plan("web", uid);
            build_play(&play_ref(&plan, &hash, run_id, fp, run_number, &inventory)).unwrap()
        };

        let desired = build("run-1", "fp-1", 1, "plan-uid");
        assert!(same_run_record(
            &build("run-1", "fp-1", 1, "plan-uid"),
            &desired
        ));

        // A different run of the same plan: same name is possible after an abort freed the
        // number, but the run ID never repeats.
        assert!(!same_run_record(
            &build("run-2", "fp-1", 1, "plan-uid"),
            &desired
        ));
        // A different revision that happens to reuse the run number.
        assert!(!same_run_record(
            &build("run-1", "fp-2", 1, "plan-uid"),
            &desired
        ));
        assert!(!same_run_record(
            &build("run-1", "fp-1", 2, "plan-uid"),
            &desired
        ));
        // A plan deleted and recreated under the same name must not adopt the old record.
        assert!(!same_run_record(
            &build("run-1", "fp-1", 1, "other-uid"),
            &desired
        ));

        // Fields outside the identity set deliberately do NOT participate: a record whose target
        // inventory came back from etcd in another shape is still ours, and the fingerprint above
        // is what catches a record prepared against different inputs.
        let mut normalized = build("run-1", "fp-1", 1, "plan-uid");
        normalized.spec.inventory = Vec::new();
        assert!(
            same_run_record(&normalized, &desired),
            "identity, not the whole spec, decides adoption"
        );
    }

    #[test]
    fn existing_owner_matches_requires_the_same_owning_plan_instance() {
        let plan_a = plan("web", "uid-a");
        let plan_b = plan("web", "uid-b");
        let hash = hash();
        let make =
            |p: &PlaybookPlan| build_play(&play_ref(p, &hash, "run-1", "fp", 1, &[])).unwrap();

        let desired = make(&plan_a);
        assert!(existing_owner_matches(&make(&plan_a), &desired));
        assert!(
            !existing_owner_matches(&make(&plan_b), &desired),
            "same plan name, recreated with a new UID, is a different owner"
        );

        let mut ownerless = make(&plan_a);
        ownerless.metadata.owner_references = None;
        assert!(!existing_owner_matches(&ownerless, &desired));
    }

    #[test]
    fn prepared_status_starts_a_record_at_prepared_with_its_host_count() {
        let plan = plan("web", "uid");
        let hash = hash();
        let inventory = vec![ResolvedHosts {
            name: "nodes".into(),
            hosts: vec!["a".into(), "b".into(), "c".into()],
        }];

        let status = prepared_status(&play_ref(&plan, &hash, "run-1", "fp", 1, &inventory));

        assert_eq!(status.phase, PlayPhase::Prepared);
        assert_eq!(status.job_name.as_deref(), Some("apply-web-abc-1"));
        assert_eq!(status.host_count, 3);
        assert!(
            !status.plan_status_recorded,
            "a prepared run has no result to acknowledge"
        );
    }

    /// A run whose record vanished mid-flight can never be recapped, so it takes the same shape as a
    /// run whose Job was reaped before its recap was read: `Unknown`, for every host it targeted.
    #[test]
    fn lost_run_status_reports_every_targeted_host_unknown() {
        let hosts = vec!["a".to_string(), "b".to_string()];

        let status = lost_run_status("apply-web-abc-1", &hosts);

        assert_eq!(status.phase, PlayPhase::Unknown);
        assert_eq!(status.host_count, 2);
        assert_eq!(status.failed_host_count, 2);
        assert_eq!(status.hosts["a"].outcome, HostOutcome::Unknown);
        assert_eq!(status.hosts["b"].outcome, HostOutcome::Unknown);
        assert!(
            !status.plan_status_recorded,
            "the plan has not been told about this yet"
        );
    }

    /// `Aborted` is terminal-but-not-finished: it carries no result, and treating it as terminal
    /// here would let retention prune a record whose cleanup may still be outstanding.
    #[test]
    fn play_is_terminal_covers_finished_results_but_not_aborted_or_in_flight() {
        let at = |phase: &PlayPhase| {
            let mut play = Play::new("run", PlaySpec::default());
            play.status = Some(PlayStatus {
                phase: phase.clone(),
                ..Default::default()
            });
            play
        };

        for phase in [PlayPhase::Succeeded, PlayPhase::Failed, PlayPhase::Unknown] {
            assert!(play_is_terminal(&at(&phase)), "{phase:?} is a result");
        }
        for phase in [
            PlayPhase::Prepared,
            PlayPhase::Starting,
            PlayPhase::Launching,
            PlayPhase::Running,
            PlayPhase::Aborted,
        ] {
            assert!(!play_is_terminal(&at(&phase)), "{phase:?} is not a result");
        }

        assert!(!play_is_terminal(&Play::new("run", PlaySpec::default())));
    }

    /// Every status write re-reads the object, so the UID is what proves the object read back is the
    /// same one the run recorded — a name alone can be reused by a later run.
    #[test]
    fn verify_play_uid_rejects_a_different_or_missing_object() {
        let mut play = Play::new("run", PlaySpec::default());
        play.metadata.uid = Some("uid-1".into());

        assert!(verify_play_uid(&play, "uid-1").is_ok());
        assert!(verify_play_uid(&play, "uid-2").is_err());

        play.metadata.uid = None;
        assert!(verify_play_uid(&play, "uid-1").is_err());
    }

    /// A terminal Play that has already been folded into its plan's status — i.e. genuine history,
    /// which is the only thing retention is allowed to consider.
    fn recorded_play(name: &str, created: i64, phase: PlayPhase) -> Play {
        let mut play = Play::new(name, PlaySpec::default());
        play.metadata.creation_timestamp = Some(Time(Timestamp::from_second(created).unwrap()));
        play.status = Some(PlayStatus {
            phase,
            plan_status_recorded: true,
            ..Default::default()
        });
        play
    }

    /// The run's counters are what Ansible reported, plus one `unreachable` per host the run
    /// excluded — which no recap mentions, so summing the recap alone would claim the run reached
    /// every host it targeted.
    #[test]
    fn sum_recap_totals_the_recap_plus_the_exclusions() {
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

        let recap = sum_recap(Some(&out), &[unreachable_host("excluded", true)]);
        assert_eq!(recap.ok, 5);
        assert_eq!(recap.changed, 1);
        assert_eq!(recap.failed, 1);
        assert_eq!(recap.unreachable, 1);

        assert_eq!(sum_recap(None, &[]), PlayRecap::default());

        // A run that excluded every host it targeted has no recap at all, and its total is exactly
        // what the user's own playbook would have printed with every host down.
        assert_eq!(
            sum_recap(
                None,
                &[unreachable_host("a", true), unreachable_host("b", false)]
            ),
            PlayRecap {
                unreachable: 2,
                ..PlayRecap::default()
            }
        );
    }

    /// The run's counters reproduce the user's **own** playbook, not the operator's rewrite of it
    /// and not the rows in `.status.hosts`. Measured against a real `ansible-core`: a 1-task
    /// `hosts: localhost` play then a 3-task `hosts: workers` play over `node-a`/`node-b`/`node-c`
    /// with `node-c` down prints `ok=7, unreachable=1` when the author runs it themselves.
    ///
    /// The operator's run of the same playbook produces the wire message below — `node-c` excluded
    /// so absent, the appended marker already subtracted per host, and `localhost` present because
    /// `hosts: localhost` plays run (`workspace::render_limit` permits the implicit localhost). Two
    /// wrong answers are close to hand and this pins against both: the pod's own `PLAY RECAP` says
    /// `ok=9`, counting the marker task the operator appended, and summing the per-host rows says
    /// `ok=6`, dropping `localhost` because it is not an inventory host of the plan.
    #[test]
    fn the_run_total_reproduces_the_users_own_playbook() {
        let wire = output(&[
            (
                "localhost",
                HostStats {
                    ok: 1,
                    ..Default::default()
                },
            ),
            (
                "node-a",
                HostStats {
                    ok: 3,
                    completed: true,
                    ..Default::default()
                },
            ),
            (
                "node-b",
                HostStats {
                    ok: 3,
                    completed: true,
                    ..Default::default()
                },
            ),
        ]);

        let recap = sum_recap(Some(&wire), &[unreachable_host("node-c", true)]);

        assert_eq!(recap.ok, 7);
        assert_eq!(recap.unreachable, 1);

        // And the rows are unaffected: the plan's three hosts, localhost among none of them.
        let rows = host_results(
            Some(&wire),
            &[
                "node-a".to_string(),
                "node-b".to_string(),
                "node-c".to_string(),
            ],
            &[unreachable_host("node-c", true)],
        );

        assert_eq!(rows.len(), 3);
        assert!(!rows.contains_key("localhost"));
        assert_eq!(rows["node-a"].outcome, HostOutcome::Succeeded);
        assert_eq!(rows["node-c"].outcome, HostOutcome::Unreachable);
    }

    /// Where a host's verdict is decided. The interesting line is between `Failed` and
    /// `Unreachable`: they are fixed in different places — a broken task versus a host nothing
    /// could connect to — and a managed-ssh Node whose proxy never came up is deliberately rendered
    /// at an unroutable address to land in the second.
    #[test]
    fn a_host_that_was_never_connected_to_is_unreachable_rather_than_failed() {
        // Ran to the end, so the only thing left to classify is the counters.
        let stats = |failed: u32, unreachable: u32| HostStats {
            ok: 1,
            failed,
            unreachable,
            completed: true,
            ..Default::default()
        };

        assert_eq!(outcome_from_stats(&stats(0, 0)), HostOutcome::Succeeded);
        assert_eq!(outcome_from_stats(&stats(0, 1)), HostOutcome::Unreachable);
        assert_eq!(outcome_from_stats(&stats(1, 0)), HostOutcome::Failed);
        // The connection dropped mid-run: something did run and did fail, which is the half worth
        // reporting.
        assert_eq!(outcome_from_stats(&stats(1, 1)), HostOutcome::Failed);

        // The classification is per host, and a host the recap never mentions is not classified
        // from counters at all.
        let hosts = vec![
            "reached".to_string(),
            "unreachable".to_string(),
            "absent".to_string(),
        ];
        let results = host_results(
            Some(&output(&[
                ("reached", stats(1, 0)),
                ("unreachable", stats(0, 1)),
            ])),
            &hosts,
            &[],
        );

        assert_eq!(results["reached"].outcome, HostOutcome::Failed);
        assert_eq!(results["unreachable"].outcome, HostOutcome::Unreachable);
        assert_eq!(results["absent"].outcome, HostOutcome::NotReached);
        // The per-host counters travel with the verdict, so `unreachable: 1` is still readable on
        // the host itself and not only in the run's total.
        assert_eq!(results["unreachable"].recap.unreachable, 1);
    }

    /// The defect the completion marker exists for. A playbook that stops at the first failure —
    /// `any_errors_fatal`, a failed `serial` batch, `max_fail_percentage` — leaves the surviving
    /// hosts having run *part* of it, and their counters are byte-for-byte what a host that ran all
    /// of it reports: `failed=0, unreachable=0`. Reading them as `Succeeded` stamped a partially
    /// applied host as converged and dropped it from every future run.
    #[test]
    fn a_host_the_playbook_stopped_short_of_is_not_a_success() {
        let cut_short = HostStats {
            ok: 1,
            skipped: 1,
            completed: false,
            ..Default::default()
        };
        let ran_it_all = HostStats {
            ok: 3,
            completed: true,
            ..Default::default()
        };

        // Identical on every counter that exists — only completion separates them.
        assert!(!cut_short.is_failure());
        assert!(!ran_it_all.is_failure());
        assert_eq!(outcome_from_stats(&cut_short), HostOutcome::Incomplete);
        assert_eq!(outcome_from_stats(&ran_it_all), HostOutcome::Succeeded);

        // A host that did fail is `Failed` whether or not the run got as far as asking: its own
        // failure is the actionable thing, and it is what stopped the others.
        let failed = HostStats {
            ok: 1,
            failed: 1,
            completed: false,
            ..Default::default()
        };
        assert_eq!(outcome_from_stats(&failed), HostOutcome::Failed);
    }

    /// The whole aborted run, end to end: one host fails, the play stops, and the two healthy hosts
    /// must not come out of it recorded as having received the playbook.
    #[test]
    fn an_aborted_play_leaves_its_survivors_incomplete_and_the_run_failed() {
        let hosts = vec![
            "good-a".to_string(),
            "good-b".to_string(),
            "bad-c".to_string(),
        ];
        let cut_short = HostStats {
            ok: 1,
            skipped: 1,
            ..Default::default()
        };
        let recap = output(&[
            ("good-a", cut_short.clone()),
            ("good-b", cut_short),
            (
                "bad-c",
                HostStats {
                    ok: 1,
                    failed: 1,
                    ..Default::default()
                },
            ),
        ]);

        let status = terminal_status("job", &hosts, Some(&recap), Vec::new());

        assert_eq!(status.phase, PlayPhase::Failed);
        assert_eq!(status.hosts["good-a"].outcome, HostOutcome::Incomplete);
        assert_eq!(status.hosts["good-b"].outcome, HostOutcome::Incomplete);
        assert_eq!(status.hosts["bad-c"].outcome, HostOutcome::Failed);
        // None of the three is a success, so none of them is recorded as converged.
        assert_eq!(status.failed_host_count, 3);
    }

    /// A host in the run's inventory that no play in the playbook targets. It reaches the marker —
    /// which targets `all` — with no counters at all, and that is the honest answer: applying this
    /// playbook to it is vacuous, so it is up to date. Before the marker it was absent from the
    /// recap entirely, which read as `NotReached`, failed the run, and left the plan retrying a
    /// host no run would ever touch until its attempt budget ran out.
    #[test]
    fn a_host_no_play_targets_is_converged_rather_than_never_reached() {
        let hosts = vec!["web-1".to_string(), "db-1".to_string()];
        let recap = output(&[
            (
                "web-1",
                HostStats {
                    ok: 2,
                    completed: true,
                    ..Default::default()
                },
            ),
            (
                "db-1",
                HostStats {
                    completed: true,
                    ..Default::default()
                },
            ),
        ]);

        let status = terminal_status("job", &hosts, Some(&recap), Vec::new());

        assert_eq!(status.phase, PlayPhase::Succeeded);
        assert_eq!(status.hosts["db-1"].outcome, HostOutcome::Succeeded);
        // Its counters stay empty: nothing ran on it, and the marker is subtracted back out by the
        // callback, so the run's totals describe the playbook rather than the operator.
        assert_eq!(status.hosts["db-1"].recap, PlayRecap::default());
    }

    /// An `Unreachable` host is not a success, so it must count against the run exactly as a failed
    /// one does — the verdict asks `is_failure`, and splitting the outcome finer must not have
    /// quietly moved that line.
    #[test]
    fn an_unreachable_host_still_makes_the_run_fail() {
        let hosts = vec!["a".to_string(), "b".to_string()];
        let recap = output(&[
            (
                "a",
                HostStats {
                    ok: 1,
                    completed: true,
                    ..Default::default()
                },
            ),
            (
                "b",
                HostStats {
                    unreachable: 1,
                    ..Default::default()
                },
            ),
        ]);

        let status = terminal_status("job", &hosts, Some(&recap), Vec::new());

        assert_eq!(status.phase, PlayPhase::Failed);
        assert_eq!(status.failed_host_count, 1);
        assert_eq!(status.hosts["b"].outcome, HostOutcome::Unreachable);
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
                    completed: true,
                    ..Default::default()
                },
            ),
            (
                "b",
                HostStats {
                    ok: 1,
                    completed: true,
                    ..Default::default()
                },
            ),
        ]);
        let s = terminal_status("job", &hosts, Some(&clean), Vec::new());
        assert_eq!(s.phase, PlayPhase::Succeeded);
        assert_eq!(s.failed_host_count, 0);

        // One failed host -> Failed.
        let bad = output(&[
            (
                "a",
                HostStats {
                    ok: 1,
                    completed: true,
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
        let s = terminal_status("job", &hosts, Some(&bad), Vec::new());
        assert_eq!(s.phase, PlayPhase::Failed);
        assert_eq!(s.failed_host_count, 1);
        assert_eq!(s.hosts["b"].outcome, HostOutcome::Failed);

        // A targeted host missing from the recap -> NotReached, and the run is Failed.
        let partial = output(&[(
            "a",
            HostStats {
                ok: 1,
                completed: true,
                ..Default::default()
            },
        )]);
        let s = terminal_status("job", &hosts, Some(&partial), Vec::new());
        assert_eq!(s.phase, PlayPhase::Failed);
        assert_eq!(s.hosts["b"].outcome, HostOutcome::NotReached);

        // No recap at all -> Unknown for the run and every host.
        let s = terminal_status("job", &hosts, None, Vec::new());
        assert_eq!(s.phase, PlayPhase::Unknown);
        assert_eq!(s.hosts["a"].outcome, HostOutcome::Unknown);
        assert_eq!(s.failed_host_count, 2);
    }

    /// A node listed by two inventory groups is flattened into the targeted-host slice twice. The
    /// per-host results deduplicate it, so the tallies must be taken over those rather than over the
    /// raw slice — otherwise a clean run reports `Failed` and its hosts never come up to date.
    #[test]
    fn terminal_status_counts_a_host_listed_by_two_groups_once() {
        let hosts = vec!["a".to_string(), "a".to_string(), "b".to_string()];
        let clean = output(&[
            (
                "a",
                HostStats {
                    ok: 1,
                    completed: true,
                    ..Default::default()
                },
            ),
            (
                "b",
                HostStats {
                    ok: 1,
                    completed: true,
                    ..Default::default()
                },
            ),
        ]);

        let status = terminal_status("job", &hosts, Some(&clean), Vec::new());

        assert_eq!(status.phase, PlayPhase::Succeeded);
        assert_eq!(status.host_count, 2);
        assert_eq!(status.failed_host_count, 0);
    }

    /// Each protocol step may be replayed after its write landed but before the operator observed
    /// it, so replaying a transition that already happened must be a no-op — while a record that
    /// moved somewhere else entirely means a second writer is driving the run, and must fail.
    #[test]
    fn a_transition_is_idempotent_but_rejects_a_record_that_moved_elsewhere() {
        let at = |phase: PlayPhase| PlayStatus {
            phase,
            ..Default::default()
        };

        // The expected phase -> advance.
        let advanced = decide_transition(
            &at(PlayPhase::Prepared),
            &PlayPhase::Prepared,
            PlayPhase::Starting,
            None,
        )
        .unwrap()
        .expect("a pending transition must produce a status to write");
        assert_eq!(advanced.phase, PlayPhase::Starting);

        // Already there -> nothing to write, and not an error.
        assert!(
            decide_transition(
                &at(PlayPhase::Starting),
                &PlayPhase::Prepared,
                PlayPhase::Starting,
                None
            )
            .unwrap()
            .is_none()
        );

        // Somewhere else entirely -> refuse.
        assert!(
            decide_transition(
                &at(PlayPhase::Running),
                &PlayPhase::Prepared,
                PlayPhase::Starting,
                None
            )
            .is_err()
        );

        // An abort cannot resurrect a run that already finished.
        assert!(
            decide_transition(
                &at(PlayPhase::Succeeded),
                &PlayPhase::Starting,
                PlayPhase::Aborted,
                None
            )
            .is_err()
        );
    }

    /// The launch commit is the only writer of the excluded hosts, and the terminal write builds a
    /// *fresh* status rather than editing the record's — so the set has to be carried across both
    /// deliberately. Without that a host the run never attempted comes back as `NotReached`, and
    /// the attempt budget loses the only evidence it has about why.
    #[test]
    fn hosts_recorded_at_launch_survive_every_later_transition() {
        let starting = PlayStatus {
            phase: PlayPhase::Starting,
            ..Default::default()
        };

        let launching = decide_transition(
            &starting,
            &PlayPhase::Starting,
            PlayPhase::Launching,
            Some(&[unreachable_host("node-b", true)]),
        )
        .unwrap()
        .expect("the launch commit writes a status");
        assert_eq!(
            launching.unreachable_hosts,
            vec![unreachable_host("node-b", true)]
        );

        // Every other transition passes `None` and must leave the recorded set alone.
        let aborted =
            decide_transition(&launching, &PlayPhase::Launching, PlayPhase::Aborted, None)
                .unwrap()
                .expect("a pending transition produces a status");
        assert_eq!(
            aborted.unreachable_hosts,
            vec![unreachable_host("node-b", true)]
        );

        // The recap carries only the host the run actually ran: `node-b` was limited out of it.
        let terminal = terminal_status(
            "apply-web-abc-1",
            &["node-a".to_string(), "node-b".to_string()],
            Some(&output(&[(
                "node-a",
                HostStats {
                    ok: 1,
                    completed: true,
                    ..Default::default()
                },
            )])),
            launching.unreachable_hosts.clone(),
        );

        assert_eq!(terminal.phase, PlayPhase::Failed);
        assert_eq!(terminal.hosts["node-b"].outcome, HostOutcome::Unreachable);
        assert_eq!(
            terminal.unreachable_hosts,
            vec![unreachable_host("node-b", true)]
        );
    }

    /// A run that excluded every host never launches a Job, so no recap will ever exist for it —
    /// but its outcome is not unknown, it is `Failed`, with every host carrying whichever exclusion
    /// it was. Calling it `Unknown` would send an operator looking for lost instrumentation, and
    /// would deny the plan the refund `classify_run_failure` owes a run whose Nodes were all down.
    ///
    /// The question is asked over membership in `unreachable_hosts`, not over the outcomes, and the
    /// mixed case is why: the outcomes no longer agree with each other, so one `Ready`-Node proxy
    /// failure among the exclusions would drop an entirely known run into `Unknown`.
    #[test]
    fn a_run_that_excluded_every_host_is_failed_rather_than_unknown() {
        let hosts = vec!["node-a".to_string(), "node-b".to_string()];

        let all_excluded = terminal_status(
            "apply-web-abc-1",
            &hosts,
            None,
            vec![
                unreachable_host("node-a", true),
                unreachable_host("node-b", true),
            ],
        );

        assert_eq!(all_excluded.phase, PlayPhase::Failed);
        assert_eq!(
            all_excluded.hosts["node-a"].outcome,
            HostOutcome::Unreachable
        );
        assert_eq!(all_excluded.failed_host_count, 2);
        assert_eq!(all_excluded.recap.unreachable, 2);

        let mixed_exclusions = terminal_status(
            "apply-web-abc-1",
            &hosts,
            None,
            vec![
                unreachable_host("node-a", true),
                unreachable_host("node-b", false),
            ],
        );

        assert_eq!(mixed_exclusions.phase, PlayPhase::Failed);
        assert_eq!(
            mixed_exclusions.hosts["node-b"].outcome,
            HostOutcome::NotReached
        );
        assert_eq!(mixed_exclusions.failed_host_count, 2);
        assert_eq!(mixed_exclusions.recap.unreachable, 2);

        // A run that did launch and whose recap could not be read is still `Unknown`: one of its
        // hosts was reachable, so something ran and its result was lost.
        let recap_lost = terminal_status(
            "apply-web-abc-1",
            &hosts,
            None,
            vec![unreachable_host("node-a", true)],
        );

        assert_eq!(recap_lost.phase, PlayPhase::Unknown);
        assert_eq!(recap_lost.hosts["node-b"].outcome, HostOutcome::Unknown);
    }

    /// A host excluded because its Node was down is absent from the recap for a reason the recap
    /// cannot express, so the default for an absent host is wrong for it in both directions:
    /// `NotReached` would put it outside the Node watch's wake set, when that Node returning is
    /// precisely what resolves it, and a run total summed over the recap alone would claim the run
    /// reached every host it targeted.
    #[test]
    fn a_host_excluded_by_a_down_node_is_unreachable_rather_than_not_reached() {
        let hosts = vec![
            "ran".to_string(),
            "excluded".to_string(),
            "absent".to_string(),
        ];
        let results = host_results(
            Some(&output(&[(
                "ran",
                HostStats {
                    ok: 1,
                    completed: true,
                    ..Default::default()
                },
            )])),
            &hosts,
            &[unreachable_host("excluded", true)],
        );

        assert_eq!(results["ran"].outcome, HostOutcome::Succeeded);
        assert_eq!(results["excluded"].outcome, HostOutcome::Unreachable);
        assert_eq!(results["excluded"].recap.unreachable, 1);
        assert_eq!(results["absent"].outcome, HostOutcome::NotReached);
    }

    /// Why a host was excluded decides its outcome, because the two exclusions are recovered from in
    /// different places: a Node that was down is fixed by that Node returning, and `Unreachable` is
    /// in the Node watch's wake set so the plan retries the moment it does. A `Ready` Node whose
    /// proxy pod never came up is fixed in the pod's scheduling, and its Node has nothing further to
    /// report — reporting that as `Unreachable` too woke the plan once per kubelet heartbeat for its
    /// whole life, re-resolving inventories, re-reading Secrets and listing every Node, long after
    /// the attempt budget had stopped it acting.
    ///
    /// The counters do not split: nothing connected either way, and that is what keeps the run's
    /// recap from claiming it reached every host it targeted.
    #[test]
    fn an_excluded_hosts_outcome_says_which_kind_of_exclusion_it_was() {
        let hosts = vec!["node-a".to_string(), "node-b".to_string()];
        let results = host_results(
            None,
            &hosts,
            &[
                unreachable_host("node-a", true),
                unreachable_host("node-b", false),
            ],
        );

        assert_eq!(results["node-a"].outcome, HostOutcome::Unreachable);
        assert_eq!(results["node-b"].outcome, HostOutcome::NotReached);
        assert_eq!(results["node-a"].recap.unreachable, 1);
        assert_eq!(results["node-b"].recap.unreachable, 1);
    }

    /// `abort_unlaunched` is the only way into `Aborted`, and it is only ever legitimate while the
    /// run has no Job. Aborting a `Running` one would drop a live node-root execution's record
    /// while the execution carried on.
    #[test]
    fn only_a_phase_without_a_job_counts_as_unlaunched() {
        for phase in [
            PlayPhase::Prepared,
            PlayPhase::Starting,
            PlayPhase::Launching,
        ] {
            assert!(is_unlaunched(&phase), "{phase:?} has no Job yet");
        }
        for phase in [
            PlayPhase::Running,
            PlayPhase::Succeeded,
            PlayPhase::Failed,
            PlayPhase::Unknown,
            PlayPhase::Aborted,
        ] {
            assert!(!is_unlaunched(&phase), "{phase:?} must not be abortable");
        }
    }

    #[test]
    fn plays_to_prune_keeps_newest_per_bucket_and_never_prunes_running() {
        let plays = vec![
            recorded_play("s-old", 100, PlayPhase::Succeeded),
            recorded_play("s-mid", 200, PlayPhase::Succeeded),
            recorded_play("s-new", 300, PlayPhase::Succeeded),
            recorded_play("f-old", 100, PlayPhase::Failed),
            recorded_play("u-mid", 150, PlayPhase::Unknown),
            recorded_play("running", 500, PlayPhase::Running),
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

    #[test]
    fn plays_to_prune_uses_run_number_when_creation_timestamps_tie() {
        let mut first = recorded_play("s-run-1", 100, PlayPhase::Succeeded);
        first.spec.run_number = 1;
        let mut second = recorded_play("s-run-2", 100, PlayPhase::Succeeded);
        second.spec.run_number = 2;

        let plays = [first, second];
        let names: Vec<&str> = plays_to_prune(&plays, 1, 1)
            .iter()
            .filter_map(|play| play.metadata.name.as_deref())
            .collect();

        assert_eq!(names, vec!["s-run-1"]);
    }

    #[test]
    fn plays_to_prune_never_prunes_a_terminal_play_without_creation_timestamp() {
        let timestamped = recorded_play("s-timestamped", 100, PlayPhase::Succeeded);
        let mut timestampless = recorded_play("s-timestampless", 200, PlayPhase::Succeeded);
        timestampless.metadata.creation_timestamp = None;

        let plays = [timestamped, timestampless];
        let names: Vec<&str> = plays_to_prune(&plays, 0, 0)
            .iter()
            .filter_map(|play| play.metadata.name.as_deref())
            .collect();

        assert_eq!(names, vec!["s-timestamped"]);
    }

    #[test]
    fn pruning_ignores_a_predecessor_with_the_same_plan_name() {
        let mut predecessor = recorded_play("predecessor", 100, PlayPhase::Succeeded);
        predecessor.spec.playbook_plan = "web".into();
        predecessor.spec.playbook_plan_uid = "old-uid".into();

        let mut current = recorded_play("current", 200, PlayPhase::Succeeded);
        current.spec.playbook_plan = "web".into();
        current.spec.playbook_plan_uid = "new-uid".into();

        let plays = vec![predecessor, current];
        let current_generation: Vec<Play> = plays
            .into_iter()
            .filter(|play| play_belongs_to_plan(play, "web", "new-uid"))
            .collect();
        let names: Vec<&str> = plays_to_prune(&current_generation, 0, 0)
            .iter()
            .filter_map(|play| play.metadata.name.as_deref())
            .collect();

        assert_eq!(names, vec!["current"]);
    }

    /// The record of a terminal run whose recap has not reached the plan yet is the only copy of
    /// that recap. Pruning it would send the next reconcile down `finalize_lost_run` and report a
    /// successful run's hosts as `Unknown`, so retention must hold it back regardless of the limits.
    #[test]
    fn plays_to_prune_never_prunes_a_terminal_result_the_plan_has_not_recorded() {
        let mut unacknowledged = recorded_play("s-new", 300, PlayPhase::Succeeded);
        unacknowledged.status.as_mut().unwrap().plan_status_recorded = false;

        let plays = vec![
            recorded_play("s-old", 100, PlayPhase::Succeeded),
            unacknowledged,
        ];

        let names: Vec<String> = plays_to_prune(&plays, 0, 0)
            .iter()
            .map(|p| p.metadata.name.clone().unwrap())
            .collect();

        assert_eq!(
            names,
            vec!["s-old".to_string()],
            "only the acknowledged record may be pruned, even at a zero limit"
        );
    }

    #[test]
    fn acknowledged_terminal_result_is_prunable_at_zero_limit() {
        let plays = vec![recorded_play("s-old", 100, PlayPhase::Succeeded)];

        let names: Vec<String> = plays_to_prune(&plays, 0, 0)
            .iter()
            .map(|play| play.metadata.name.clone().unwrap())
            .collect();

        assert_eq!(names, vec!["s-old"]);
    }

    /// An aborted run may still hold host Leases and proxy pods; its record is what keeps that
    /// cleanup retryable, so it must outlive the cleanup rather than be pruned as history.
    #[test]
    fn plays_to_prune_never_prunes_an_aborted_run_awaiting_cleanup() {
        let plays = vec![recorded_play("aborted", 100, PlayPhase::Aborted)];

        assert!(plays_to_prune(&plays, 0, 0).is_empty());
    }

    #[test]
    fn terminal_recovery_uses_status_acknowledgement_and_retention_can_follow() {
        let mut play = Play::new("run", PlaySpec::default());
        play.metadata.creation_timestamp = Some(Time(Timestamp::from_second(100).unwrap()));
        play.status = Some(PlayStatus {
            phase: PlayPhase::Succeeded,
            plan_status_recorded: false,
            ..Default::default()
        });

        assert!(needs_recovery(&play));
        play.status.as_mut().unwrap().plan_status_recorded = true;
        assert!(!needs_recovery(&play));

        let names: Vec<String> = plays_to_prune(&[play], 0, 0)
            .iter()
            .map(|play| play.metadata.name.clone().unwrap())
            .collect();
        assert_eq!(names, vec!["run"]);
    }
}
