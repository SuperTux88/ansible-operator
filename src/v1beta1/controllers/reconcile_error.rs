use k8s_openapi::api::batch::v1::Job;
use kube::ResourceExt as _;

use crate::v1beta1::{Play, PlayPhase, ansible};

#[derive(thiserror::Error, Debug)]
pub enum ReconcileError {
    #[error(transparent)]
    KubeError(#[from] kube::Error),

    #[error("Precondition failed: {0}")]
    PreconditionFailed(&'static str),

    /// A run's `Play` record is not in the state the record protocol (`play_history`) expects at
    /// this step. Names the record and the phase it was read in: a failure here usually means a
    /// second writer is driving the same run, and the record is the only evidence left of it.
    #[error("Play {namespace}/{play}{}: {reason}", phase_suffix(.phase))]
    RecordMismatch {
        namespace: String,
        play: String,
        /// `None` if the record had no status, or was not there at all.
        phase: Option<PlayPhase>,
        /// Completes a sentence whose subject is the record, e.g. "has no status".
        reason: &'static str,
    },

    /// A Job at a run's recorded name is not the Job that run expects. Names the Job, because
    /// when it is a foreign one, deleting that exact Job is how the run is unblocked.
    #[error("Job {namespace}/{job}: {reason}")]
    JobMismatch {
        namespace: String,
        job: String,
        /// Completes a sentence whose subject is the Job, e.g. "has no run ID".
        reason: &'static str,
    },

    /// Every run name a new run could take is held by a Job or `Play` the plan did not create.
    #[error(
        "run names {first} to {last} in namespace {namespace} are all held by Jobs or Plays this plan did not create; delete the ones that are not the operator's"
    )]
    RunNamesTaken {
        namespace: String,
        first: String,
        last: String,
    },

    /// More than one of a plan's `Play` records is in flight, which the record protocol never
    /// produces. Names them all, since resolving it means deleting the stray one.
    #[error(
        "more than one Play in namespace {namespace} claims to be the plan's active run: {}",
        .plays.join(", ")
    )]
    ConcurrentActiveRecords {
        namespace: String,
        plays: Vec<String>,
    },

    #[error("Inventory group {group:?} sets variable {key:?}, which the operator manages")]
    ReservedInventoryVariable { group: String, key: String },

    #[error("Referenced {kind} {name:?} does not exist")]
    InventoryNotFound { kind: &'static str, name: String },

    #[error(
        "Host {host:?} is reached both as a cluster Node (group {node_group:?}) and as an external host (group {ssh_group:?}); one name cannot mean two machines"
    )]
    AmbiguousHost {
        host: String,
        node_group: String,
        ssh_group: String,
    },

    #[error(
        "Host {host:?} is reached as an external host by {first} and by {second}, with different SSH credentials; one name cannot be reached two ways"
    )]
    AmbiguousHostCredentials {
        host: String,
        first: String,
        second: String,
    },

    #[error(
        "Referenced ClusterInventory {name:?} has not published its resolved hosts for generation {generation} yet (observed: {observed})"
    )]
    InventoryNotSynced {
        name: String,
        generation: i64,
        observed: String,
    },

    #[error("Referenced Secret {name:?} does not exist")]
    SecretNotFound { name: String },

    #[error("spec.template.files entry {name:?} is not usable: {reason}")]
    InvalidFileEntry { name: String, reason: &'static str },

    /// The plan's own playbook does not parse. Kept apart from [`ReconcileError::RenderError`],
    /// which also covers the operator's own rendering, because only this one is the user's to fix.
    #[error("spec.template.playbook is not a valid playbook: {0}")]
    InvalidPlaybook(#[source] ansible::RenderError),

    #[error(
        "Secret {name:?} already exists but is not owned by this PlaybookPlan, so it cannot be used as its workspace"
    )]
    ForeignWorkspaceSecret { name: String },

    #[error(
        "spec.template references Secret {name:?}, which is this plan's own workspace — the operator rewrites it on every run, so it cannot also be an input"
    )]
    WorkspaceSecretReferenced { name: String },

    #[error(
        "{kind} {name:?} already exists but is not this run's managed-ssh proxy for host {host:?}"
    )]
    ForeignProxyResource {
        kind: &'static str,
        name: String,
        host: String,
    },

    #[error(transparent)]
    RenderError(#[from] ansible::RenderError),

    #[error(transparent)]
    CaError(#[from] crate::v1beta1::ca::CaError),

    #[error(transparent)]
    JsonSerializationError(#[from] serde_json::Error),

    #[error(transparent)]
    YamlSerializationError(#[from] serde_yaml::Error),
}

fn phase_suffix(phase: &Option<PlayPhase>) -> String {
    phase
        .as_ref()
        .map(|phase| format!(" (phase {phase:?})"))
        .unwrap_or_default()
}

/// Whether a kube API error is a 409 Conflict. Covers both of the concurrency outcomes this
/// operator treats as recoverable rather than fatal: losing an optimistic-concurrency race on a
/// version-checked write, and an `AlreadyExists` on `create`. Callers re-read and re-decide.
pub fn is_conflict(err: &kube::Error) -> bool {
    matches!(err, kube::Error::Api(status) if status.code == 409)
}

/// Whether a kube API error is a 404 Not Found — for a delete, the outcome the caller wanted.
pub fn is_not_found(err: &kube::Error) -> bool {
    matches!(err, kube::Error::Api(status) if status.code == 404)
}

impl ReconcileError {
    /// Whether this wraps a 409 Conflict — see [`is_conflict`].
    pub fn is_conflict(&self) -> bool {
        matches!(self, ReconcileError::KubeError(error) if is_conflict(error))
    }

    /// A [`ReconcileError::RecordMismatch`] naming `record` as it was read.
    pub fn record_mismatch(record: &Play, reason: &'static str) -> Self {
        ReconcileError::RecordMismatch {
            namespace: record.namespace().unwrap_or_default(),
            play: Some(record.name_any())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| "<unnamed>".into()),
            phase: record.status.as_ref().map(|status| status.phase.clone()),
            reason,
        }
    }

    /// A [`ReconcileError::JobMismatch`] naming `job` as it was read.
    pub fn job_mismatch(job: &Job, reason: &'static str) -> Self {
        ReconcileError::JobMismatch {
            namespace: job.namespace().unwrap_or_default(),
            job: Some(job.name_any())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| "<unnamed>".into()),
            reason,
        }
    }

    /// A [`ReconcileError::ConcurrentActiveRecords`] naming every record in `records`.
    pub fn concurrent_active_records(records: &[&Play]) -> Self {
        ReconcileError::ConcurrentActiveRecords {
            namespace: records
                .first()
                .and_then(|record| record.namespace())
                .unwrap_or_default(),
            plays: records.iter().map(|record| record.name_any()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1beta1::{PlaySpec, PlayStatus};

    fn record(name: &str) -> Play {
        let mut play = Play::new(name, PlaySpec::default());
        play.metadata.namespace = Some("ops".into());
        play
    }

    /// A record-protocol failure is logged and written into the plan's summary with nothing else
    /// around it, so the message itself has to say which record it was and what phase it was in.
    #[test]
    fn a_record_mismatch_names_the_record_and_its_phase() {
        let mut play = record("apply-web-abc-1");
        assert_eq!(
            ReconcileError::record_mismatch(&play, "has no status").to_string(),
            "Play ops/apply-web-abc-1: has no status"
        );

        play.status = Some(PlayStatus {
            phase: PlayPhase::Running,
            ..Default::default()
        });
        assert_eq!(
            ReconcileError::record_mismatch(&play, "phase changed before the transition")
                .to_string(),
            "Play ops/apply-web-abc-1 (phase Running): phase changed before the transition"
        );

        assert_eq!(
            ReconcileError::record_mismatch(&record(""), "has no name").to_string(),
            "Play ops/<unnamed>: has no name"
        );
    }

    /// The fix for a foreign Job at a run's name is deleting that Job, so the message has to name it.
    #[test]
    fn a_job_mismatch_names_the_job() {
        let mut job = Job::default();
        job.metadata.namespace = Some("ops".into());
        assert_eq!(
            ReconcileError::job_mismatch(&job, "has no run ID").to_string(),
            "Job ops/<unnamed>: has no run ID"
        );

        job.metadata.name = Some("apply-web-abc-3".into());
        assert_eq!(
            ReconcileError::job_mismatch(&job, "does not carry this run's identity").to_string(),
            "Job ops/apply-web-abc-3: does not carry this run's identity"
        );
    }

    #[test]
    fn taken_run_names_name_the_range() {
        let error = ReconcileError::RunNamesTaken {
            namespace: "ops".into(),
            first: "apply-web-abc-4".into(),
            last: "apply-web-abc-19".into(),
        };
        assert_eq!(
            error.to_string(),
            "run names apply-web-abc-4 to apply-web-abc-19 in namespace ops are all held by Jobs \
             or Plays this plan did not create; delete the ones that are not the operator's"
        );
    }

    /// The fix for two in-flight records is deleting the stray one, so the message has to say
    /// which records are competing.
    #[test]
    fn concurrent_active_records_name_every_record() {
        let (first, second) = (record("apply-web-abc-1"), record("apply-web-abc-2"));
        assert_eq!(
            ReconcileError::concurrent_active_records(&[&first, &second]).to_string(),
            "more than one Play in namespace ops claims to be the plan's active run: \
             apply-web-abc-1, apply-web-abc-2"
        );
    }
}
