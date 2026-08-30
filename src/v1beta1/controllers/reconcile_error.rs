use crate::v1beta1::ansible;

#[derive(thiserror::Error, Debug)]
pub enum ReconcileError {
    #[error(transparent)]
    KubeError(#[from] kube::Error),

    #[error("Precondition failed: {0}")]
    PreconditionFailed(&'static str),

    #[error("Inventory group {group:?} sets variable {key:?}, which the operator manages")]
    ReservedInventoryVariable { group: String, key: String },

    #[error("Referenced {kind} {name:?} does not exist")]
    InventoryNotFound { kind: &'static str, name: String },

    #[error("Referenced Secret {name:?} does not exist")]
    SecretNotFound { name: String },

    #[error("spec.template.files entry {name:?} is not usable: {reason}")]
    InvalidFileEntry { name: String, reason: &'static str },

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
}
