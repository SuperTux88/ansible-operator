mod callback_output;
mod execution_evaluator;
mod job_builder;
mod locking;
mod managed_ssh;
mod mappers;
mod node_access;
mod node_readiness;
mod paths;
mod play_history;
pub mod reconciler;
mod status;
mod triggers;
mod workspace;

/// The operator-tunable readiness-grace policy for managed-ssh proxy pods, built from config in
/// `main.rs` and threaded into the reconciler. Re-exported so `main.rs` can name it without exposing
/// the rest of the (private) `managed_ssh` module.
pub use managed_ssh::ProxyGracePolicy;
