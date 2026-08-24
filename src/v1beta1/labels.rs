pub const PLAYBOOKPLAN_NAME: &str = "ansible.cloudbending.dev/playbookplan";
pub const PLAYBOOKPLAN_HOST: &str = "ansible.cloudbending.dev/target-host";
pub const PLAYBOOKPLAN_HASH: &str = "ansible.cloudbending.dev/hash";
pub const RUN_ID: &str = "ansible.cloudbending.dev/run-id";

/// The `Play` UID correlating a run to its Job and that Job's pod template.
///
/// Annotation (not label): for exact-value comparison only. Never use in `LabelSelector`.
pub const PLAY_UID_ANNOTATION: &str = "ansible.cloudbending.dev/play-uid";

pub const COMPONENT: &str = "ansible.cloudbending.dev/component";
pub const MANAGED_SSH_PROXY_COMPONENT: &str = "managed-ssh-proxy";
pub const PLAYBOOK_COMPONENT: &str = "playbook";
