pub const PLAYBOOKPLAN_NAME: &str = "ansible.cloudbending.dev/playbookplan";

/// The host a run-scoped resource serves, used as **both** a label and an annotation key.
///
/// The label carries the host bounded to a label value (`managed_ssh::host_segment`), which for a
/// Node name over 63 characters is a truncated form with a hash — it is what the resource is named
/// after, and what a selector matches. The annotation carries the Node name verbatim, whatever its
/// length. One key, because they answer the same question and a reader meeting both should see at a
/// glance that one is the other, shortened.
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
