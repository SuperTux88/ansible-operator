use std::{borrow::Cow, collections::BTreeMap};

use crate::{
    utils::Condition,
    v1beta1::{ResolvedHosts, UnsignedInt},
};
use chrono::{DateTime, FixedOffset};
use chrono_tz::Tz;
use kube::CustomResource;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
#[serde(transparent)]
pub struct GenericMap(pub serde_json::Value);

impl JsonSchema for GenericMap {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("GenericMap")
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        serde_json::from_value(serde_json::json!({
            "type": "object",
            "x-kubernetes-preserve-unknown-fields": true
        }))
        .unwrap()
    }
}

/// Cap on a plan's own object name, enforced at admission by the CRD rule below and re-checked by
/// the reconciler for clusters that do not evaluate such rules.
///
/// Kubernetes would allow the full DNS *subdomain* length here, but the plan's name is written as a
/// **label value** onto every object a run creates — its `Play`, its Job, that Job's pod template and
/// the run's egress NetworkPolicy — and label values stop at 63 characters. Without this cap a longer
/// name is accepted happily and then fails at the first of those creates, with an error naming a
/// label the user never wrote. See `reconciler::plan_name_within_label_limit`.
pub const MAX_PLAN_NAME_LEN: usize = 63;

#[derive(CustomResource, Debug, Serialize, Deserialize, Default, Clone, JsonSchema)]
#[kube(
    group = "ansible.cloudbending.dev",
    version = "v1beta1",
    kind = "PlaybookPlan",
    namespaced,
    status = "PlaybookPlanStatus",
    // Root-level rule: `self` is the whole object, and `metadata.name` is one of the few metadata
    // fields CEL can always reach from here. See `MAX_PLAN_NAME_LEN` for why the cap exists, and
    // `deployment.md` for the same caveat the `Play` rule carries — an API server that does not
    // evaluate validation rules ignores this silently rather than rejecting it, which is why the
    // reconciler checks it too.
    validation = Rule::new("!has(self.metadata.name) || self.metadata.name.size() <= 63")
        .message("PlaybookPlan name must be at most 63 characters: it is used as a label value on the objects each run creates"),
    printcolumn = r#"{"name":"Mode","type":"string","jsonPath":".spec.mode"}"#,
    printcolumn = r#"{"name":"Schedule","type":"string","jsonPath":".spec.schedule"}"#,
    printcolumn = r#"{"name":"Suspended","type":"boolean","jsonPath":".spec.suspend"}"#,
    printcolumn = r#"{"name":"Previous run","type":"string","jsonPath":".status.lastTriggeredRun"}"#,
    printcolumn = r#"{"name":"Next run","type":"string","jsonPath":".status.nextRun"}"#,
    printcolumn = r#"{"name":"Current hash","type":"string","jsonPath":".status.currentHash"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Running","type":"string","jsonPath":".status.conditions[?(@.type==\"Running\")].status"}"#,
    printcolumn = r#"{"name":"Summary","type":"string","jsonPath":".status.summary"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct PlaybookPlanSpec {
    /// An OCI image with Ansible and all required collections
    pub image: String,

    /// Container security context applied to both the Ansible playbook container and the optional
    /// collection-installer init container. Optional for compatibility with arbitrary execution
    /// images; cluster admission policies may require particular fields.
    pub security_context: Option<PlaybookSecurityContext>,

    /// ServiceAccount the playbook pod runs as, letting tasks reach the Kubernetes API with that
    /// identity's RBAC. When set, the SA's token is auto-mounted (Ansible's `kubernetes.core`
    /// modules pick it up via in-cluster config). When unset, the pod runs with no API token at
    /// all — create the ServiceAccount and its Role/RoleBinding yourself and name it here.
    pub service_account_name: Option<String>,

    /// Verbosity for `ansible-playbook`, mapped to `-v`…`-vvvv`. 0 (unset) adds no flag; values
    /// above 4 are clamped to 4. Affects log detail only — it is not part of the execution hash, so
    /// changing it does not re-run the playbook on already-current hosts.
    #[schemars(with = "Option<UnsignedInt>")]
    pub verbosity: Option<u8>,

    /// Controls if a playbook is executed once or repeatedly
    #[schemars(default)]
    pub mode: ExecutionMode,

    /// When true, the operator stops starting new runs for this plan — the same idea as a
    /// CronJob's `.spec.suspend`. A run already in progress is left to finish; only the *starting*
    /// of new runs is gated. While suspended the `Suspended` printer column reads `true` and
    /// `.status.nextRun` is cleared; the plan's phase keeps reflecting its underlying state.
    /// Defaults to false.
    #[serde(default)]
    pub suspend: bool,

    /// 5-part cron expression that tells at which time the playbook may execute
    pub schedule: Option<String>,

    /// Time zone for the _schedule_ field, if unset UTC is assumed
    pub time_zone: Option<String>,

    /// Grace window, in seconds, after a scheduled tick during which a run may still start. The
    /// operator evaluates the schedule on a requeue rather than exactly on the tick, so this
    /// absorbs the gap between a tick and the next reconcile (e.g. the operator was busy or
    /// restarting). If more than this many seconds pass past a tick without the run starting, that
    /// tick is skipped and the run waits for the next one. The same idea as a CronJob's
    /// `.spec.startingDeadlineSeconds`. Only affects scheduled (`schedule`) plans. Defaults to 30.
    #[schemars(with = "Option<UnsignedInt>")]
    pub starting_deadline_seconds: Option<u32>,

    /// These host groups will be available in our playbook
    pub inventory_refs: Vec<InventoryRef>,

    /// How long a finished run's Job (and its pod) is kept before Kubernetes' TTL controller
    /// reaps it. Reaping a finished run is left entirely to that controller, so this governs the
    /// ansible pod's lifetime. The one Job the operator deletes itself is the Job of a run still in
    /// flight when its plan is deleted, which is cancelled rather than left running; such a run
    /// never reaches this TTL. Values below 60 seconds are silently raised to 60; unset uses the
    /// operator's default.
    pub ttl_seconds_after_finished: Option<i32>,

    /// How many successful `Play` history records to keep for this plan before the oldest are
    /// pruned. Unlike the Job's short TTL, Plays are the durable run history. A terminal result is
    /// temporarily exempt until it reaches the plan status. Defaults to 3.
    #[schemars(with = "Option<UnsignedInt>")]
    pub successful_plays_history_limit: Option<u32>,

    /// How many failed (or outcome-unknown) `Play` history records to keep for this plan. Kept
    /// larger than the successful limit so failures stay visible longer. A terminal result is
    /// temporarily exempt until it reaches the plan status; an aborted run is deleted only
    /// after its resources are cleaned up. Defaults to 10.
    #[schemars(with = "Option<UnsignedInt>")]
    pub failed_plays_history_limit: Option<u32>,

    /// The playbook will be built from this, some fields will be set automatically (vars, hosts)
    pub template: PlaybookTemplate,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct InventoryRef {
    /// Name of the ClusterInventory resource being referenced
    pub cluster_inventory: Option<String>,
    /// Name of the StaticInventory resource being referenced
    pub static_inventory: Option<String>,
}

/// Kubernetes container security settings for the playbook execution image.
#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PlaybookSecurityContext {
    pub allow_privilege_escalation: Option<bool>,
    pub app_armor_profile: Option<SecurityProfile>,
    pub capabilities: Option<ContainerCapabilities>,
    pub privileged: Option<bool>,
    pub proc_mount: Option<String>,
    pub read_only_root_filesystem: Option<bool>,
    pub run_as_group: Option<i64>,
    pub run_as_non_root: Option<bool>,
    pub run_as_user: Option<i64>,
    pub se_linux_options: Option<ContainerSeLinuxOptions>,
    pub seccomp_profile: Option<SecurityProfile>,
    pub windows_options: Option<ContainerWindowsOptions>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContainerCapabilities {
    pub add: Option<Vec<String>>,
    pub drop: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecurityProfile {
    pub localhost_profile: Option<String>,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContainerSeLinuxOptions {
    pub level: Option<String>,
    pub role: Option<String>,
    #[serde(rename = "type")]
    pub type_: Option<String>,
    pub user: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContainerWindowsOptions {
    pub gmsa_credential_spec: Option<String>,
    pub gmsa_credential_spec_name: Option<String>,
    pub host_process: Option<bool>,
    pub run_as_user_name: Option<String>,
}

impl From<&PlaybookSecurityContext> for k8s_openapi::api::core::v1::SecurityContext {
    fn from(value: &PlaybookSecurityContext) -> Self {
        Self {
            allow_privilege_escalation: value.allow_privilege_escalation,
            app_armor_profile: value.app_armor_profile.as_ref().map(|profile| {
                k8s_openapi::api::core::v1::AppArmorProfile {
                    localhost_profile: profile.localhost_profile.clone(),
                    type_: profile.type_.clone(),
                }
            }),
            capabilities: value.capabilities.as_ref().map(|capabilities| {
                k8s_openapi::api::core::v1::Capabilities {
                    add: capabilities.add.clone(),
                    drop: capabilities.drop.clone(),
                }
            }),
            privileged: value.privileged,
            proc_mount: value.proc_mount.clone(),
            read_only_root_filesystem: value.read_only_root_filesystem,
            run_as_group: value.run_as_group,
            run_as_non_root: value.run_as_non_root,
            run_as_user: value.run_as_user,
            se_linux_options: value.se_linux_options.as_ref().map(|options| {
                k8s_openapi::api::core::v1::SELinuxOptions {
                    level: options.level.clone(),
                    role: options.role.clone(),
                    type_: options.type_.clone(),
                    user: options.user.clone(),
                }
            }),
            seccomp_profile: value.seccomp_profile.as_ref().map(|profile| {
                k8s_openapi::api::core::v1::SeccompProfile {
                    localhost_profile: profile.localhost_profile.clone(),
                    type_: profile.type_.clone(),
                }
            }),
            windows_options: value.windows_options.as_ref().map(|options| {
                k8s_openapi::api::core::v1::WindowsSecurityContextOptions {
                    gmsa_credential_spec: options.gmsa_credential_spec.clone(),
                    gmsa_credential_spec_name: options.gmsa_credential_spec_name.clone(),
                    host_process: options.host_process,
                    run_as_user_name: options.run_as_user_name.clone(),
                }
            }),
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
pub enum ExecutionMode {
    #[default]
    OneShot,
    Recurring,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema)]
pub struct PlaybookTemplate {
    /// The actual playbook contents
    pub playbook: String,

    /// Variables for the playbook
    pub variables: Option<Vec<PlaybookVariableSource>>,

    /// Files for the playbook
    #[schemars(with = "Option<Vec<GenericMap>>")]
    pub files: Option<Vec<FilesSource>>,

    /// Runtime requirements (e.g. Ansible collections)
    pub requirements: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum FilesSource {
    #[serde(rename_all = "camelCase")]
    Secret { name: String, secret_ref: SecretRef },
    Other {
        name: String,
        #[serde(flatten)]
        extra: BTreeMap<String, serde_json::Value>,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "camelCase", untagged)]
pub enum PlaybookVariableSource {
    /// Extra variables to read from a secret. These must be within `.data."variables.yaml"`.
    #[serde(rename_all = "camelCase")]
    SecretRef {
        secret_ref: SecretRef,
    },
    Inline {
        inline: GenericMap,
    },
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretRef {
    pub name: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
pub enum Phase {
    /// Triggers have not yet been evaluated
    #[default]
    Pending,

    /// The plan is waiting for its scheduled time, and the current playbook and inputs have not
    /// produced a result yet. Once a run has finished, its `Succeeded`/`Failed` verdict is what the
    /// plan reports between runs, with `nextRun` naming the next one.
    Delayed,

    /// Playbook has not yet been applied to all hosts.
    Applying,

    /// The latest run did not succeed on every host it targeted, or its recap could not be read.
    /// A `Recurring` plan keeps this result between schedule ticks, with `nextRun` naming the next
    /// one. Also set when the plan is refused outright, e.g. for a name that is too long.
    Failed,

    /// Every host the latest run targeted succeeded. A `Recurring` plan keeps this result between
    /// schedule ticks, with `nextRun` naming the next one.
    Succeeded,

    /// The PlaybookPlan's namespace is not enrolled for the operator (not in the chart's
    /// `watchNamespaces`), so the operator has no RBAC to read its Secrets or create its Job and
    /// refuses to run it. Terminal until an administrator enrols the namespace and the operator
    /// restarts (see R1 / T-INFO-1).
    UnauthorizedNamespace,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PlaybookPlanStatus {
    /// The run that is currently being applied, independent of the newly desired execution hash.
    /// This remains stable while a spec change queues a replacement run, so the old Job, locks, and
    /// managed-ssh resources continue to be reconciled until the run finishes.
    ///
    /// Only what finishing that run needs: everything else about it lives in its immutable `Play`,
    /// which is the record recovery reads. This copy is what lets the operator still release a run
    /// whose `Play` was deleted out from under it.
    pub active_run: Option<ActiveRun>,
    pub eligible_hosts: Vec<ResolvedHosts>,
    /// The plan generation the workspace Secret was last rendered from — informational only.
    ///
    /// It is deliberately *not* a "needs re-render" gate: the workspace embeds the live proxy pod
    /// IPs, which are fresh every time a run's infrastructure is built, so it is rewritten whenever
    /// a run reaches that point regardless of whether the spec changed. Reintroducing a gate here
    /// would let a run mount an inventory pointing at a previous run's pods.
    pub last_rendered_generation: Option<i64>,
    pub conditions: Vec<PlaybookPlanCondition>,
    pub hosts_status: Option<BTreeMap<String, HostStatus>>,
    // `default` is required, not just nice-to-have: status patches are JSON Merge Patches, where
    // a `null` value deletes the key rather than setting it to null, so this key is genuinely
    // absent whenever `None`. `#[serde(with = ...)]` opts out of serde's usual missing-`Option`
    // tolerance, so `default` must be added back explicitly or deserialization hard-fails.
    #[serde(default, with = "crate::v1beta1::resources::custom_rfc3339")]
    #[schemars(with = "Option<String>")]
    pub next_run: Option<DateTime<FixedOffset>>,
    /// The start of the schedule slot (`Timing::Now`'s window start) that a run was last started
    /// for. The trigger gate compares the current slot against this so a run that completes inside
    /// its grace window isn't immediately re-triggered by the next reconcile within that same
    /// window. Cleared whenever `currentHash` changes, so an edit takes effect inside the window it
    /// was made in; `None` for unscheduled plans (no slot to dedupe against).
    #[serde(default, with = "crate::v1beta1::resources::custom_rfc3339")]
    #[schemars(with = "Option<String>")]
    pub last_triggered_run: Option<DateTime<FixedOffset>>,
    pub phase: Phase,
    pub current_hash: String,
    pub summary: Option<String>,
    /// The highest run number this plan has handed out, which is what keeps the Job name
    /// (`apply-{plan}-{shortid}-{n}`) unique across runs of an unchanged spec. Reset to 0 whenever
    /// `currentHash` changes, but that reset only ever lowers the *starting point*: a new run is
    /// numbered past every run still claiming a name — all of this plan's Jobs and all of its
    /// retained `Play` records, whatever revision they belong to — so it can advance by more than
    /// one, and a new revision does not restart at 1 while earlier runs are still retained. Names
    /// are reserved plan-wide rather than per revision because the short id truncates a hash over
    /// the plan and the revision, so two revisions of one plan can share one; see
    /// `reconciler::select_job`.
    ///
    /// A high-water mark, not a count of runs: a run abandoned before its Job existed is not
    /// deducted, so its number stays reserved for as long as this field outlives its `Play`.
    #[schemars(with = "UnsignedInt")]
    pub last_run_number: u32,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ActiveRun {
    /// The execution hash used to create this run's Job and infrastructure.
    pub execution_hash: String,
    /// Stable per-run resource/cleanup identity, distinct even across same-hash retries.
    pub run_id: String,
    /// The Job backing this run, which is also the name of its `Play`.
    pub job_name: String,
    /// UID of the immutable `Play` recovery record correlated with the Job and its pod template.
    pub play_uid: String,
    /// Hosts targeted by this run, preserved even if the desired inventory changes while it runs.
    pub hosts: Vec<String>,
    /// Run number represented by `jobName`.
    #[schemars(with = "UnsignedInt")]
    pub run_number: u32,
    /// Start of the schedule slot consumed by this run, if it is scheduled.
    #[serde(default, with = "crate::v1beta1::resources::custom_rfc3339")]
    #[schemars(with = "Option<String>")]
    pub triggered_slot: Option<DateTime<FixedOffset>>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HostStatus {
    /// The execution hash last SUCCESSFULLY applied to this host. Only bumped on `HostOutcome::Succeeded`.
    pub last_applied_hash: String,
    pub last_outcome: HostOutcome,
    // See the `#[serde(default, ...)]` note on `PlaybookPlanStatus::next_run`.
    #[serde(default, with = "crate::v1beta1::resources::custom_rfc3339")]
    #[schemars(with = "Option<String>")]
    pub last_transition_time: Option<DateTime<FixedOffset>>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
pub enum HostOutcome {
    /// The callback's output was missing or malformed for this run — distinct from `NotReached`:
    /// this means the operator's own instrumentation broke, not that Ansible legitimately skipped the host.
    #[default]
    Unknown,
    Succeeded,
    Failed,
    /// The host was in scope for this run but Ansible never reached it (e.g. an earlier host in its
    /// `serial` batch stopped the play).
    NotReached,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PlaybookPlanCondition {
    #[serde(rename = "type")]
    pub type_: String,
    pub status: String,
    pub reason: Option<String>,
    pub message: Option<String>,
    // See the identical `#[serde(default, ...)]` note on `PlaybookPlanStatus::next_run`.
    #[serde(default, with = "crate::v1beta1::resources::custom_rfc3339")]
    #[schemars(with = "Option<String>")]
    pub last_transition_time: Option<DateTime<FixedOffset>>,
}

impl Condition for PlaybookPlanCondition {
    fn type_(&self) -> &str {
        &self.type_
    }

    fn status(&self) -> &str {
        &self.status
    }

    fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    fn last_transition_time(&self) -> Option<DateTime<FixedOffset>> {
        self.last_transition_time
    }

    fn set_last_transition_time(&mut self, value: Option<DateTime<FixedOffset>>) {
        self.last_transition_time = value;
    }
}

impl PlaybookPlan {
    pub fn timezone(&self) -> Result<Tz, chrono_tz::ParseError> {
        self.spec
            .time_zone
            .as_ref()
            .map(|tz| tz.parse::<Tz>())
            .unwrap_or(Ok(Tz::UTC))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plan-name cap has to reach the API server as a rule on the *root* of the object: only
    /// there can CEL see `metadata.name`, and the spec is where a rule would otherwise land. The
    /// reconciler enforces the same bound for clusters that ignore validation rules, so this pins
    /// the admission-time half — the one that gives the user the error at `kubectl apply`.
    #[test]
    fn crd_caps_the_plan_name_at_the_label_value_limit() {
        use kube::CustomResourceExt as _;

        let crd = serde_json::to_value(PlaybookPlan::crd()).unwrap();
        let root = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"];
        let validations = root["x-kubernetes-validations"].as_array().unwrap();

        let rule = validations
            .iter()
            .find(|validation| {
                validation["rule"]
                    .as_str()
                    .is_some_and(|rule| rule.contains("metadata.name"))
            })
            .expect("the plan-name rule is on the root schema, not the spec");

        assert_eq!(
            rule["rule"],
            format!("!has(self.metadata.name) || self.metadata.name.size() <= {MAX_PLAN_NAME_LEN}"),
            "the rule must state the same bound the reconciler enforces"
        );
        assert!(
            rule["message"]
                .as_str()
                .is_some_and(|message| message.contains("label value")),
            "the message has to say why, or the cap reads as arbitrary"
        );
    }

    #[test]
    fn test_serialization() {
        let playbookplan = PlaybookPlan::new(
            "blubb",
            PlaybookPlanSpec {
                image: "registry.tld/ansible:1.0.0".to_string(),
                security_context: None,
                service_account_name: None,
                verbosity: None,
                mode: ExecutionMode::Recurring,
                suspend: false,
                schedule: Some("0 1 * * *".into()),
                time_zone: None,
                starting_deadline_seconds: None,
                inventory_refs: vec![InventoryRef {
                    cluster_inventory: Some("controlplanes".into()),
                    static_inventory: Some("others".into()),
                }],
                ttl_seconds_after_finished: None,
                successful_plays_history_limit: None,
                failed_plays_history_limit: None,
                template: PlaybookTemplate {
                    variables: Some(vec![PlaybookVariableSource::SecretRef {
                        secret_ref: SecretRef {
                            name: "some-secret".into(),
                        },
                    }]),
                    files: Some(vec![FilesSource::Secret {
                        name: "some-name".into(),
                        secret_ref: SecretRef {
                            name: "secret-with-files".into(),
                        },
                    }]),
                    playbook: r#"
- tasks:
    - name: Ensure httpd installed
        ansible.builtin.dnf:
            name: httpd
            state: installed
            "#
                    .into(),
                    ..Default::default()
                },
            },
        );

        let serialized = serde_yaml::to_string(&playbookplan).unwrap();

        println!("{serialized}");
    }

    #[test]
    fn test_deserialization() {
        let yaml = r#"
apiVersion: ansible.cloudbending.dev/v1beta1
kind: PlaybookPlan
metadata:
  name: an-example
spec:
  image: docker.io/serversideup/ansible-core:2.18
  inventoryRefs:
    - name: controlplanes
  mode: OneShot
  template:
    variables:
      - inline:
          key: value
          nested:
            otherkey: othervalue
      - secretRef:
          name: secret-with-variables
    files:
      - name: some-configs
        secretRef:
          name: secret-with-config-files
      - name: binary-assets
        image:
          reference: my.registry.tld/the-image:v2
          pullPolicy: IfNotPresent
    playbook: |
      - hosts: all
        tasks:
          - name: Echo someting
            ansible.builtin.command:
              command: echo Hello
        "#;

        let pp = serde_yaml::from_str::<PlaybookPlan>(yaml).unwrap();

        assert!(pp.spec.template.files.is_some());

        let files = pp.spec.template.files.as_ref().unwrap();

        assert!(matches!(
            files.first().unwrap(),
            FilesSource::Secret {
                name,
                secret_ref: _
            } if name == "some-configs"
        ));

        assert!(matches!(
            files.get(1).unwrap(),
            FilesSource::Other {name, extra: _} if name == "binary-assets"
        ));

        println!("{pp:?}");
    }

    /// Regression test: JSON Merge Patches delete a key entirely rather than setting it null, so
    /// `nextRun`/`lastTransitionTime` are genuinely absent from the stored object when `None`.
    /// Without `#[serde(default)]` this used to fail deserialization with "missing field".
    #[test]
    fn status_deserializes_when_optional_timestamps_are_entirely_absent() {
        let json = serde_json::json!({
            "eligibleHosts": [],
            "lastRenderedGeneration": null,
            "conditions": [{
                "type": "Ready",
                "status": "True",
                "reason": null,
                "message": null
                // lastTransitionTime deliberately omitted
            }],
            "hostsStatus": {
                "some-host": {
                    "lastAppliedHash": "",
                    "lastOutcome": "Unknown"
                    // lastTransitionTime deliberately omitted
                }
            },
            // nextRun deliberately omitted
            "phase": "Applying",
            "currentHash": "abc123",
            "summary": null,
            "lastRunNumber": 1
        });

        let status: PlaybookPlanStatus = serde_json::from_value(json).unwrap();

        assert_eq!(status.next_run, None);
        assert_eq!(
            status.conditions.first().unwrap().last_transition_time,
            None
        );
        assert_eq!(
            status.hosts_status.unwrap()["some-host"].last_transition_time,
            None
        );
    }
}
