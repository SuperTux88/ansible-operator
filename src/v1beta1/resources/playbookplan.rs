use std::{borrow::Cow, collections::BTreeMap};

use crate::{
    utils::Condition,
    v1beta1::{PositiveInt, ResolvedHosts, UnsignedInt},
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

    /// How many times a failed run may be tried again before the operator stops, counting the first
    /// run — so `1` means no retry. Defaults to 3 for `OneShot` and 1 for `Recurring`.
    ///
    /// The budget covers one *execution*: for `OneShot` the current playbook and inputs, which an
    /// edit resets; for `Recurring` one schedule tick, since the next tick is going to re-apply the
    /// playbook anyway. Every try is a run of its own, with its own `Play` record and its own Job.
    #[schemars(with = "Option<PositiveInt>")]
    pub max_attempts: Option<u32>,

    /// When true, the operator stops starting new runs for this plan — the same idea as a
    /// CronJob's `.spec.suspend`. A run already in progress is left to finish; only the *starting*
    /// of new runs is gated. While suspended the `Suspended` printer column reads `true` and
    /// `.status.nextRun` is cleared; the plan's phase keeps reflecting its underlying state.
    /// Defaults to false.
    #[serde(default)]
    pub suspend: bool,

    /// 5-field cron expression (`minute hour day-of-month month day-of-week`) that tells at which
    /// time the playbook may execute.
    #[schemars(pattern(
        r"^[0-9*/,-]+[ \t]+[0-9*/,-]+[ \t]+[0-9?*/,-]+[ \t]+[0-9A-Za-z*/,-]+[ \t]+[0-9A-Za-z?*/,-]+$"
    ))]
    pub schedule: Option<String>,

    /// IANA time zone for the `schedule` field, if unset UTC is assumed.
    #[schemars(with = "Option<TimeZoneSchema>")]
    pub time_zone: Option<String>,

    /// Grace window, in seconds, after a scheduled tick during which a run may still start. The
    /// operator evaluates the schedule on a requeue rather than exactly on the tick, so this
    /// absorbs the gap between a tick and the next reconcile (e.g. the operator was busy or
    /// restarting). If more than this many seconds pass past a tick without the run starting, that
    /// tick is skipped and the run waits for the next one. The same idea as a CronJob's
    /// `.spec.startingDeadlineSeconds`. A `Recurring` retry shares the original tick's deadline; the
    /// window does not restart when an attempt fails, so time spent running earlier attempts counts
    /// against it. Only affects scheduled (`schedule`) plans. Defaults to 30.
    #[schemars(with = "Option<UnsignedInt>")]
    pub starting_deadline_seconds: Option<u32>,

    /// These host groups will be available in our playbook
    pub inventory_refs: Vec<InventoryRef>,

    /// What this plan makes true on the hosts it converges, for other plans to depend on.
    ///
    /// Setting it opts the plan into Node labelling: every cluster Node this plan applied to
    /// successfully is labelled `<namespace>.plan.ansible.cloudbending.dev/<plan-name>` with the
    /// declared `version`, and another plan's `ClusterInventory` can select on that label to keep
    /// its own runs off hosts that are not ready yet. A plan without `provides` is labelled
    /// nowhere, so nothing unrelated appears on a Node.
    ///
    /// Left an object rather than a bare version string so it can grow a field without a breaking
    /// change.
    pub provides: Option<Provides>,

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

/// The dependency claim a plan publishes onto the Nodes it converged — see
/// [`PlaybookPlanSpec::provides`].
#[derive(Debug, Serialize, Deserialize, Default, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Provides {
    /// What this plan is providing right now, and the value the Node label carries.
    ///
    /// **Part of the execution hash**, which is what makes the label trustworthy: a Node carrying
    /// version X has to have had a run of the revision that *declared* X succeed on it, so bumping
    /// this re-applies the playbook everywhere before any label moves. Adding or removing
    /// `provides` re-runs the plan once for the same reason. It is also the only way to roll out a
    /// new binary that ships inside the plan's `image`, since the image is not hashed.
    ///
    /// A plan whose playbook must not re-run on every release therefore wants a version of its own
    /// rather than the chart's.
    ///
    /// Any valid Kubernetes label value is accepted, but `Gt`/`Ge`/`Lt`/`Le` selectors read it as a
    /// SemVer version, so a value that is not one only ever matches `Exists`, `In` and `NotIn`.
    /// SemVer build metadata cannot be expressed — `+` is not a legal label value character — so
    /// follow Helm's own `helm.sh/chart` convention and write it as `_`, piping the chart version
    /// through `replace "+" "_"` where a chart renders this field.
    #[schemars(
        length(max = 63),
        pattern(r"^[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$")
    )]
    pub version: String,
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
    Secret {
        name: String,
        secret_ref: FilesSecretRef,
        #[serde(flatten)]
        extra: BTreeMap<String, serde_json::Value>,
    },
    Other {
        name: String,
        #[serde(flatten)]
        extra: BTreeMap<String, serde_json::Value>,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FilesSecretRef {
    pub name: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
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

    /// The latest run reached and applied the playbook to every host it *could* reach, and the only
    /// hosts left over were ones nothing could connect to.
    ///
    /// A failure, and counted as one everywhere the budget and the schedule ask — but a different
    /// one from `Failed`, which means something the operator did reach did not work. Nothing here is
    /// wrong with the playbook: a machine is down, or a `StaticInventory` host is refusing
    /// connections. The plan is waiting for hardware, not for someone to fix it, and reporting that
    /// as `Failed` made a healthily-waiting plan indistinguishable at a glance from a broken one.
    ///
    /// Requires *every* non-succeeded host to be `Unreachable`. One host that ran a task and failed,
    /// or one the play stopped short of, makes the run `Failed` — the unreachable hosts are then not
    /// the whole story.
    HostsUnreachable,

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
    /// for. This is an observable run-start marker only; the trigger gate uses the slot-scoped retry
    /// budget and immutable `Play` records instead. Cleared whenever `currentHash` changes, so an
    /// edit takes effect inside the window it was made in; `None` for unscheduled plans.
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
    /// How many tries the current execution has spent of its `spec.maxAttempts` budget, the latest
    /// run included. Unlike `lastRunNumber` this counts, and it counts within one execution only:
    /// it restarts at 1 whenever `currentHash` changes and, for `Recurring` plans, whenever a new
    /// schedule tick starts a run — the two events that begin a new execution. A successful
    /// `OneShot` execution resets it to 0 so newly eligible hosts can begin a new execution.
    ///
    /// Written from the run's own `Play` record, so a status that lags a run in flight cannot hand
    /// the budget back by forgetting a try that was already made.
    #[serde(default)]
    #[schemars(with = "UnsignedInt")]
    pub retry_count: u32,
    /// The schedule slot to which `retryCount` belongs. Set for scheduled runs and used by
    /// `Recurring` plans to distinguish retries in the current tick from the first attempt in the
    /// next one. `None` for an execution that has not started or an unscheduled run.
    #[serde(default, with = "crate::v1beta1::resources::custom_rfc3339")]
    #[schemars(with = "Option<String>")]
    pub retry_count_slot: Option<DateTime<FixedOffset>>,
    /// Fingerprint of the SSH key material this plan's `StaticInventory` hosts are reached with,
    /// as it was when the plan last looked. Absent for a plan that reaches no such hosts.
    ///
    /// Deliberately *not* part of `currentHash`. That hash decides which hosts are outdated, so
    /// folding a key into it would re-apply the playbook to every host that is already current —
    /// rotating a key changes how the operator connects, not what it applies. Kept beside the hash
    /// instead, this notices the rotation without claiming a new revision: a plan whose last run
    /// did not succeed gets its `retryCount` back, because the old key may well be why it failed,
    /// and `lastAppliedHash` still keeps the run off the hosts that are already converged.
    #[serde(default)]
    pub observed_ssh_key_revision: Option<String>,
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
    /// Which try of the current execution this run is — see `status.retryCount`.
    #[schemars(with = "UnsignedInt")]
    pub attempt: u32,
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
    /// When `lastAppliedHash` was stamped — moved by exactly the outcome that moves that field, and
    /// by no other. This is what separates it from `lastTransitionTime`, which records every
    /// outcome, successful or not.
    ///
    /// Absent on a record written before this field existed. See the `#[serde(default, ...)]` note
    /// on `PlaybookPlanStatus::next_run`.
    #[serde(default, with = "crate::v1beta1::resources::custom_rfc3339")]
    #[schemars(with = "Option<String>")]
    pub applied_at: Option<DateTime<FixedOffset>>,
    /// The `metadata.uid` of the host's Node when `lastAppliedHash` was stamped — moved by exactly
    /// the outcome that moves that field, and by no other.
    ///
    /// It exists because `hostsStatus` is keyed by host *name*, and the name is all a replacement
    /// machine inherits: without it, a Node deleted and re-registered under the same name would keep
    /// the claim its predecessor earned, and a `OneShot` plan would never run on the fresh machine.
    /// A Node with a different uid is a different machine, and its recorded application is dropped
    /// — see `node_recreation`.
    ///
    /// Identity rather than time: comparing the Node's `creationTimestamp` against `appliedAt` would
    /// weigh the apiserver's clock against the operator's, and an operator running behind would drop
    /// the claim it had just written for a freshly joined Node — a success that re-runs for ever.
    ///
    /// Absent for a host that had no Node in the cache when it succeeded, and on a record written
    /// before this field existed. Such a record is never treated as a replacement, or the upgrade
    /// that introduced the field would re-run every plan across the fleet, and it is never labelled
    /// either; the next success fills it in.
    ///
    /// Absent, too, for a host the plan reaches only through a `StaticInventory`: a Node that
    /// happens to share its name is not that machine.
    #[serde(default)]
    pub applied_node_uid: Option<String>,
    /// The `spec.provides` version of the revision that stamped `lastAppliedHash` — moved by exactly
    /// the same outcome, and taken from that run's own `Play` rather than from the plan as it reads
    /// now.
    ///
    /// This is what a Node label is derived from, which is why it is recorded per host instead of
    /// read from the spec: the plan converges one host at a time, so at any moment some hosts carry
    /// the new revision and some still carry the old one, and each must be labelled with what it
    /// actually has.
    ///
    /// Absent for a plan that provides nothing, and absent on a record stamped before this field
    /// existed. A host with no version here is never labelled — see `node_labels`.
    #[serde(default)]
    pub applied_version: Option<String>,
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
    /// Ansible connected to the host and a task failed on it.
    Failed,
    /// Nothing could open a connection to the host, so no task ran on it — a `StaticInventory` host
    /// that is down or refusing the key, or a cluster Node that was itself not `Ready`, which the
    /// run excludes rather than dialling.
    ///
    /// Distinct from `Failed` because the two are fixed in different places. Distinct from
    /// `NotReached` because something has to come back for this host before anything can be
    /// attempted on it, and the operator is watching for exactly that: a Node returning to `Ready`
    /// wakes the plan. A host whose connection dropped part-way through, leaving both failed and
    /// unreachable tasks behind, reads `Failed`: something did run and did fail, which is the more
    /// actionable half.
    Unreachable,
    /// The host was in scope for this run, nothing was attempted on it, and no Node coming back will
    /// change that. Two causes, one answer:
    ///
    /// - an earlier host in its `serial` batch stopped the play, so the fix is on *that* host;
    /// - the run excluded it because its managed-ssh proxy pod never came up on a Node that was
    ///   itself `Ready` — an untolerated taint, a failing image pull, a rejecting admission webhook.
    ///   The fix is in the pod's scheduling, not on the Node.
    ///
    /// What they share is the part the operator acts on: this host's own `Ready` heartbeats carry no
    /// news, so `mappers::plan_awaits_node` leaves it out of the Node watch's wake set. Contrast
    /// `Unreachable`, where a Node returning is precisely what resolves it.
    NotReached,
    /// Ansible ran tasks on the host, none of them failed, and the playbook still stopped before
    /// reaching the end for it — an `any_errors_fatal` abort, a failed `serial` batch, a
    /// `max_fail_percentage` rollout halt. Some other host is what failed.
    ///
    /// This host received *part* of the playbook. Its counters look exactly like a host that
    /// received all of it — that is the whole reason the outcome exists — so it is deliberately not
    /// `Succeeded`, and the run does not record the playbook as applied to it. Fix whatever failed
    /// elsewhere in the run; this host is re-applied on the next one.
    Incomplete,
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
    /// The version this plan declares in `spec.provides`, if it declares one.
    ///
    /// One accessor rather than the field read spelled out at each site: the version is read by the
    /// execution hash, by the run record that a host's claim is later dated against, and by the Node
    /// label diff. Those three answering differently is the one disagreement this design has no room
    /// for — the label would then claim a revision that never ran.
    pub fn provides_version(&self) -> Option<&str> {
        self.spec
            .provides
            .as_ref()
            .map(|provides| provides.version.as_str())
    }

    pub fn timezone(&self) -> Result<Tz, chrono_tz::ParseError> {
        self.spec
            .time_zone
            .as_ref()
            .map(|tz| tz.parse::<Tz>())
            .unwrap_or(Ok(Tz::UTC))
    }
}

struct TimeZoneSchema;

impl JsonSchema for TimeZoneSchema {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("TimeZone")
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({
            "type": "string",
            "enum": chrono_tz::TZ_VARIANTS
                .iter()
                .map(|time_zone| time_zone.name())
                .collect::<Vec<_>>()
        })
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
    fn crd_rejects_non_five_field_schedules_and_unknown_time_zones() {
        use kube::CustomResourceExt as _;

        let crd = serde_json::to_value(PlaybookPlan::crd()).unwrap();
        let spec = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"];

        assert_eq!(
            spec["schedule"]["pattern"],
            r"^[0-9*/,-]+[ \t]+[0-9*/,-]+[ \t]+[0-9?*/,-]+[ \t]+[0-9A-Za-z*/,-]+[ \t]+[0-9A-Za-z?*/,-]+$"
        );

        let time_zones = spec["timeZone"]["enum"].as_array().unwrap();
        assert!(time_zones.contains(&serde_json::json!("UTC")));
        assert!(time_zones.contains(&serde_json::json!("Europe/Berlin")));
        assert!(!time_zones.contains(&serde_json::json!("Nowhere")));

        let required = crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]
            ["spec"]["required"]
            .as_array()
            .unwrap();
        assert!(!required.contains(&serde_json::json!("timeZone")));
    }

    /// `provides.version` is written verbatim into a Node label value, so admission is where a value
    /// that cannot be one has to be refused. Letting it through would leave the plan running happily
    /// and only failing at the label patch, on a Node, with an error about a field the user would
    /// have to work backwards to.
    #[test]
    fn crd_only_accepts_a_version_that_can_be_a_label_value() {
        use kube::CustomResourceExt as _;

        let crd = serde_json::to_value(PlaybookPlan::crd()).unwrap();
        let spec = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"];
        let provides = &spec["properties"]["provides"];

        assert_eq!(provides["properties"]["version"]["maxLength"], 63);
        let pattern = provides["properties"]["version"]["pattern"]
            .as_str()
            .expect("the version carries a label-value pattern");

        let pattern = regex::Regex::new(pattern).unwrap();
        let accepts = |value: &str| pattern.is_match(value);
        assert!(accepts("1.4.2"));
        assert!(accepts("1"));
        assert!(accepts("v1.4.0-rc.1"));
        assert!(
            accepts("1.4.2_a1b2c3"),
            "the Helm build-metadata convention"
        );
        assert!(!accepts(""), "an empty version tells a dependent nothing");
        assert!(
            !accepts("1.4.2+a1b2c3"),
            "'+' is not a label value character"
        );
        assert!(!accepts(".1.4.2"), "a label value starts alphanumeric");
        assert!(!accepts("1.4.2-"), "and ends alphanumeric");

        assert!(
            !spec["required"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("provides")),
            "a plan that provides nothing is the normal case"
        );
        assert_eq!(
            provides["required"],
            serde_json::json!(["version"]),
            "provides without a version would label a Node with nothing"
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
                max_attempts: None,
                suspend: false,
                schedule: Some("0 1 * * *".into()),
                time_zone: None,
                starting_deadline_seconds: None,
                inventory_refs: vec![InventoryRef {
                    cluster_inventory: Some("controlplanes".into()),
                    static_inventory: Some("others".into()),
                }],
                provides: None,
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
                        secret_ref: FilesSecretRef {
                            name: "secret-with-files".into(),
                            extra: BTreeMap::new(),
                        },
                        extra: BTreeMap::new(),
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
                secret_ref: _,
                extra: _
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
