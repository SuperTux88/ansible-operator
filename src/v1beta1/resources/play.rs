use std::collections::BTreeMap;

use chrono::{DateTime, FixedOffset};
use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1beta1::{HostOutcome, ResolvedHosts, UnsignedInt};

/// An immutable per-run recovery and history record. It is written before Job creation, advances
/// from preparation through execution, and retains the terminal recap after the Job is reaped.
///
/// Owned (ownerReference) by its `PlaybookPlan`, so deleting the plan cascades to all its Plays;
/// retention beyond that is bounded per-plan by `successfulPlaysHistoryLimit`/
/// `failedPlaysHistoryLimit`. The Job and pod template carry this Play's UID for correlation.
#[derive(CustomResource, Debug, Serialize, Deserialize, Default, Clone, KubeSchema)]
#[kube(
    group = "ansible.cloudbending.dev",
    version = "v1beta1",
    kind = "Play",
    namespaced,
    status = "PlayStatus",
    printcolumn = r#"{"name":"Plan","type":"string","jsonPath":".spec.playbookPlan"}"#,
    printcolumn = r#"{"name":"Run","type":"integer","jsonPath":".spec.runNumber","priority":1}"#,
    printcolumn = r#"{"name":"Hosts","type":"integer","jsonPath":".status.hostCount"}"#,
    printcolumn = r#"{"name":"Ok","type":"integer","jsonPath":".status.recap.ok"}"#,
    printcolumn = r#"{"name":"Changed","type":"integer","jsonPath":".status.recap.changed"}"#,
    printcolumn = r#"{"name":"Failed","type":"integer","jsonPath":".status.recap.failed"}"#,
    printcolumn = r#"{"name":"Unreachable","type":"integer","jsonPath":".status.recap.unreachable"}"#,
    printcolumn = r#"{"name":"Rescued","type":"integer","jsonPath":".status.recap.rescued","priority":1}"#,
    printcolumn = r#"{"name":"Skipped","type":"integer","jsonPath":".status.recap.skipped","priority":1}"#,
    printcolumn = r#"{"name":"Ignored","type":"integer","jsonPath":".status.recap.ignored","priority":1}"#,
    printcolumn = r#"{"name":"Status","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
// Freezes the whole spec. CEL is blind inside `x-kubernetes-preserve-unknown-fields`, so the rule is
// only worth its name because every field below is *typed* — which is possible because the inputs an
// run may be resumed against are reduced to the `preparationFingerprint` hash rather than stored
// verbatim. `crd_makes_the_play_spec_immutable` fails if a schemaless field is ever reintroduced.
// Not the only control: the nodes a resumed run is about to reach are re-authorized against live
// policy before any of them get a proxy pod. See THREAT_MODEL §T-ESC-8.
#[x_kube(validation = Rule::new("self == oldSelf").message("Play spec is immutable"))]
#[serde(rename_all = "camelCase")]
pub struct PlaySpec {
    /// The `PlaybookPlan` this run belongs to (also this Play's ownerReference).
    pub playbook_plan: String,

    /// UID of the owning `PlaybookPlan`. Unlike an ownerReference, this is part of the immutable run
    /// record and prevents a plan recreated with the same name from adopting an older run.
    pub playbook_plan_uid: String,

    /// The execution hash the run applied — matches the backing Job's hash label.
    pub execution_hash: String,

    /// Stable identifier for this run, used to isolate resource names, labels, and cleanup from
    /// other runs that share the same execution hash.
    pub run_id: String,

    /// Fingerprint of all plan and resolved-inventory inputs used while preparing this run.
    ///
    /// This is the run's change detector, and it is why the record carries no copy of the plan spec,
    /// resolved connection configuration or the Job. Everything an unlaunched run needs to be
    /// resumed is a pure function of the live plan spec and the freshly resolved groups, so while
    /// the fingerprint still matches those the inputs can simply be re-derived; once it stops
    /// matching there is nothing worth resuming and the run is aborted in favour of the new
    /// revision. Reducing them to one *typed* field is also what lets the spec's `self == oldSelf`
    /// rule cover the whole record: CEL cannot see into a schemaless field, and there is none here.
    pub preparation_fingerprint: String,

    /// Sequence number reserved across all revisions of this plan: 1 for the first run, then one
    /// past every Job and retained `Play` record still claiming a number. It therefore continues
    /// across plan edits rather than restarting at 1 for a new revision. Mirrors the backing Job's
    /// numbered name (`apply-{plan}-{shortid}-{runNumber}`).
    ///
    /// Not a dense count of this plan's runs: a run abandoned before its Job exists leaves its
    /// number unused whenever the plan's `lastRunNumber` already recorded it. Uniqueness of the
    /// name is the whole contract.
    #[schemars(with = "UnsignedInt")]
    pub run_number: u32,

    /// The inventory this run targeted, preserving the groups the user designed (each group's name
    /// and its hosts) rather than a flat host list. Same shape as the plan's `.status.eligibleHosts`,
    /// filtered to the hosts this run actually ran.
    pub inventory: Vec<ResolvedHosts>,

    /// Start of the schedule slot consumed by this run. Unscheduled runs leave this absent. Keeping
    /// it in the immutable run record lets restart recovery distinguish this run's slot from a later
    /// slot that becomes due while the operator is unavailable.
    #[serde(default, with = "crate::v1beta1::resources::custom_rfc3339")]
    #[schemars(with = "Option<String>")]
    pub triggered_slot: Option<DateTime<FixedOffset>>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PlayStatus {
    pub phase: PlayPhase,

    /// Whether this terminal result has been applied to the owning `PlaybookPlan` status. Kept on
    /// the status subresource so acknowledgement uses the operator's existing `plays/status` RBAC.
    #[serde(default)]
    pub plan_status_recorded: bool,

    /// Name of the backing Job in the plan's namespace. The Job/pod may already have been reaped by
    /// Kubernetes' TTL controller; this Play outlives them.
    pub job_name: Option<String>,

    /// When the backing Job reached a terminal state. The run's *start* is the Play's own
    /// `metadata.creationTimestamp` (the Play is created immediately before the run's Job), so it
    /// isn't duplicated here. See the `#[serde(default, ...)]` timestamp note on
    /// `PlaybookPlanStatus::next_run`: merge patches drop `null` keys, so this is genuinely absent
    /// when `None`.
    #[serde(default, with = "crate::v1beta1::resources::custom_rfc3339")]
    #[schemars(with = "Option<String>")]
    pub finished_at: Option<DateTime<FixedOffset>>,

    /// Number of distinct hosts this run targeted (the total across `spec.inventory`, surfaced as
    /// a column).
    #[schemars(with = "UnsignedInt")]
    pub host_count: u32,

    /// How many hosts ended `Failed` or `Unreachable`.
    #[schemars(with = "UnsignedInt")]
    pub failed_host_count: u32,

    /// The Ansible recap, summed across every targeted host — the recap columns read from here.
    pub recap: PlayRecap,

    /// Per-host recap and outcome, for drilling into which host did what.
    pub hosts: BTreeMap<String, PlayHostResult>,
}

/// The seven Ansible recap counters (`PLAY RECAP` line). Field order is irrelevant here — unlike
/// the positional wire format in `callback_output::HostStats`, these are named/`camelCase` for
/// JSONPath columns and merge-patch friendliness.
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PlayRecap {
    #[schemars(with = "UnsignedInt")]
    pub ok: u32,
    #[schemars(with = "UnsignedInt")]
    pub changed: u32,
    #[schemars(with = "UnsignedInt")]
    pub unreachable: u32,
    #[schemars(with = "UnsignedInt")]
    pub failed: u32,
    #[schemars(with = "UnsignedInt")]
    pub skipped: u32,
    #[schemars(with = "UnsignedInt")]
    pub rescued: u32,
    #[schemars(with = "UnsignedInt")]
    pub ignored: u32,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PlayHostResult {
    pub recap: PlayRecap,
    pub outcome: HostOutcome,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
pub enum PlayPhase {
    /// The immutable run record exists, but Job creation has not yet been committed.
    #[default]
    Prepared,
    /// The run holds its host locks and its privileged infrastructure is being created. Recovery
    /// resumes that setup while the plan's inputs are unchanged; the run is abandoned if its
    /// nodes lost their authorization or if the desired revision moved on.
    Starting,
    /// Setup is complete and final live authorization has passed, so Job creation is committed.
    /// Recovery re-derives the blueprint from the plan and creates it. If the desired revision moved
    /// on first, recovery adopts the Job when it already exists — a started run is always allowed to
    /// finish — and otherwise abandons the run rather than launching a superseded one.
    Launching,
    /// The backing Job has been confirmed and hasn't reached a terminal state yet.
    Running,
    /// The Job finished and no targeted host was `Failed`/`Unreachable`.
    Succeeded,
    /// The Job finished with at least one `Failed`/`Unreachable` host.
    Failed,
    /// The Job finished but its recap couldn't be read — reaped before the operator saw it, or a
    /// hard crash (OOM/SIGKILL) before the stats hook wrote `/dev/termination-log`.
    Unknown,
    /// The run was superseded before Job creation committed. Cleanup is pending; this phase is
    /// transient and the Play is deleted after cleanup.
    Aborted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt as _;

    #[test]
    fn play_status_serializes_recap_camel_case_for_columns() {
        let mut hosts = BTreeMap::new();
        hosts.insert(
            "node-1".to_string(),
            PlayHostResult {
                recap: PlayRecap {
                    ok: 5,
                    changed: 2,
                    ..Default::default()
                },
                outcome: HostOutcome::Succeeded,
            },
        );

        let status = PlayStatus {
            phase: PlayPhase::Succeeded,
            job_name: Some("apply-web-a1b2c3-1".into()),
            host_count: 1,
            failed_host_count: 0,
            recap: PlayRecap {
                ok: 5,
                changed: 2,
                ..Default::default()
            },
            hosts,
            ..Default::default()
        };

        let json = serde_json::to_value(&status).unwrap();

        // The printer columns read these JSONPaths — pin the camelCase surface.
        assert_eq!(json["recap"]["ok"], 5);
        assert_eq!(json["hostCount"], 1);
        assert_eq!(json["phase"], "Succeeded");

        let back: PlayStatus = serde_json::from_value(json).unwrap();
        assert_eq!(back.recap, status.recap);
        assert_eq!(back.hosts["node-1"].outcome, HostOutcome::Succeeded);
    }

    #[test]
    fn crd_makes_the_play_spec_immutable() {
        let crd = serde_json::to_value(Play::crd()).unwrap();
        let spec_schema =
            &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"];
        let validations = &spec_schema["x-kubernetes-validations"];

        assert!(validations.as_array().unwrap().iter().any(|validation| {
            validation["rule"] == "self == oldSelf"
                && validation["message"] == "Play spec is immutable"
        }));

        // The rule is only worth the name if CEL can actually see everything it claims to freeze.
        // CEL is blind inside `x-kubernetes-preserve-unknown-fields`, so a single schemaless field
        // anywhere under the spec would silently carve a hole in the immutability guarantee — and
        // the hole would be invisible in the rule itself. Keeping every input reduced to a typed
        // field (`preparationFingerprint` rather than a verbatim inventory snapshot) is what makes
        // this hold; a new field that reintroduces one has to fail here rather than in production.
        fn schemaless_field(schema: &serde_json::Value, path: &str) -> Option<String> {
            if schema["x-kubernetes-preserve-unknown-fields"] == serde_json::json!(true) {
                return Some(path.to_string());
            }
            let mut nested: Vec<(String, &serde_json::Value)> = Vec::new();
            if let Some(properties) = schema["properties"].as_object() {
                nested.extend(
                    properties
                        .iter()
                        .map(|(key, value)| (format!("{path}.{key}"), value)),
                );
            }
            if schema["items"].is_object() {
                nested.push((format!("{path}[]"), &schema["items"]));
            }
            nested
                .into_iter()
                .find_map(|(path, schema)| schemaless_field(schema, &path))
        }

        assert_eq!(
            schemaless_field(spec_schema, "spec"),
            None,
            "a schemaless field under the Play spec is invisible to the immutability rule"
        );
    }

    /// An absent optional timestamp must deserialize (merge patches store it as genuinely missing,
    /// not `null`) — same contract as the other status types.
    #[test]
    fn play_status_deserializes_when_timestamps_are_absent() {
        let json = serde_json::json!({
            "phase": "Running",
            "hostCount": 2,
            "failedHostCount": 0,
            "recap": { "ok": 0, "changed": 0, "unreachable": 0, "failed": 0, "skipped": 0, "rescued": 0, "ignored": 0 },
            "hosts": {}
            // finishedAt / jobName deliberately omitted
        });

        let status: PlayStatus = serde_json::from_value(json).unwrap();
        assert_eq!(status.phase, PlayPhase::Running);
        assert_eq!(status.finished_at, None);
        assert_eq!(status.job_name, None);
    }
}
