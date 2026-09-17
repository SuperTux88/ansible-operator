use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1beta1::{AnsibleInventory, GenericMap, NodeSelectorTerm, ResolvedHosts};

#[derive(CustomResource, Debug, Serialize, Deserialize, Default, Clone, JsonSchema)]
#[kube(
    group = "ansible.cloudbending.dev",
    version = "v1beta1",
    kind = "ClusterInventory",
    status = "ClusterInventoryStatus",
    namespaced,
    printcolumn = r#"{"name":"Hosts","type":"string","jsonPath":".status.hostCount"}"#,
    printcolumn = r#"{"name":"Waiting","type":"string","jsonPath":".status.waitingHosts"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ClusterInventorySpec {
    pub hosts: Vec<InventoryHosts>,

    /// Tolerations applied to the managed-ssh proxy pods created for this inventory's hosts,
    /// e.g. to allow scheduling onto tainted controlplane nodes.
    pub tolerations: Option<Vec<Toleration>>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
pub struct Toleration {
    pub effect: Option<String>,
    pub key: Option<String>,
    pub operator: Option<String>,
    pub toleration_seconds: Option<i64>,
    pub value: Option<String>,
}

impl From<k8s_openapi::api::core::v1::Toleration> for Toleration {
    fn from(other: k8s_openapi::api::core::v1::Toleration) -> Self {
        Self {
            effect: other.effect,
            key: other.key,
            operator: other.operator,
            toleration_seconds: other.toleration_seconds,
            value: other.value,
        }
    }
}

impl From<Toleration> for k8s_openapi::api::core::v1::Toleration {
    fn from(t: Toleration) -> Self {
        k8s_openapi::api::core::v1::Toleration {
            key: t.key,
            value: t.value,
            effect: t.effect,
            operator: t.operator,
            toleration_seconds: t.toleration_seconds,
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterInventoryStatus {
    /// The `metadata.generation` this status was computed from.
    ///
    /// `resolvedHosts` is a *published* answer rather than a live one — a plan reads it instead of
    /// evaluating the selectors itself — so between a spec edit and this controller's next reconcile
    /// the published hosts still describe the previous spec. A plan that started a run in that
    /// window would target the old host set, which one `helm upgrade` changing an inventory and a
    /// plan together makes routine: Helm applies both in a single pass and waits for no status.
    ///
    /// A plan therefore prepares no new run from an inventory whose `observedGeneration` is not its
    /// `metadata.generation`, and the status write that catches it up wakes every plan that names
    /// it. Absent until this controller has written a status at all.
    pub observed_generation: Option<i64>,
    /// How many distinct Nodes this inventory resolves to — the `Hosts` column. A Node matched by
    /// two of the inventory's groups is listed in both of `resolvedHosts` and counted here once,
    /// because that is what it is to a run: one host, applied to once. The plan's own `n/m hosts`
    /// summaries and a `Play`'s `Hosts` column count the same way, and they are read side by side.
    pub host_count: usize,
    /// The Nodes each group resolved to, with their group membership preserved — a Node in two
    /// groups appears in both, which is what makes the rendered Ansible inventory's groups mean
    /// something.
    pub resolved_hosts: Vec<ResolvedHosts>,
    /// How many distinct Nodes are kept out of this inventory by a dependency alone — the `Waiting`
    /// column. Counted over distinct Nodes like `hostCount`, so a Node waiting on two dependencies,
    /// or on the same one in two groups, is one waiting host.
    ///
    /// Read it beside `hostCount`: `2` hosts and `6` waiting is a rollout in progress, and `0`
    /// waiting on an inventory that resolves fewer hosts than expected means the missing Nodes fail
    /// something other than a dependency.
    #[serde(default)]
    pub waiting_hosts: usize,
    /// What each group is waiting on another plan for, one entry per dependency requirement.
    ///
    /// Empty on an inventory whose selectors name no operator-owned key, which is every inventory
    /// that does not express a dependency.
    ///
    /// Bounded so the status always fits the object size limit: at most 256 entries, with any
    /// string longer than a label key (317 characters) cut and ending in `…`.
    ///
    /// Written without `skip_serializing_if` on purpose. The status goes out as a JSON **merge**
    /// patch, which leaves a field it does not mention alone, so a list that has become empty has to
    /// be sent as `[]` to actually empty. Omitting it would leave a satisfied dependency reported as
    /// waiting for ever.
    #[serde(default)]
    pub dependencies: Vec<DependencyStatus>,
}

/// One positive requirement on another plan's label, and how far the fleet has got with it.
///
/// A *dependency* is a requirement on a key this operator publishes
/// (`<namespace>.plan.ansible.cloudbending.dev/<plan>`), which only ever appears on a Node where
/// that plan converged. So a Node failing one is not misconfigured, it is *not ready yet* — and
/// telling those two apart from the outside is impossible without this, since both simply show up
/// as an inventory resolving fewer hosts than its author expected.
///
/// Exclusions (`NotIn`, `DoesNotExist`) are deliberately not dependencies: a Node fails them by
/// *carrying* something, which no amount of waiting fixes.
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DependencyStatus {
    /// The inventory group whose selector carries this requirement.
    pub group: String,
    /// The label key the requirement is on.
    pub key: String,
    /// The namespace of the `PlaybookPlan` that publishes `key`, decoded from the key itself.
    ///
    /// Not looked up: the operator does not check that this plan exists. A dependency on a plan
    /// nobody has therefore reads as waiting for it, which is exactly what a typo in the key looks
    /// like — and naming it is what lets a human spot the typo.
    pub provider_namespace: String,
    /// The name of the `PlaybookPlan` that publishes `key`, decoded from the key itself.
    pub provider_name: String,
    /// The requirement as written, rendered back for a reader: `Ge 1.4.0`, `Exists`, `= 1.4.2`.
    pub requirement: String,
    /// How many of the group's Nodes this requirement is holding back.
    ///
    /// "The group's Nodes" are the ones that satisfy every term the author wrote for reasons other
    /// than a dependency, so a Node excluded by the wrong `node-role` is not waiting for anything.
    /// A Node held back by two dependencies is counted under both: there is no ordering between
    /// them, and neither one finishing releases it.
    pub waiting: usize,
    /// How many of the group's Nodes have got past this requirement.
    ///
    /// `satisfied + waiting` is the denominator a reader needs — "3 of 8" — which is why both are
    /// published rather than one number or a percentage.
    pub satisfied: usize,
    /// The requirement's own value is not a version, under an operator that orders versions.
    ///
    /// It therefore matches **nothing**, whatever the Nodes carry, and `waiting` beside it is the
    /// whole group. The selector is what needs fixing.
    #[serde(default)]
    pub invalid_value: bool,
    /// An ordered operator (`Gt`/`Ge`/`Lt`/`Le`) listing anything other than exactly one value, or
    /// an `In` listing none.
    ///
    /// Like `invalidValue` it matches nothing. Reported here rather than rejected at admission,
    /// because the selector type is shared with `NodeAccessPolicy` and sits inside a
    /// preserve-unknown-fields item where a CEL rule cannot see it.
    #[serde(default)]
    pub malformed_term: bool,
    /// How many of the waiting Nodes carry the key with a value that is not a version.
    ///
    /// The one failure the label's *author* caused rather than the selector's: the provider
    /// published something like `latest`, so no ordered comparison against it can be answered and
    /// the Node waits for ever. A subset of `waiting`.
    #[serde(default)]
    pub unparseable_hosts: usize,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct InventoryHosts {
    pub name: String,
    #[serde(flatten)]
    pub match_labels: Option<NodeSelectorTerm>,
    #[serde(flatten)]
    pub match_expressions: Option<BTreeMap<String, serde_json::Value>>, // todo: placeholder

    /// Group variables applied to every node this group resolves to, rendered as Ansible group
    /// `vars:`. Use it to set node facts the playbook author should not have to know, e.g.
    /// `ansible_python_interpreter`. Operator-managed connection variables (`ansible_host`,
    /// `ansible_user`, `ansible_port`, `ansible_ssh_*`) are rejected — the operator owns those.
    pub variables: Option<GenericMap>,
}

impl ClusterInventory {
    /// Whether `status.resolvedHosts` describes the spec the apiserver currently holds.
    ///
    /// False while this inventory's controller has not caught up with a spec edit — including
    /// before it has written any status at all, where there are no stale hosts to speak of but
    /// equally none to run against.
    ///
    /// An object carrying no `metadata.generation` reads as current: the apiserver stamps one onto
    /// every custom resource, so there is nothing to compare against and no evidence of staleness
    /// to act on. Blocking on the absence would hold every plan on a field that is never missing in
    /// a real cluster.
    pub fn status_is_current(&self) -> bool {
        let Some(generation) = self.metadata.generation else {
            return true;
        };

        self.status
            .as_ref()
            .is_some_and(|status| status.observed_generation == Some(generation))
    }
}

impl AnsibleInventory for ClusterInventory {
    fn get_hosts(&self) -> Vec<ResolvedHosts> {
        self.status
            .as_ref()
            .map(|s| s.resolved_hosts.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_example() {
        let inventory_str = include_str!("../../../examples/v1beta1/cluster-inventory.yaml");
        let _: ClusterInventory = serde_yaml::from_str(inventory_str).unwrap();
    }

    fn example() -> ClusterInventory {
        serde_yaml::from_str(include_str!(
            "../../../examples/v1beta1/cluster-inventory.yaml"
        ))
        .unwrap()
    }

    /// The gate a plan asks before it prepares a run. While it answers false, `resolvedHosts`
    /// describes a spec the apiserver no longer holds, and a run started against it would target the
    /// host set the edit replaced.
    #[test]
    fn a_status_behind_the_spec_is_not_current() {
        let mut inventory = example();
        inventory.metadata.generation = Some(5);

        assert!(
            !inventory.status_is_current(),
            "an inventory whose controller has never written a status resolves no hosts to run on"
        );

        inventory.status = Some(ClusterInventoryStatus {
            observed_generation: Some(4),
            ..Default::default()
        });
        assert!(!inventory.status_is_current());

        inventory.status = Some(ClusterInventoryStatus {
            observed_generation: Some(5),
            ..Default::default()
        });
        assert!(inventory.status_is_current());
    }

    /// The status is written as a JSON merge patch, which leaves out what it does not mention. A
    /// `dependencies` that stops being serialized once it is empty would therefore leave the last
    /// wait standing on the object for ever, long after the provider finished.
    #[test]
    fn an_emptied_dependency_list_is_written_as_an_empty_list() {
        let patch = serde_json::to_value(ClusterInventoryStatus::default()).unwrap();

        assert_eq!(patch["dependencies"], serde_json::json!([]));
        assert_eq!(patch["waitingHosts"], serde_json::json!(0));
    }

    /// The apiserver stamps a generation onto every custom resource, so an object without one offers
    /// nothing to compare and no staleness to act on. Reading it as stale would hold every plan on a
    /// field that is never actually missing.
    #[test]
    fn an_object_without_a_generation_reads_as_current() {
        let inventory = example();

        assert_eq!(inventory.metadata.generation, None);
        assert!(inventory.status_is_current());
    }
}
