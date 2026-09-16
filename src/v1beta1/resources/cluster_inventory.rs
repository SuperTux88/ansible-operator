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
    printcolumn = r#"{"name":"Hosts","type":"string","jsonPath":".status.hostCount"}"#
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
