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
}
