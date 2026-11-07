use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1beta1::{AnsibleInventory, GenericMap, PortNumber, ResolvedHosts, SecretRef};

#[derive(CustomResource, Debug, Serialize, Deserialize, Default, Clone, JsonSchema)]
#[kube(
    group = "ansible.cloudbending.dev",
    version = "v1beta1",
    kind = "StaticInventory",
    // No status subresource: nothing resolves a StaticInventory. Its hosts are literals the user
    // wrote, so there is nothing for a controller to compute back onto it, and the operator holds no
    // `staticinventories/status` grant to write one with (see the chart's ClusterRole).
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct StaticInventorySpec {
    pub hosts: Vec<StaticInventoryGroup>,

    /// How to reach these hosts over SSH. Mandatory: a StaticInventory with no reachability
    /// info isn't usable by any PlaybookPlan.
    pub ssh: SshConfig,
}

/// One named group of external hosts, optionally carrying group variables applied to every host
/// in the group.
//
// Same `name` + `hosts` shape as `ResolvedHosts`, plus author-supplied `variables`; kept a distinct
// type so `ResolvedHosts` (which also backs status and the execution hash) stays a plain
// name/host-list pair.
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StaticInventoryGroup {
    pub name: String,
    pub hosts: Vec<String>,

    /// Group variables applied to every host in this group, rendered as Ansible group `vars:`,
    /// e.g. `ansible_python_interpreter`. The connection variables the operator manages are
    /// rejected: `ansible_host`, `ansible_port` and `ansible_user`, also as `ansible_ssh_host`,
    /// `ansible_ssh_port` and `ansible_ssh_user`, `ansible_ssh_private_key_file` and
    /// `ansible_ssh_common_args`.
    pub variables: Option<GenericMap>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshConfig {
    pub user: String,
    pub secret_ref: SecretRef,

    /// The TCP port the hosts' SSH server listens on. Omit it for SSH's default, 22.
    //
    // Left out of the serialized form when unset: `reconciler::preparation_fingerprint` hashes it,
    // and a `"port": null` would move the fingerprint of every run prepared before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<PortNumber>")]
    pub port: Option<u16>,
}

impl AnsibleInventory for StaticInventory {
    fn get_hosts(&self) -> Vec<ResolvedHosts> {
        self.spec
            .hosts
            .iter()
            .map(|group| ResolvedHosts {
                name: group.name.clone(),
                hosts: group.hosts.clone(),
                ..Default::default()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use kube::CustomResourceExt as _;

    use super::*;

    #[test]
    fn test_deserialize_example() {
        let inventory_str = include_str!("../../../examples/v1beta1/static-inventory.yaml");
        let _: StaticInventory = serde_saphyr::from_str(inventory_str).unwrap();
    }

    #[test]
    fn an_unset_port_is_left_out_of_the_serialized_config() {
        let config = SshConfig {
            user: "root".into(),
            secret_ref: SecretRef {
                name: "ssh-key".into(),
            },
            port: None,
        };
        assert_eq!(
            serde_json::to_value(&config).unwrap(),
            serde_json::json!({ "user": "root", "secretRef": { "name": "ssh-key" } })
        );
    }

    #[test]
    fn the_port_schema_is_a_tcp_port_without_an_unrecognised_format() {
        let crd = serde_json::to_value(StaticInventory::crd()).unwrap();
        let port = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]
            ["ssh"]["properties"]["port"];
        assert_eq!(port["type"], "integer");
        assert_eq!(port["minimum"].as_f64(), Some(1.0));
        assert_eq!(port["maximum"].as_f64(), Some(65535.0));
        assert!(port.get("format").is_none(), "{port}");
    }
}
