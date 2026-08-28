use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1beta1::{GenericMap, SshConfig, Toleration};

pub trait AnsibleInventory {
    fn get_hosts(&self) -> Vec<ResolvedHosts>;
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedHosts {
    pub name: String,
    pub hosts: Vec<String>,
}

/// The hosts a group list names, each one exactly once, in first-seen order.
///
/// A node reachable through two inventory groups is listed twice in the flat `ResolvedHosts`
/// projection, but it is one host to Ansible and one host to whoever reads an `n/m hosts` summary.
/// Every population reported on is therefore taken over the distinct names — the plan's `n/m`
/// summaries and per-record `Play` counts, and the `ClusterInventory` host count that sits directly
/// above them in `kubectl` output. Those surfaces must not disagree about how many hosts there are,
/// which is why this lives beside `ResolvedHosts` rather than inside one controller.
pub fn distinct_hosts(groups: &[ResolvedHosts]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    groups
        .iter()
        .flat_map(|group| group.hosts.iter())
        .filter(|host| seen.insert(host.as_str()))
        .cloned()
        .collect()
}

/// How many distinct hosts a group list names — see [`distinct_hosts`].
pub fn distinct_host_count(groups: &[ResolvedHosts]) -> usize {
    distinct_hosts(groups).len()
}

/// A resolved inventory group tagged with which mechanism reaches its hosts — connection
/// strategy is implicit by inventory kind: `ClusterInventory`-sourced groups always use
/// managed-ssh, `StaticInventory`-sourced groups always use their own embedded SSH key. Kept as
/// a distinct per-group type, not flattened, since each resource's own config (tolerations /
/// SshConfig) has to travel with its hosts downstream.
///
/// `Serialize` is not for persistence — no `Play` or status stores these — but for
/// `reconciler::preparation_fingerprint`, which hashes the serialized form to detect that the
/// resolved inventory a run was prepared against has moved on.
#[derive(Clone, Debug, Serialize)]
pub enum ResolvedInventoryGroup {
    ManagedSsh {
        hosts: ResolvedHosts,
        tolerations: Option<Vec<Toleration>>,
        /// Author-supplied group variables from the owning `ClusterInventory`, rendered as
        /// Ansible group `vars:`. `None` when the group set none.
        variables: Option<GenericMap>,
    },
    Ssh {
        hosts: ResolvedHosts,
        /// Name of the owning `StaticInventory` resource — used to key its SSH secret's mount
        /// path, since one run can reference multiple StaticInventories with different
        /// credentials simultaneously.
        static_inventory_name: String,
        config: SshConfig,
        /// Author-supplied group variables from the owning `StaticInventory`, rendered as
        /// Ansible group `vars:`. `None` when the group set none.
        variables: Option<GenericMap>,
    },
}

impl ResolvedInventoryGroup {
    pub fn hosts(&self) -> &ResolvedHosts {
        match self {
            ResolvedInventoryGroup::ManagedSsh { hosts, .. } => hosts,
            ResolvedInventoryGroup::Ssh { hosts, .. } => hosts,
        }
    }

    /// Author-supplied group variables, if any, regardless of connection mechanism.
    pub fn variables(&self) -> Option<&GenericMap> {
        match self {
            ResolvedInventoryGroup::ManagedSsh { variables, .. } => variables.as_ref(),
            ResolvedInventoryGroup::Ssh { variables, .. } => variables.as_ref(),
        }
    }
}

/// Projects a run's resolved groups down to the flat `Vec<ResolvedHosts>` shape
/// `PlaybookPlanStatus.eligible_hosts` uses — `execution_evaluator.rs`'s hash/outdated-host
/// comparisons only need flat host-name lists.
pub fn flatten_hosts(groups: &[ResolvedInventoryGroup]) -> Vec<ResolvedHosts> {
    groups.iter().map(|g| g.hosts().clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One Node is one host, however many of an inventory's groups match it. Both counting surfaces
    /// read from here, so this is where the two are kept from disagreeing.
    #[test]
    fn a_host_in_two_groups_is_one_host() {
        let groups = vec![
            ResolvedHosts {
                name: "workers".into(),
                hosts: vec!["node-a".into(), "node-b".into()],
            },
            ResolvedHosts {
                name: "storage".into(),
                hosts: vec!["node-b".into(), "node-c".into()],
            },
        ];

        assert_eq!(
            distinct_hosts(&groups),
            vec!["node-a".to_string(), "node-b".into(), "node-c".into()],
            "first-seen order, so group membership still reads naturally"
        );
        assert_eq!(distinct_host_count(&groups), 3);
        assert_eq!(distinct_host_count(&[]), 0);
    }
}
