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

/// A resolved inventory group tagged with which mechanism reaches its hosts — connection
/// strategy is implicit by inventory kind: `ClusterInventory`-sourced groups always use
/// managed-ssh, `StaticInventory`-sourced groups always use their own embedded SSH key. Kept as
/// a distinct per-group type, not flattened, since each resource's own config (tolerations /
/// SshConfig) has to travel with its hosts downstream.
///
/// `Serialize` is not for persistence — no `Play` or status stores these — but for
/// `reconciler::preparation_fingerprint`, which hashes the serialized form to detect that the
/// resolved inventory an attempt was prepared against has moved on.
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
