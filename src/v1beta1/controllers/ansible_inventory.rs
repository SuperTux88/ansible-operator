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

/// Whether a group's `variables` reach the rendered inventory at all: the value has to be a mapping
/// with at least one entry.
///
/// This is `inventory_renderer`'s own condition for emitting a `vars:` block, and it lives here —
/// beside the type rather than inside one of its consumers — because three of them have to agree
/// about it. What a run *executes* is the rendered inventory, so a group whose variables render
/// nothing is a group with no variables: to the execution hash, which must not re-apply the playbook
/// for an edit no host can observe, and to [`ResolvedInventoryGroup`]'s serialized form, which is
/// what `reconciler::preparation_fingerprint` reads to decide whether a run that has not launched
/// yet still matches the plan it was prepared for.
///
/// The mapping check covers the same ground for the same reason. A value that is not a mapping
/// cannot reach the API server (the CRD types `variables` as an object) and the renderer would drop
/// it if one did, so treating it as content would be the same contradiction in a shape nobody can
/// produce.
pub fn renders_group_vars(variables: &serde_json::Value) -> bool {
    variables.as_object().is_some_and(|vars| !vars.is_empty())
}

/// The `skip_serializing_if` behind [`ResolvedInventoryGroup`]'s `variables` — see
/// [`renders_group_vars`] for why an empty map is serialized as though the field were absent.
fn group_vars_render_nothing(variables: &Option<GenericMap>) -> bool {
    !variables
        .as_ref()
        .is_some_and(|variables| renders_group_vars(&variables.0))
}

/// A resolved inventory group tagged with which mechanism reaches its hosts — connection
/// strategy is implicit by inventory kind: `ClusterInventory`-sourced groups always use
/// managed-ssh, `StaticInventory`-sourced groups always use their own embedded SSH key. Kept as
/// a distinct per-group type, not flattened, since each resource's own config (tolerations /
/// SshConfig) has to travel with its hosts downstream.
///
/// `Serialize` is not for persistence — no `Play` or status stores these, and there is deliberately
/// no `Deserialize` — but for `reconciler::preparation_fingerprint`, which hashes the serialized
/// form to detect that the resolved inventory a run was prepared against has moved on. Being the
/// sole consumer is what lets `variables` be canonicalized on the way out
/// ([`group_vars_render_nothing`]) rather than at that one call site.
#[derive(Clone, Debug, Serialize)]
pub enum ResolvedInventoryGroup {
    ManagedSsh {
        hosts: ResolvedHosts,
        tolerations: Option<Vec<Toleration>>,
        /// Author-supplied group variables from the owning `ClusterInventory`, rendered as
        /// Ansible group `vars:`. `None` when the group set none.
        #[serde(skip_serializing_if = "group_vars_render_nothing")]
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
        #[serde(skip_serializing_if = "group_vars_render_nothing")]
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
