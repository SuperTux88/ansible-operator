use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1beta1::{GenericMap, SshConfig, Toleration};

pub trait AnsibleInventory {
    fn get_hosts(&self) -> Vec<ResolvedHosts>;
}

/// How a run reaches this group's hosts: `managedSsh` for a cluster Node, through a per-run
/// managed-ssh proxy pod, and `ssh` for an external machine, through its `StaticInventory`'s own
/// key. It follows from the kind of inventory the group came from and is never chosen.
///
/// Recorded because everything about a host — its `hostsStatus` row, its per-host Lease, its entry
/// in the rendered inventory — is keyed by host *name*, and a name alone cannot say whether a Node
/// object standing under it describes this host. For a `ClusterInventory` host it does; for a
/// `StaticInventory` host a Node of the same name is an unrelated machine, whose rebuilding says
/// nothing about the external one.
///
/// Absent on a `ClusterInventory`'s own `status.resolvedHosts`, where the kind of the resource
/// holding it is already the answer, and on a record written before this field existed. Absent
/// therefore reads as "not known to be a Node", which is the safe way round: every question it
/// gates is about Node objects.
#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum HostConnection {
    /// A cluster Node, reached through a per-run managed-ssh proxy pod.
    ManagedSsh,
    /// An external machine, reached directly with a `StaticInventory`'s own key.
    Ssh,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedHosts {
    pub name: String,
    pub hosts: Vec<String>,
    /// See [`HostConnection`]. Written only where the record naming these hosts belongs to a
    /// *plan* — its `status.eligibleHosts` and its runs' `Play` records — and only by
    /// [`flatten_hosts`], which takes it from the group's own variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<HostConnection>,
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

    /// How this group's hosts are reached — the variant itself, named so it can be recorded.
    pub fn connection(&self) -> HostConnection {
        match self {
            ResolvedInventoryGroup::ManagedSsh { .. } => HostConnection::ManagedSsh,
            ResolvedInventoryGroup::Ssh { .. } => HostConnection::Ssh,
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
/// `PlaybookPlanStatus.eligible_hosts` and `PlaySpec.inventory` use — `execution_evaluator.rs`'s
/// hash/outdated-host comparisons only need flat host-name lists.
///
/// The one thing it adds rather than drops is [`ResolvedHosts::connection`], which is the enum
/// variant the group is losing here. This is the **only** writer of that field, so it cannot
/// disagree with the variant it was taken from — and it is what lets a reader of either record ask
/// whether a host is a cluster Node without the groups still being in hand.
pub fn flatten_hosts(groups: &[ResolvedInventoryGroup]) -> Vec<ResolvedHosts> {
    groups
        .iter()
        .map(|group| ResolvedHosts {
            connection: Some(group.connection()),
            ..group.hosts().clone()
        })
        .collect()
}

/// What counts as a cluster Node in a flattened record, written once for both shapes the question
/// is asked in. A group whose `connection` was never recorded is left out, so the answer is "known
/// to be a Node" rather than "not known not to be".
///
/// Lazy, so the caller decides whether a set is worth building.
fn node_host_names(groups: &[ResolvedHosts]) -> impl Iterator<Item = &str> {
    groups
        .iter()
        .filter(|group| group.connection == Some(HostConnection::ManagedSsh))
        .flat_map(|group| group.hosts.iter().map(String::as_str))
}

/// The hosts of `groups` that are cluster Nodes, as recorded by [`flatten_hosts`].
///
/// For the readers that have a flattened record and not the groups: a plan's own
/// `status.eligibleHosts` and a run's `Play`.
pub fn node_hosts(groups: &[ResolvedHosts]) -> std::collections::HashSet<&str> {
    node_host_names(groups).collect()
}

/// [`node_hosts`]' question asked about one host, without building the set.
///
/// The same rule, in the shape a caller with a single name needs. `mappers::plan_awaits_node` asks
/// it of every plan in the store on every kubelet heartbeat, where the whole point of that predicate
/// is that a settled cluster pays nothing for one — so it must not allocate a set of the plan's
/// every host to answer a question about one of them, and must be reached only after the cheaper
/// tests have already failed to rule the host out.
pub fn is_node_host(groups: &[ResolvedHosts], host: &str) -> bool {
    node_host_names(groups).any(|recorded| recorded == host)
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
                ..Default::default()
            },
            ResolvedHosts {
                name: "storage".into(),
                hosts: vec!["node-b".into(), "node-c".into()],
                ..Default::default()
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

    fn group(name: &str, hosts: &[&str]) -> ResolvedHosts {
        ResolvedHosts {
            name: name.into(),
            hosts: hosts.iter().map(|host| (*host).to_string()).collect(),
            ..Default::default()
        }
    }

    /// The flattened record loses the enum variant, so it carries the answer instead. Taken from the
    /// variant here and nowhere else, which is what stops the two from ever disagreeing.
    #[test]
    fn flattening_records_how_each_group_is_reached() {
        let flattened = flatten_hosts(&[
            ResolvedInventoryGroup::ManagedSsh {
                hosts: group("workers", &["node-a"]),
                tolerations: None,
                variables: None,
            },
            ResolvedInventoryGroup::Ssh {
                hosts: group("edge", &["ccu.fritz.box"]),
                static_inventory_name: "ccu".into(),
                config: SshConfig {
                    user: "root".into(),
                    secret_ref: crate::v1beta1::SecretRef { name: "key".into() },
                },
                variables: None,
            },
        ]);

        assert_eq!(
            flattened[0].connection,
            Some(HostConnection::ManagedSsh),
            "a ClusterInventory group is always a cluster Node"
        );
        assert_eq!(flattened[1].connection, Some(HostConnection::Ssh));
        assert_eq!(flattened[0].hosts, vec!["node-a".to_string()]);
    }

    /// Only what was *recorded* as a Node counts. A group from before the field existed answers "not
    /// a Node", which is the safe way round for every question this gates.
    #[test]
    fn only_groups_recorded_as_nodes_are_nodes() {
        let node_group = ResolvedHosts {
            connection: Some(HostConnection::ManagedSsh),
            ..group("workers", &["node-a", "node-b"])
        };
        let external = ResolvedHosts {
            connection: Some(HostConnection::Ssh),
            ..group("edge", &["ccu.fritz.box"])
        };
        let untracked = group("legacy", &["node-c"]);

        let groups = [node_group, external, untracked];
        let hosts = node_hosts(&groups);

        assert_eq!(
            hosts,
            std::collections::HashSet::from(["node-a", "node-b"]),
            "the external group and the untracked one are both left out"
        );
        assert!(node_hosts(&[]).is_empty());

        for host in ["node-a", "node-b", "ccu.fritz.box", "node-c", "absent"] {
            assert_eq!(
                is_node_host(&groups, host),
                hosts.contains(host),
                "{host} must be answered the same way whichever shape asks"
            );
        }
        assert!(!is_node_host(&[], "node-a"));
    }
}
