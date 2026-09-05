//! Whether the cluster Nodes a run would target are in a state to be reached at all.
//!
//! This is the *scheduling* question — "is it worth starting a run right now?" — and is entirely
//! separate from `node_access`, which answers the *authorization* question and must keep reading
//! Nodes live (INV-5). Readiness is not a security decision, so it is answered from the reflector
//! cache the controller already maintains for its Node watch.

use k8s_openapi::api::core::v1::Node;
use kube::runtime::reflector::{ObjectRef, Store};

use crate::v1beta1::{ExecutionMode, ResolvedInventoryGroup};

/// Whether a Node reports `Ready=True`.
///
/// A Node that has registered but not yet reported a status carries no conditions at all, so the
/// absence of the condition is a real state and means "not ready", not "missing data".
pub fn is_ready(node: &Node) -> bool {
    node.status
        .as_ref()
        .and_then(|status| status.conditions.as_ref())
        .into_iter()
        .flatten()
        .any(|condition| condition.type_ == "Ready" && condition.status == "True")
}

/// The managed-ssh nodes among `groups` that are currently known to be **not** `Ready`, sorted and
/// deduplicated.
///
/// A node the cache has no entry for is treated as ready — deliberately. The alternative fails
/// closed on missing data, which here would mean an operator whose Node reflector has not finished
/// its initial sync holds back every run it should be starting. A node that is genuinely gone is
/// also not in the resolved inventory for long, and a run that targets one anyway behaves exactly
/// as it did before this module existed: no proxy pod, grace window, reported unreachable.
///
/// `StaticInventory` hosts are not Nodes and never appear here.
pub fn unready_nodes(nodes: &Store<Node>, groups: &[ResolvedInventoryGroup]) -> Vec<String> {
    let mut unready: Vec<String> = groups
        .iter()
        .filter_map(|group| match group {
            ResolvedInventoryGroup::ManagedSsh { hosts, .. } => Some(hosts),
            ResolvedInventoryGroup::Ssh { .. } => None,
        })
        .flat_map(|hosts| hosts.hosts.iter())
        .filter(|host| {
            nodes
                .get(&ObjectRef::new(host))
                .is_some_and(|node| !is_ready(&node))
        })
        .cloned()
        .collect();

    unready.sort();
    unready.dedup();
    unready
}

/// Whether a run must be held rather than started, because every host it would target is a
/// managed-ssh node that is not `Ready` — the condition under which starting it buys nothing.
///
/// Such a run is not harmless. Each of those nodes gets a proxy pod that cannot come up, the run
/// waits out the full grace window, and Ansible then reports every host unreachable — spending one
/// of a `OneShot` plan's attempts on an outcome that was knowable before the Job existed. Holding
/// instead costs nothing, because the controller's Node watch wakes the plan the moment one of them
/// reports `Ready` again.
///
/// It is deliberately "every", not "any". A run that can still reach *some* of its hosts must go
/// ahead and reach them, carrying the unreachable ones along so they are reported as such in the
/// play result rather than silently dropped from it.
///
/// `Recurring` never holds, whatever the nodes are doing: its contract is to re-apply at each tick
/// against whatever exists then, and its budget already resets per tick, so a tick that reaches
/// nobody costs it nothing to skip. The mode is taken here rather than checked at the call site so
/// that both halves of the rule are decided — and tested — in one place.
pub fn holds_for_unready_nodes(
    mode: &ExecutionMode,
    groups: &[ResolvedInventoryGroup],
    unready: &[String],
) -> bool {
    if !matches!(mode, ExecutionMode::OneShot) || unready.is_empty() {
        return false;
    }

    groups
        .iter()
        .flat_map(|group| group.hosts().hosts.iter())
        .all(|host| unready.contains(host))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1beta1::{ResolvedHosts, SecretRef, SshConfig};
    use k8s_openapi::api::core::v1::{NodeCondition, NodeStatus};

    fn node_with_ready(status: Option<&str>) -> Node {
        Node {
            status: Some(NodeStatus {
                conditions: status.map(|status| {
                    vec![NodeCondition {
                        type_: "Ready".to_string(),
                        status: status.to_string(),
                        ..Default::default()
                    }]
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn managed(name: &str, hosts: &[&str]) -> ResolvedInventoryGroup {
        ResolvedInventoryGroup::ManagedSsh {
            hosts: ResolvedHosts {
                name: name.into(),
                hosts: hosts.iter().map(|host| host.to_string()).collect(),
            },
            tolerations: None,
            variables: None,
        }
    }

    fn ssh(name: &str, hosts: &[&str]) -> ResolvedInventoryGroup {
        ResolvedInventoryGroup::Ssh {
            hosts: ResolvedHosts {
                name: name.into(),
                hosts: hosts.iter().map(|host| host.to_string()).collect(),
            },
            static_inventory_name: "external".into(),
            config: SshConfig {
                user: "root".into(),
                secret_ref: SecretRef { name: "key".into() },
            },
            variables: None,
        }
    }

    #[test]
    fn only_a_ready_true_condition_counts_as_ready() {
        assert!(is_ready(&node_with_ready(Some("True"))));
        assert!(!is_ready(&node_with_ready(Some("False"))));
        // The node controller writes `Unknown` once a kubelet stops reporting.
        assert!(!is_ready(&node_with_ready(Some("Unknown"))));
    }

    /// A Node that has registered but not yet posted a status is a real state, not missing data:
    /// nothing has said it can run anything yet.
    #[test]
    fn a_node_that_has_not_reported_a_status_is_not_ready() {
        assert!(!is_ready(&node_with_ready(None)));
        assert!(!is_ready(&Node::default()));
    }

    #[test]
    fn a_run_holds_only_when_every_one_of_its_hosts_is_an_unready_node() {
        let groups = vec![managed("workers", &["node-a", "node-b"])];

        assert!(holds_for_unready_nodes(
            &ExecutionMode::OneShot,
            &groups,
            &["node-a".to_string(), "node-b".to_string()]
        ));
        assert!(
            !holds_for_unready_nodes(&ExecutionMode::OneShot, &groups, &["node-a".to_string()]),
            "node-b can still be reached, so the run has work to do"
        );
        assert!(!holds_for_unready_nodes(
            &ExecutionMode::OneShot,
            &groups,
            &[]
        ));
    }

    /// A `Recurring` plan re-applies at each tick against whatever exists then, and its budget
    /// resets per tick, so it has nothing to protect by waiting and a skipped tick is simply a tick
    /// that did not happen. It runs even when every one of its nodes is down.
    #[test]
    fn a_recurring_run_starts_even_when_every_node_is_down() {
        let groups = vec![managed("workers", &["node-a", "node-b"])];
        let unready = ["node-a".to_string(), "node-b".to_string()];

        assert!(!holds_for_unready_nodes(
            &ExecutionMode::Recurring,
            &groups,
            &unready
        ));
        assert!(
            holds_for_unready_nodes(&ExecutionMode::OneShot, &groups, &unready),
            "the same inputs hold a OneShot plan — the mode is the only difference"
        );
    }

    /// A `StaticInventory` host is reached over its own SSH key, with no Node and no proxy pod
    /// between the run and the host — a down cluster node says nothing about whether it can be
    /// reached, so a run carrying one always has work to do.
    #[test]
    fn a_static_host_alongside_an_unready_node_keeps_the_run_going() {
        let groups = vec![
            managed("workers", &["node-a"]),
            ssh("edge", &["host.example.com"]),
        ];

        assert!(!holds_for_unready_nodes(
            &ExecutionMode::OneShot,
            &groups,
            &["node-a".to_string()]
        ));
    }
}
