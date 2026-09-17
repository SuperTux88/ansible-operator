//! `NodeAccessPolicy` enforcement — the authoritative gate that caps which cluster Nodes a
//! namespace's managed-ssh (`ClusterInventory`-sourced) groups may target.
//!
//! Applied while resolving a `PlaybookPlan`'s inventory, *before* any proxy infra is created. The
//! operation is a set **intersection** of the plan's requested nodes with the union of nodes the
//! admin-authored policies grant that namespace, so it can only ever shrink the request — a forged
//! or buggy node set can never reach a node no policy allowed. Fail-closed: a namespace with no
//! matching policy may target no managed-ssh nodes at all.

use std::collections::HashSet;

use k8s_openapi::api::core::v1::{Namespace, Node};
use kube::{Api, ResourceExt as _, api::ListParams, runtime::reflector::Store};

use crate::v1beta1::{
    NodeAccessPolicy, ResolvedInventoryGroup,
    controllers::{nodeselector::selector_matches_fail_closed, reconcile_error::ReconcileError},
};

/// Clamps every managed-ssh group in `groups` to the nodes `plan_namespace` is permitted to target,
/// dropping now-empty managed-ssh groups. Returns the sorted, de-duplicated host names that were
/// excluded (for logging/status). Non-managed-ssh (`StaticInventory`) groups are untouched — they
/// carry their own credentials and aren't node-root, so they're outside this policy.
///
/// `policies` is the reflector-cached view of the cluster's `NodeAccessPolicy` resources
/// (cluster-scoped, admin-authored, stable) — cheap to read every reconcile. The Node set is fetched
/// *live* rather than cached: it's the authoritative allow-set for a security gate, so it must not
/// serve a node stale-labelled into a pool it has since left.
pub async fn enforce(
    client: &kube::Client,
    policies: &Store<NodeAccessPolicy>,
    plan_namespace: &str,
    groups: &mut Vec<ResolvedInventoryGroup>,
) -> Result<Vec<String>, ReconcileError> {
    let has_managed_ssh = groups
        .iter()
        .any(|g| matches!(g, ResolvedInventoryGroup::ManagedSsh { .. }));
    if !has_managed_ssh {
        // No node-root groups → nothing this policy governs; skip the API calls entirely.
        return Ok(Vec::new());
    }

    let allowed = allowed_nodes_for_namespace(client, policies, plan_namespace).await?;
    Ok(clamp_managed_ssh_groups(groups, &allowed))
}

/// The union of Nodes granted to `plan_namespace` by the cached `NodeAccessPolicy` resources.
/// Fail-closed at every step: no matching policy, or a policy with an empty selector, contributes
/// nothing.
async fn allowed_nodes_for_namespace(
    client: &kube::Client,
    policies: &Store<NodeAccessPolicy>,
    plan_namespace: &str,
) -> Result<HashSet<String>, ReconcileError> {
    // The namespace's own labels — Kubernetes always stamps `kubernetes.io/metadata.name`, so a
    // policy can target a single namespace by name via that label.
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let namespace = namespaces.get(plan_namespace).await?;
    let namespace_labels = namespace.labels().clone();

    // Policies are admin-authored, cluster-scoped, cached by the reflector.
    let policies = policies.state();
    let granting: Vec<&NodeAccessPolicy> = policies
        .iter()
        .map(|policy| policy.as_ref())
        .filter(|policy| {
            selector_matches_fail_closed(&namespace_labels, &policy.spec.namespace_selector)
        })
        .collect();

    if granting.is_empty() {
        // Default-deny: an ungoverned namespace gets no managed-ssh nodes.
        return Ok(HashSet::new());
    }

    let nodes: Api<Node> = Api::all(client.clone());
    let nodes = nodes.list_metadata(&ListParams::default()).await?;

    let allowed = nodes
        .items
        .iter()
        .filter(|node| {
            let labels = node.labels();
            granting
                .iter()
                .any(|policy| selector_matches_fail_closed(labels, &policy.spec.node_selector))
        })
        .filter_map(|node| node.metadata.name.clone())
        .collect();

    Ok(allowed)
}

/// Pure intersection step: retain only `allowed` hosts in each managed-ssh group, drop groups left
/// empty, and return the excluded host names sorted+deduped. Split out from the async fetching so
/// the actual policy logic is unit-testable without a cluster.
fn clamp_managed_ssh_groups(
    groups: &mut Vec<ResolvedInventoryGroup>,
    allowed: &HashSet<String>,
) -> Vec<String> {
    let mut dropped = Vec::new();

    for group in groups.iter_mut() {
        if let ResolvedInventoryGroup::ManagedSsh { hosts, .. } = group {
            hosts.hosts.retain(|host| {
                let keep = allowed.contains(host);
                if !keep {
                    dropped.push(host.clone());
                }
                keep
            });
        }
    }

    groups.retain(
        |group| !matches!(group, ResolvedInventoryGroup::ManagedSsh { hosts, .. } if hosts.hosts.is_empty()),
    );

    dropped.sort();
    dropped.dedup();
    dropped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1beta1::{ResolvedHosts, SecretRef, SshConfig};

    fn managed(name: &str, hosts: &[&str]) -> ResolvedInventoryGroup {
        ResolvedInventoryGroup::ManagedSsh {
            hosts: ResolvedHosts {
                name: name.into(),
                hosts: hosts.iter().map(|h| h.to_string()).collect(),
                ..Default::default()
            },
            tolerations: None,
            variables: None,
        }
    }

    fn ssh(name: &str, hosts: &[&str]) -> ResolvedInventoryGroup {
        ResolvedInventoryGroup::Ssh {
            hosts: ResolvedHosts {
                name: name.into(),
                hosts: hosts.iter().map(|h| h.to_string()).collect(),
                ..Default::default()
            },
            static_inventory_name: "static".into(),
            config: SshConfig {
                user: "root".into(),
                secret_ref: SecretRef { name: "k".into() },
            },
            variables: None,
        }
    }

    fn allowed(nodes: &[&str]) -> HashSet<String> {
        nodes.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn keeps_only_allowed_managed_ssh_hosts_and_reports_dropped() {
        let mut groups = vec![managed("workers", &["node-a", "node-b", "node-c"])];
        let dropped = clamp_managed_ssh_groups(&mut groups, &allowed(&["node-a", "node-c"]));

        assert_eq!(dropped, vec!["node-b".to_string()]);
        let ResolvedInventoryGroup::ManagedSsh { hosts, .. } = &groups[0] else {
            panic!("expected managed-ssh group to survive");
        };
        assert_eq!(
            hosts.hosts,
            vec!["node-a".to_string(), "node-c".to_string()]
        );
    }

    #[test]
    fn empty_allow_set_drops_all_managed_ssh_and_removes_the_group() {
        let mut groups = vec![managed("workers", &["node-a", "node-b"])];
        let dropped = clamp_managed_ssh_groups(&mut groups, &allowed(&[]));

        assert_eq!(dropped, vec!["node-a".to_string(), "node-b".to_string()]);
        assert!(groups.is_empty(), "an emptied managed-ssh group is removed");
    }

    #[test]
    fn ssh_groups_are_never_touched() {
        // StaticInventory/BYO-key groups aren't node-root and aren't governed by NodeAccessPolicy,
        // so they pass through untouched even against an empty allow-set.
        let mut groups = vec![ssh("external", &["host.example.com"])];
        let dropped = clamp_managed_ssh_groups(&mut groups, &allowed(&[]));

        assert!(dropped.is_empty());
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].hosts().hosts,
            vec!["host.example.com".to_string()]
        );
    }

    #[test]
    fn only_managed_ssh_is_clamped_in_a_mixed_plan() {
        let mut groups = vec![
            managed("workers", &["node-a", "node-b"]),
            ssh("external", &["host.example.com"]),
        ];
        let dropped = clamp_managed_ssh_groups(&mut groups, &allowed(&["node-a"]));

        assert_eq!(dropped, vec!["node-b".to_string()]);
        assert_eq!(
            groups.len(),
            2,
            "the ssh group survives alongside the clamped managed one"
        );
    }
}
