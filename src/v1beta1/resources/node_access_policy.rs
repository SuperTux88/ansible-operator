use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1beta1::LabelSelector;

/// Cluster-admin-authored, **cluster-scoped** policy that caps which cluster Nodes a namespace's
/// `ClusterInventory` resources may resolve.
///
/// `ClusterInventory` confers node-root (its managed-ssh proxy pods run with hostPID + nsenter), so
/// any namespace allowed to create one could otherwise target *any* node. A `NodeAccessPolicy` maps
/// a set of namespaces to a *ceiling* set of nodes; a `ClusterInventory`'s resolved nodes are
/// intersected with that ceiling before any proxy infra is created.
///
/// # Trust model
///
/// The policy is cluster-scoped, so authoring one requires cluster-level RBAC (the cluster admin) —
/// a different principal than the tenant who authors the namespaced `ClusterInventory`. Enforcement
/// is an intersection, so it can only ever *shrink* a tenant's node set: a forged or buggy request
/// can never reach a node the policy didn't grant.
///
/// # Fail-closed
///
/// A namespace with no matching policy resolves to zero allowed nodes. An empty selector (`{}`)
/// matches *nothing*, not everything — to grant all nodes, match a ubiquitous label explicitly,
/// e.g. `matchExpressions: [{ key: kubernetes.io/hostname, operator: Exists }]`. The effective
/// allow-set for a namespace is the union across every policy whose `namespaceSelector` matches it.
#[derive(CustomResource, Debug, Serialize, Deserialize, Default, Clone, JsonSchema)]
#[kube(
    group = "ansible.cloudbending.dev",
    version = "v1beta1",
    kind = "NodeAccessPolicy",
    status = "NodeAccessPolicyStatus",
    printcolumn = r#"{"name":"Allowed nodes","type":"integer","jsonPath":".status.allowedNodeCount"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct NodeAccessPolicySpec {
    /// Selects the namespaces this policy grants node access to, by namespace labels. Kubernetes
    /// stamps every namespace with its own name as `kubernetes.io/metadata.name`, so a single
    /// namespace is targeted with `matchLabels: { kubernetes.io/metadata.name: business-app }` —
    /// there is deliberately no separate name field. An empty selector matches no namespaces.
    pub namespace_selector: LabelSelector,

    /// The ceiling of Nodes that the matched namespaces' `ClusterInventory` resources may resolve,
    /// by node labels. A `ClusterInventory`'s resolved nodes are intersected with the Nodes
    /// matching this selector. An empty selector matches no nodes; to allow every node, match a
    /// ubiquitous label with `Exists` (see the type-level docs).
    pub node_selector: LabelSelector,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeAccessPolicyStatus {
    /// Namespaces currently matched by `namespaceSelector`, for observability.
    pub matched_namespaces: Vec<String>,
    /// Number of Nodes currently matched by `nodeSelector` — the size of the ceiling. `i64` (not
    /// `usize`) so the generated CRD carries the Kubernetes-recognized `format: int64` rather than
    /// `uint`, which the API server warns about on apply.
    pub allowed_node_count: i64,
    /// Every node name currently matched by `nodeSelector`, alphabetically sorted — the concrete
    /// set of nodes this policy's ceiling resolves to. `allowedNodeCount` is its length (kept for
    /// the printer column, which can't take an array's length).
    pub allowed_nodes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_example() {
        let policy_str = include_str!("../../../examples/v1beta1/node-access-policy.yaml");
        // The example is a multi-document stream (tenant scope + admin allow-all), so parse each.
        let policies: Vec<NodeAccessPolicy> = serde_saphyr::from_multiple(policy_str).unwrap();
        assert_eq!(policies.len(), 2);
    }
}
