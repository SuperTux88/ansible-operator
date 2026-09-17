use std::{
    collections::{BTreeSet, HashSet},
    sync::Arc,
    time::Duration,
};

use futures::Stream;
use k8s_openapi::api::core::v1::Node;
use kube::{
    Api,
    api::{ListParams, PartialObjectMeta, Patch, PatchParams},
    runtime::{
        Controller,
        controller::{self, Action},
        reflector::{Lookup, ObjectRef},
        watcher,
    },
};

use crate::v1beta1::{
    self, ClusterInventory, ClusterInventoryStatus,
    controllers::{nodeselector::node_matches, reconcile_error::ReconcileError, selector_trigger},
    distinct_hosts,
};

use super::dependencies;

struct ReconciliationContext {
    client: kube::Client,
}
pub fn new(
    client: kube::Client,
) -> impl Stream<
    Item = Result<
        (ObjectRef<v1beta1::ClusterInventory>, Action),
        controller::Error<ReconcileError, kube::runtime::watcher::Error>,
    >,
> {
    let context = Arc::new(ReconciliationContext {
        client: client.clone(),
    });

    let inventories_api: Api<v1beta1::ClusterInventory> = Api::all(client.clone());
    // Metadata-only: `node_matches` reads labels and nothing else, and so does the trigger.
    let node_metadata_api: Api<PartialObjectMeta<Node>> = Api::all(client.clone());

    // Every inventory is recomputed on every tick, which is what the Node mapper this replaced did
    // too — a `ClusterInventory`'s status is a function of the whole Node set, so there is no
    // narrower answer to give. What changed is the *rate*: the mapper fired on every kubelet status
    // repost, and `selector_trigger::label_changes` fires only when the labels those inventories
    // select over actually move. `Controller::reconcile_all_on` reads the controller's own store,
    // so the hand-rolled reflector the mapper needed is gone with it.
    Controller::new(inventories_api, watcher::Config::default())
        // Every tick recomputes every inventory against the whole Node set, so a fleet being
        // labelled by a providing plan would otherwise buy one full recompute per Node —
        // see `selector_trigger::RECOMPUTE_DEBOUNCE`.
        .with_config(controller::Config::default().debounce(selector_trigger::RECOMPUTE_DEBOUNCE))
        .reconcile_all_on(selector_trigger::label_changes(node_metadata_api))
        .run(
            reconcile,
            |_, _, _| Action::requeue(std::time::Duration::from_secs(15)),
            Arc::clone(&context),
        )
}

async fn reconcile(
    object: Arc<v1beta1::ClusterInventory>,
    context: Arc<ReconciliationContext>,
) -> Result<Action, ReconcileError> {
    let namespace = object
        .namespace()
        .ok_or(ReconcileError::PreconditionFailed("namespace not set"))?;

    let nodes_api: Api<Node> = Api::all(context.client.clone());
    let all_nodes = nodes_api.list_metadata(&ListParams::default()).await?;

    let next_status = status_for(&object, &all_nodes.items);

    let api: Api<ClusterInventory> = Api::namespaced(context.client.clone(), &namespace);
    patch_status(&api, &object, next_status).await?;

    Ok(Action::requeue(Duration::from_hours(1)))
}

/// The status `object` has against `nodes`, the whole Node set.
fn status_for(
    object: &ClusterInventory,
    nodes: &[PartialObjectMeta<Node>],
) -> ClusterInventoryStatus {
    let to_resolve = &object.spec.hosts;
    let resolved_hosts: Vec<v1beta1::ResolvedHosts> = to_resolve
        .iter()
        .map(|group| {
            let name = group.name.to_owned();
            let hosts = nodes
                .iter()
                .filter(|node| node_matches(node, group.match_labels.as_ref()))
                .map(|node| node.name().expect("name is set").to_string())
                .collect();

            v1beta1::ResolvedHosts {
                name,
                hosts,
                ..Default::default()
            }
        })
        .collect();

    // The same Nodes, asked the complementary question: which of them this group would have taken
    // if another plan had finished with them. Computed in the pass that resolves the hosts and
    // published in the same write, so a plan reading both reads one observation — and the
    // `observedGeneration` below answers for the diagnostics exactly as it answers for the hosts.
    let mut dependencies = Vec::new();
    let mut waiting: BTreeSet<String> = BTreeSet::new();
    for group in to_resolve {
        let group_waits = dependencies::waits(&group.name, group.match_labels.as_ref(), nodes);
        dependencies.extend(group_waits.dependencies);
        waiting.extend(group_waits.waiting_hosts);
    }
    // Said out loud, because the cut is otherwise invisible: the status would report a subset of the
    // inventory's waits in exactly the shape of the whole set, and a reader troubleshooting a
    // dependency that is missing from it has no way to tell it was dropped. The bound is far above
    // any inventory anyone writes, so this should never be said at all.
    if dependencies.len() > dependencies::MAX_DEPENDENCIES {
        tracing::warn!(
            "ClusterInventory {}/{}: {} dependency requirements is past the {} the status publishes; the rest are not reported (the hosts and the waiting count still cover all of them)",
            object
                .metadata
                .namespace
                .as_deref()
                .unwrap_or("<no namespace>"),
            object.metadata.name.as_deref().unwrap_or("<no name>"),
            dependencies.len(),
            dependencies::MAX_DEPENDENCIES
        );
        dependencies.truncate(dependencies::MAX_DEPENDENCIES);
    }
    // A Node one group waits for and another already takes is in the inventory, so it is not kept
    // out of it: counting it would put one machine under both `Hosts` and `Waiting`, and the two
    // columns are read as disjoint. The per-group `dependencies` entries still count it, because
    // there it *is* waiting.
    let resolved: HashSet<String> = distinct_hosts(&resolved_hosts).into_iter().collect();
    waiting.retain(|node| !resolved.contains(node));

    // Published with the hosts it was computed from, in the same write: it is what tells a plan that
    // `resolvedHosts` answers for the spec the apiserver holds now, and not for the one before the
    // edit it has yet to see.
    ClusterInventoryStatus {
        observed_generation: object.metadata.generation,
        // Over the distinct Nodes, not the group memberships: a Node matched by two groups is
        // listed in both, and this column sits directly above the plan's `n/m hosts` summaries,
        // which have always counted it once.
        host_count: resolved.len(),
        resolved_hosts,
        // Counted over distinct Nodes for the same reason `hostCount` is: the two sit side by side
        // in the printer columns, and a Node waiting in two groups is one machine not joining.
        waiting_hosts: waiting.len(),
        dependencies,
    }
}

/// Persists `status` via a JSON merge patch, not `Api::replace_status` — see the identical
/// reasoning in `playbookplancontroller::reconciler::patch_status`.
async fn patch_status(
    api: &Api<ClusterInventory>,
    target: &ClusterInventory,
    status: ClusterInventoryStatus,
) -> Result<(), ReconcileError> {
    let name = target
        .name()
        .ok_or(ReconcileError::PreconditionFailed("name not set"))?;

    api.patch_status(
        &name,
        &PatchParams::default(),
        &Patch::Merge(serde_json::json!({ "status": status })),
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1beta1::{
        ClusterInventorySpec, InventoryHosts, NodeSelectorTerm, SelectorExpression,
        SelectorOperator, controllers::dependency_keys::label_key,
    };

    fn node(name: &str, labels: &[(&str, &str)]) -> PartialObjectMeta<Node> {
        let mut object = PartialObjectMeta::<Node>::default();
        object.metadata.name = Some(name.to_string());
        object.metadata.labels = Some(
            labels
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
        );
        object
    }

    fn group(name: &str, expressions: Vec<SelectorExpression>) -> InventoryHosts {
        InventoryHosts {
            name: name.to_string(),
            match_labels: Some(NodeSelectorTerm {
                match_labels: Some([("node-role".to_string(), "worker".to_string())].into()),
                match_expressions: Some(expressions),
            }),
            variables: None,
        }
    }

    fn inventory(groups: Vec<InventoryHosts>) -> ClusterInventory {
        let mut object = ClusterInventory::new(
            "workers",
            ClusterInventorySpec {
                hosts: groups,
                tolerations: None,
            },
        );
        object.metadata.generation = Some(3);
        object
    }

    /// The natural shape of an inventory with one broad group and one gated one: a worker the gated
    /// group waits for is already in the inventory through the broad one, so it is a host and not a
    /// waiting one. Only a Node no group takes is kept out.
    #[test]
    fn a_node_another_group_takes_is_not_waiting() {
        let key = label_key("platform", "hardening");
        let gated = SelectorExpression {
            operator: SelectorOperator::Exists,
            key: key.clone(),
            values: None,
        };

        let status = status_for(
            &inventory(vec![group("all", vec![]), group("hardened", vec![gated])]),
            &[
                node("hardened", &[("node-role", "worker"), (&key, "1.0.0")]),
                node("plain", &[("node-role", "worker")]),
            ],
        );

        assert_eq!(status.observed_generation, Some(3));
        assert_eq!(status.host_count, 2);
        assert_eq!(status.waiting_hosts, 0);
        assert_eq!(status.dependencies.len(), 1);
        assert_eq!(status.dependencies[0].waiting, 1);
        assert_eq!(status.dependencies[0].satisfied, 1);
    }

    /// However many requirements the spec writes, the status publishes a bounded number, and the
    /// hosts and the waiting count are still computed from all of them.
    #[test]
    fn the_published_requirements_are_bounded() {
        let key = label_key("platform", "hardening");
        let groups = (0..=dependencies::MAX_DEPENDENCIES)
            .map(|index| {
                group(
                    &format!("group-{index}"),
                    vec![SelectorExpression {
                        operator: SelectorOperator::Exists,
                        key: key.clone(),
                        values: None,
                    }],
                )
            })
            .collect();

        let status = status_for(
            &inventory(groups),
            &[node("plain", &[("node-role", "worker")])],
        );

        assert_eq!(status.dependencies.len(), dependencies::MAX_DEPENDENCIES);
        assert_eq!(status.waiting_hosts, 1);
    }

    /// Distinct Nodes on both sides: a Node waiting in two groups is one machine not joining, and a
    /// Node two groups take is one host.
    #[test]
    fn hosts_and_waiting_count_distinct_nodes() {
        let hardening = label_key("platform", "hardening");
        let containerd = label_key("platform", "containerd");
        let exists = |key: &str| SelectorExpression {
            operator: SelectorOperator::Exists,
            key: key.to_string(),
            values: None,
        };

        let status = status_for(
            &inventory(vec![
                group("hardened", vec![exists(&hardening)]),
                group("containerd", vec![exists(&containerd)]),
            ]),
            &[
                node(
                    "both",
                    &[
                        ("node-role", "worker"),
                        (&hardening, "1.0.0"),
                        (&containerd, "1.4.0"),
                    ],
                ),
                node("neither", &[("node-role", "worker")]),
                node("controlplane", &[("node-role", "controlplane")]),
            ],
        );

        assert_eq!(status.host_count, 1);
        assert_eq!(status.waiting_hosts, 1);
    }
}
