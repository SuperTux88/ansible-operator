use std::{sync::Arc, time::Duration};

use futures::{Stream, StreamExt as _};
use k8s_openapi::api::core::v1::Node;
use kube::{
    Api,
    api::{ListParams, Patch, PatchParams},
    runtime::{
        Controller,
        controller::{self, Action},
        reflector::{Lookup, ObjectRef, store::Writer},
        watcher,
    },
};
use tracing::error;

use crate::v1beta1::{
    self, ClusterInventory, ClusterInventoryStatus,
    clusterinventorycontroller::mappers,
    controllers::{nodeselector::node_matches, reconcile_error::ReconcileError},
    distinct_host_count,
};

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
    let nodes_api: Api<Node> = Api::all(client.clone());

    let inventory_reflector_reader = {
        let inventory_reflector_writer = Writer::<v1beta1::ClusterInventory>::default();
        let inventory_reflector_reader = Arc::new(inventory_reflector_writer.as_reader());

        let inventory_reflector = kube::runtime::reflector(
            inventory_reflector_writer,
            watcher(inventories_api.clone(), watcher::Config::default()),
        );

        tokio::spawn(async move {
            inventory_reflector
                .for_each(|event| async {
                    match event {
                        Ok(_) => {}
                        Err(e) => error!("Reflector error: {e:?}"),
                    }
                })
                .await;
        });

        inventory_reflector_reader
    };

    Controller::new(inventories_api, watcher::Config::default())
        .watches(
            nodes_api,
            watcher::Config::default(),
            mappers::node_to_inventories(Arc::clone(&inventory_reflector_reader)),
        )
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

    let to_resolve = &object.spec.hosts;
    let resolved_hosts: Vec<v1beta1::ResolvedHosts> = to_resolve
        .iter()
        .map(|group| {
            let name = group.name.to_owned();
            let hosts = all_nodes
                .iter()
                .filter(|node| node_matches(node, group.match_labels.as_ref()))
                .map(|node| node.name().expect("name is set").to_string())
                .collect();

            v1beta1::ResolvedHosts { name, hosts }
        })
        .collect();

    // Over the distinct Nodes, not the group memberships: a Node matched by two groups is listed
    // in both, and this column sits directly above the plan's `n/m hosts` summaries, which have
    // always counted it once.
    let host_count = distinct_host_count(&resolved_hosts);

    let next_status = ClusterInventoryStatus {
        host_count,
        resolved_hosts,
    };

    let api: Api<ClusterInventory> = Api::namespaced(context.client.clone(), &namespace);
    patch_status(&api, &object, next_status).await?;

    Ok(Action::requeue(Duration::from_hours(1)))
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
