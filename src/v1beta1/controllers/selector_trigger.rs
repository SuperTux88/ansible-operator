use std::collections::{BTreeMap, HashMap};
use std::hash::{DefaultHasher, Hash as _, Hasher as _};

use futures::{Stream, StreamExt as _};
use kube::runtime::watcher;
use kube::{Api, Resource, ResourceExt as _};
use serde::de::DeserializeOwned;
use tracing::{debug, error};

/// Emits one tick whenever a watched object's **labels** change, it appears, or it disappears —
/// and stays silent for every other update.
///
/// This exists for the controllers whose status is a function of a whole *selected set*
/// (`ClusterInventory` over Nodes, `NodeAccessPolicy` over Nodes and Namespaces). Their triggers
/// used to map any event on a watched object to *every* object they own, which was correct and
/// ruinously loud: kubelets repost Node status roughly every five minutes
/// (`nodeStatusReportFrequency`) and every one of those reposts recomputed a byte-identical status,
/// each recomputation costing a cluster-wide `list_metadata` and a status patch. The load was
/// `nodes × 12/hour × (inventories + policies)`, roughly quadratic in cluster size, for zero change
/// in output.
///
/// A status repost never touches labels, so hashing them is the whole filter — but only because
/// **labels are exactly what the selectors read**: `nodeselector::node_matches` and
/// `nodeselector::selector_matches_fail_closed` consult `metadata.labels` and nothing else. A
/// selector term that ever reads a taint, an annotation or a spec field would be invisible to this
/// trigger and would silently stop reaching its controller, so the two have to move together.
///
/// The event kind is why this is a hand-built stream rather than `Controller::watches` with a
/// narrower mapper, or `WatchStreamExt::predicate_filter`. Both of those see only the object:
/// `trigger_others` flattens `watcher::Event` through `touched_objects()`, and a deleted object
/// still carries the labels it matched with, so either would treat a deletion as "nothing changed"
/// and leave a departed Node in the inventory until the hourly requeue — during which plans target
/// a machine that no longer exists. `Controller::reconcile_all_on` takes a prepared stream, so the
/// filter can be written where `Event::Delete` is still distinguishable.
///
/// Call sites pass an `Api<PartialObjectMeta<K>>`, which kube turns into metadata-only requests: the
/// label map is all this reads and all the reconciles it wakes read, so the apiserver sends
/// `PartialObjectMetadata` instead of whole Nodes, roughly a tenth of the bytes per event.
pub fn label_changes<M>(api: Api<M>) -> impl Stream<Item = ()> + Send + 'static
where
    M: Resource + Clone + DeserializeOwned + std::fmt::Debug + Send + 'static,
    M::DynamicType: Default,
{
    let kind = M::kind(&M::DynamicType::default()).to_string();

    watcher(api, watcher::Config::default())
        .scan(TrackedLabels::default(), move |tracked, event| {
            let tick = match event {
                Ok(event) => tracked.absorb(&kind, event),
                Err(error) => {
                    // The watcher retries on its own; a tick here would reconcile everything
                    // against state this stream has not seen yet.
                    error!("{kind} watch error, waiting for the watcher to re-establish: {error}");
                    None
                }
            };
            futures::future::ready(Some(tick))
        })
        .filter_map(futures::future::ready)
}

/// The label fingerprints this stream has already reported, keyed by the object's identity.
///
/// A `Delete` removes its entry, so a name that is deleted and recreated with the same labels
/// reports twice, which is correct: the second object is a different machine.
#[derive(Default)]
struct TrackedLabels {
    seen: HashMap<ObjectKey, u64>,
    /// Non-`None` only between `Init` and `InitDone`, where it accumulates the relisted set.
    initializing: Option<HashMap<ObjectKey, u64>>,
}

type ObjectKey = (Option<String>, String);

impl TrackedLabels {
    /// Folds one watch event in, returning `Some(())` when the selected set may have moved.
    fn absorb<K: Resource>(&mut self, kind: &str, event: watcher::Event<K>) -> Option<()> {
        match event {
            watcher::Event::Apply(object) => {
                let (key, hash) = fingerprint(&object);
                let changed = self.seen.insert(key.clone(), hash) != Some(hash);
                if changed {
                    debug!("{kind} {} changed its labels", key.1);
                }
                changed.then_some(())
            }
            watcher::Event::Delete(object) => {
                let (key, _) = fingerprint(&object);
                self.seen.remove(&key);
                debug!("{kind} {} was deleted", key.1);
                Some(())
            }
            // A restarted watch relists everything, so the events below are not news by themselves.
            // What they can carry is news the disconnect swallowed: an object deleted while the
            // watch was down is simply absent from the relist, with no `Delete` to announce it. So
            // the set is rebuilt to one side and compared once, at `InitDone`.
            watcher::Event::Init => {
                self.initializing = Some(HashMap::new());
                None
            }
            watcher::Event::InitApply(object) => {
                let (key, hash) = fingerprint(&object);
                self.initializing
                    .get_or_insert_with(HashMap::new)
                    .insert(key, hash);
                None
            }
            watcher::Event::InitDone => {
                let relisted = self.initializing.take()?;
                let changed = relisted != self.seen;
                self.seen = relisted;
                if changed {
                    debug!("{kind} set moved while the watch was re-establishing");
                }
                changed.then_some(())
            }
        }
    }
}

fn fingerprint<K: Resource>(object: &K) -> (ObjectKey, u64) {
    let meta = object.meta();
    let key = (
        meta.namespace.clone(),
        meta.name.clone().unwrap_or_default(),
    );
    (key, hash_labels(object.labels()))
}

fn hash_labels(labels: &BTreeMap<String, String>) -> u64 {
    let mut hasher = DefaultHasher::new();
    labels.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::Node;
    use kube::api::PartialObjectMeta;
    use kube::core::{ObjectMeta, PartialObjectMetaExt as _};

    fn node(name: &str, labels: &[(&str, &str)]) -> PartialObjectMeta<Node> {
        ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(
                labels
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
            ..Default::default()
        }
        .into_response_partial::<Node>()
    }

    /// The whole point: a kubelet status repost re-sends the same object with the same labels, and
    /// there is nothing for a set-valued status to recompute.
    #[test]
    fn a_repeated_apply_with_unchanged_labels_is_silent() {
        let mut tracked = TrackedLabels::default();
        let worker = node("node-a", &[("role", "worker")]);

        assert_eq!(
            tracked.absorb("Node", watcher::Event::Apply(worker.clone())),
            Some(()),
            "the first sighting is news"
        );
        for _ in 0..5 {
            assert_eq!(
                tracked.absorb("Node", watcher::Event::Apply(worker.clone())),
                None
            );
        }
    }

    #[test]
    fn a_label_change_ticks() {
        let mut tracked = TrackedLabels::default();
        tracked.absorb("Node", watcher::Event::Apply(node("node-a", &[])));

        assert_eq!(
            tracked.absorb(
                "Node",
                watcher::Event::Apply(node("node-a", &[("role", "worker")]))
            ),
            Some(())
        );
    }

    /// The case that rules out filtering on the object alone — a deleted Node still carries the
    /// labels that matched, so any predicate over its content reads "unchanged" and leaves a
    /// machine that no longer exists in the resolved host list.
    #[test]
    fn a_deletion_ticks_even_though_its_labels_are_unchanged() {
        let mut tracked = TrackedLabels::default();
        let worker = node("node-a", &[("role", "worker")]);
        tracked.absorb("Node", watcher::Event::Apply(worker.clone()));

        assert_eq!(
            tracked.absorb("Node", watcher::Event::Delete(worker.clone())),
            Some(())
        );
        assert_eq!(
            tracked.absorb("Node", watcher::Event::Apply(worker)),
            Some(()),
            "a name that comes back is a new machine, not a repeat"
        );
    }

    /// A relist that reports exactly what was already known is not news, however many objects it
    /// carries — otherwise every `410 Expired` would reconcile the whole cluster.
    #[test]
    fn an_unchanged_relist_is_silent() {
        let mut tracked = TrackedLabels::default();
        for name in ["node-a", "node-b"] {
            tracked.absorb("Node", watcher::Event::Apply(node(name, &[("r", "w")])));
        }

        assert_eq!(
            tracked.absorb::<PartialObjectMeta<Node>>("Node", watcher::Event::Init),
            None
        );
        for name in ["node-a", "node-b"] {
            assert_eq!(
                tracked.absorb("Node", watcher::Event::InitApply(node(name, &[("r", "w")]))),
                None,
                "individual relist entries are buffered, never reported"
            );
        }
        assert_eq!(
            tracked.absorb::<PartialObjectMeta<Node>>("Node", watcher::Event::InitDone),
            None
        );
    }

    /// The reason the relist is diffed rather than ignored: an object deleted while the watch was
    /// down is simply missing from the new list, and no `Delete` event ever announces it.
    #[test]
    fn a_relist_that_lost_an_object_ticks() {
        let mut tracked = TrackedLabels::default();
        for name in ["node-a", "node-b"] {
            tracked.absorb("Node", watcher::Event::Apply(node(name, &[("r", "w")])));
        }

        tracked.absorb::<PartialObjectMeta<Node>>("Node", watcher::Event::Init);
        tracked.absorb(
            "Node",
            watcher::Event::InitApply(node("node-a", &[("r", "w")])),
        );

        assert_eq!(
            tracked.absorb::<PartialObjectMeta<Node>>("Node", watcher::Event::InitDone),
            Some(())
        );
        assert_eq!(
            tracked.absorb("Node", watcher::Event::Apply(node("node-a", &[("r", "w")]))),
            None,
            "the surviving object is still tracked at its relisted fingerprint"
        );
    }

    #[test]
    fn a_relist_that_changed_a_label_ticks() {
        let mut tracked = TrackedLabels::default();
        tracked.absorb("Node", watcher::Event::Apply(node("node-a", &[("r", "w")])));

        tracked.absorb::<PartialObjectMeta<Node>>("Node", watcher::Event::Init);
        tracked.absorb(
            "Node",
            watcher::Event::InitApply(node("node-a", &[("r", "cp")])),
        );

        assert_eq!(
            tracked.absorb::<PartialObjectMeta<Node>>("Node", watcher::Event::InitDone),
            Some(())
        );
    }

    /// Namespaces are watched by the same helper and are namespace-less themselves, but the key
    /// carries a namespace so the helper stays usable for namespaced kinds without two objects of
    /// the same name in different namespaces colliding.
    #[test]
    fn objects_of_the_same_name_in_different_namespaces_are_distinct() {
        let mut tracked = TrackedLabels::default();
        let in_namespace = |namespace: &str| {
            ObjectMeta {
                name: Some("shared".into()),
                namespace: Some(namespace.to_string()),
                labels: Some(BTreeMap::new()),
                ..Default::default()
            }
            .into_response_partial::<Node>()
        };

        assert_eq!(
            tracked.absorb("Node", watcher::Event::Apply(in_namespace("a"))),
            Some(())
        );
        assert_eq!(
            tracked.absorb("Node", watcher::Event::Apply(in_namespace("b"))),
            Some(()),
            "a different namespace is a different object, not a repeat"
        );
    }
}
