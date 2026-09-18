//! Publishing what a plan provides onto the Nodes it converged, so other plans can depend on it.
//!
//! A `PlaybookPlan` with `spec.provides` labels every cluster Node it applied to successfully with
//! `<namespace>.plan.ansible.cloudbending.dev/<plan-name>: <version>`. Another plan's
//! `ClusterInventory` selects on that label, so its runs only ever reach hosts the first plan has
//! finished with — the dependency is expressed as a *host set*, not as an ordering between runs,
//! which is what lets a level-triggered reconciler express it at all. A host that is not ready yet
//! is simply not in the run: it costs no attempt, holds no Lease and starts no proxy pod.
//!
//! Three properties are load-bearing:
//!
//! - **The operator owns the key.** It is derived from the plan's own namespace and name, never
//!   from anything a tenant writes. A tenant-chosen key would let a plan label its way past a
//!   `NodeAccessPolicy` ceiling, steer other people's workloads through a well-known key, or
//!   overwrite another plan's claim (INV-8, THREAT_MODEL T-ESC-3/T-ESC-9). The key itself lives in
//!   [`crate::v1beta1::controllers::dependency_keys`], because the dependent side has to recognise
//!   exactly what this side writes.
//! - **The labels are derived from recorded state, every tick, not written when a run finishes.**
//!   A crash between persisting a terminal status and patching the Nodes would otherwise lose the
//!   label for good. The order is *status first, labels after*: a label may lag the record, but it
//!   must never get ahead of it.
//! - **Only a real change is written.** A Node label change is broadcast to every Node watcher in
//!   the cluster — the scheduler, the DaemonSet controller, CNI agents, this operator's own three
//!   controllers. A converged plan must therefore write nothing at all, which is why the diff
//!   compares against what the Node already carries instead of patching unconditionally.

use k8s_openapi::api::core::v1::Node;
use kube::runtime::reflector::{ObjectRef, Store};

use crate::v1beta1::controllers::dependency_keys::{decode_key, is_operator_key};
use crate::v1beta1::{PlaybookPlan, PlaybookPlanStatus, ResolvedInventoryGroup};

use super::node_recreation::node_replaced_since;

pub use crate::v1beta1::controllers::dependency_keys::label_key;

/// A Node label this operator owns whose plan no longer exists.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Orphan {
    pub node: String,
    pub key: String,
}

/// Every operator-owned label in the cluster whose plan is gone.
///
/// The backstop for the deletions nothing reacted to: a plan removed while the operator was down,
/// one removed during a watch disconnection (a re-LIST announces no deletion, it simply drops the
/// object), or the operator being uninstalled and reinstalled. Those labels would otherwise stand
/// for ever, and dependents would keep treating those Nodes as ready — the one place this design
/// fails open, which is why it is swept rather than merely documented.
///
/// **`plans` must be a fully populated store.** Every judgement here is "no such plan", so a store
/// that is empty because it has not synced yet would strip every dependency label in the cluster.
/// The caller runs this only on a `watcher::Event::InitDone`, which the reflector emits *after*
/// swapping a complete LIST into the store.
///
/// A plan that exists but has dropped `spec.provides` is deliberately **not** swept: that is its own
/// reconcile's job, which knows the difference between "stopped providing" and "was never here".
/// This only ever judges absence, which is the one thing a reconcile can never observe.
pub fn orphaned_labels(nodes: &Store<Node>, plans: &Store<PlaybookPlan>) -> Vec<Orphan> {
    let mut orphans: Vec<Orphan> = nodes
        .state()
        .iter()
        .flat_map(|node| {
            let node_name = node.metadata.name.clone();
            node.metadata
                .labels
                .iter()
                .flatten()
                .filter(|(key, _)| is_operator_key(key))
                .filter(|(key, _)| {
                    decode_key(key).is_none_or(|(namespace, plan)| {
                        plans.get(&ObjectRef::new(plan).within(namespace)).is_none()
                    })
                })
                .filter_map(|(key, _)| {
                    Some(Orphan {
                        node: node_name.clone()?,
                        key: key.clone(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect();

    orphans.sort();
    orphans
}

/// The Nodes in the cache that carry `key`, whatever its value.
///
/// A linear scan of the Node store, which is where the removal paths start: they have to answer
/// "is anything still labelled for this plan?", and unlike the publish diff they cannot get that
/// from the plan's own host set — a label outlives the host leaving the inventory. In memory, so it
/// costs no API call on the overwhelmingly common answer of "nothing".
pub fn nodes_carrying(key: &str, nodes: &Store<Node>) -> Vec<String> {
    let mut carrying: Vec<String> = nodes
        .state()
        .iter()
        .filter(|node| {
            node.metadata
                .labels
                .as_ref()
                .is_some_and(|labels| labels.contains_key(key))
        })
        .filter_map(|node| node.metadata.name.clone())
        .collect();

    carrying.sort();
    carrying
}

/// How far a plan's key has got: the Nodes carrying it at all, and those carrying `version` exactly.
///
/// Two numbers because one cannot answer the question. A version bump leaves every Node on the
/// previous value until its host runs again, so a count of the key alone reads a rollout that has
/// not started as one that has finished; a count of the version alone loses the leftovers an admin
/// has to clean up where the feature is switched off.
#[derive(Debug, PartialEq, Eq)]
pub struct LabelReach {
    /// Nodes carrying the key at exactly the declared version — how far this rollout has got.
    pub at_version: usize,
    /// Nodes carrying the key at any version — the plan's whole reach.
    pub carrying: usize,
}

/// Counts both halves of [`LabelReach`] in one walk of the Node cache.
///
/// One pass rather than two, and no allocation: this runs for every providing plan on every tick,
/// and the counts are only ever read together.
pub fn label_reach(key: &str, version: &str, nodes: &Store<Node>) -> LabelReach {
    let mut reach = LabelReach {
        at_version: 0,
        carrying: 0,
    };

    for node in nodes.state().iter() {
        let Some(value) = node
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(key))
        else {
            continue;
        };
        reach.carrying += 1;
        if value == version {
            reach.at_version += 1;
        }
    }

    reach
}

/// The Nodes carrying `key` according to the API server rather than the cache.
///
/// For the paths that run where no cache answer can be trusted — chiefly a plan's deletion, which
/// is handled off the watch stream and has no reconcile, no status and no resolved inventory behind
/// it. A label selector does the filtering server-side, so this returns the Nodes to clean and
/// nothing else.
pub async fn nodes_carrying_live(
    client: &kube::Client,
    key: &str,
) -> Result<Vec<String>, kube::Error> {
    let nodes: kube::Api<Node> = kube::Api::all(client.clone());
    let list = nodes
        .list(&kube::api::ListParams::default().labels(key))
        .await?;

    Ok(list
        .items
        .into_iter()
        .filter_map(|node| node.metadata.name)
        .collect())
}

/// Strips `key` from the named Nodes, and returns how many lost it.
///
/// A JSON merge patch deletes a key only when it is explicitly `null` — omitting it means "leave it
/// alone", which is precisely the no-op this must not be.
pub async fn remove_labels(
    client: &kube::Client,
    key: &str,
    nodes: &[String],
    plan: &str,
) -> usize {
    let api: kube::Api<Node> = kube::Api::all(client.clone());
    let patch = serde_json::json!({ "metadata": { "labels": { key: serde_json::Value::Null } } });
    let mut removed = 0;

    for node in nodes {
        match api
            .patch(
                node,
                &kube::api::PatchParams::default(),
                &kube::api::Patch::Merge(&patch),
            )
            .await
        {
            Ok(_) => {
                removed += 1;
                tracing::info!("PlaybookPlan {plan}: removed {key} from Node {node}");
            }
            Err(error) => tracing::warn!(
                "PlaybookPlan {plan}: could not remove {key} from Node {node}: {error}"
            ),
        }
    }

    removed
}

/// One Node whose label has to change, and what it has to become.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LabelWrite {
    pub node: String,
    pub value: String,
}

/// The Nodes whose label for this plan is missing or out of date, and the value each needs.
///
/// Pure, and the whole decision: everything the patch loop does afterwards is mechanical.
///
/// The hosts come from the plan's **resolved managed-ssh groups**, never from `hostsStatus` alone.
/// That record is keyed by host *name*, so a `StaticInventory` host sharing a Node's name would
/// otherwise get that Node labelled for work done on an entirely different machine. External hosts
/// cannot take part in dependencies at all — there is no Kubernetes object to label.
///
/// A host is labelled only when all of this holds:
///
/// - it has an `appliedVersion`, which is stamped by exactly the outcome that stamps
///   `lastAppliedHash`. A host that failed, was unreachable, or received only part of a playbook
///   has none, and a record written before that field existed has none either.
/// - its Node is in the cache. The Node's current labels are needed to tell a change from a no-op,
///   and its `creationTimestamp` is needed for the next point.
/// - its Node is the machine the claim was recorded for. A machine rebuilt under its predecessor's
///   name inherits the name and nothing else, so labelling it would advertise software it has
///   never been given. `node_recreation` has already dropped such a claim earlier in the tick; this
///   asks the question again rather than depending on that, because the answer here is published to
///   the whole cluster and a caller that forgot the earlier pass must not be able to produce a false
///   label.
///
/// **Only ever adds and updates.** A label is never lowered or removed because a later run failed —
/// it says "this version was applied here at some point", which a failure does not undo — nor
/// because the host left the plan's inventory, since the software is still on the machine.
/// Removal has its own triggers and its own path.
pub fn desired_labels(
    key: &str,
    groups: &[ResolvedInventoryGroup],
    status: &PlaybookPlanStatus,
    nodes: &Store<Node>,
) -> Vec<LabelWrite> {
    let Some(hosts_status) = status.hosts_status.as_ref() else {
        return Vec::new();
    };

    let mut writes: Vec<LabelWrite> = groups
        .iter()
        .filter_map(|group| match group {
            ResolvedInventoryGroup::ManagedSsh { hosts, .. } => Some(hosts),
            ResolvedInventoryGroup::Ssh { .. } => None,
        })
        .flat_map(|hosts| hosts.hosts.iter())
        .filter_map(|host| {
            let record = hosts_status.get(host.as_str())?;
            let version = record.applied_version.as_deref()?;
            // An undated claim cannot be shown to belong to the machine standing there now, so it
            // is not published. `node_replaced_since` answers `false` for one, and rightly so for
            // the question *it* exists for — treating undated records as replacements would re-run
            // every plan in the fleet on the upgrade that introduced the field. Publishing is the
            // opposite trade: the cost of a wrong label is every dependent in the cluster acting on
            // it, so an unanswerable question fails closed here.
            let applied_at = record.applied_at?;
            let node = nodes.get(&ObjectRef::new(host))?;
            if node_replaced_since(Some(applied_at), &node) {
                return None;
            }
            let current = node
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(key));
            (current.map(String::as_str) != Some(version)).then(|| LabelWrite {
                node: host.clone(),
                value: version.to_string(),
            })
        })
        .collect();

    writes.sort();
    writes.dedup();
    writes
}

/// What one pass of [`write_labels`] did, in the two numbers its caller decides on.
#[derive(Debug, Default)]
pub struct LabelWrites {
    /// Patches the apiserver accepted.
    pub published: usize,
    /// Patches that failed for a reason another tick could plausibly clear — see
    /// [`worth_retrying_soon`].
    pub retryable: usize,
}

/// Whether a refused label patch is worth coming back for sooner than the plan otherwise would.
///
/// A refusal the cluster is going to repeat is not. The diff stays non-empty for as long as the
/// label is missing, so hurrying back for one would re-issue the same refused PATCH every few
/// seconds, for every providing plan, for as long as the cluster stays that way — and log a line
/// each time. Both ways of getting there are configuration only an administrator can fix: the
/// `nodes: patch` grant gone while `node_labels.enabled` is still on (the chart moves the two
/// together precisely so this cannot happen by accident), and the chart's
/// `ValidatingAdmissionPolicy` denying the write. Those wait for the plan's ordinary requeue, which
/// is what they did before this distinction existed.
///
/// A conflict, a throttle, an apiserver mid-restart or a connection that failed are the opposite:
/// nothing is wrong with the plan or the cluster's configuration, the write simply has to be made
/// again. That is worth hurrying for, because a converged `OneShot` provider has no other reason to
/// be looked at for an hour — `mappers::node_to_playbookplans` wakes a plan only for a Node it is
/// still waiting on — so every dependent would wait that hour for a label a second attempt would
/// have published.
///
/// A Node that is gone (404) is deliberately not in the retryable set: it leaves the cache, and with
/// it the diff.
fn worth_retrying_soon(error: &kube::Error) -> bool {
    match error {
        kube::Error::Api(status) => status.code == 409 || status.code == 429 || status.code >= 500,
        // Not a verdict from the apiserver at all — a connection that failed, a request that timed
        // out, a response that could not be read. Nothing about the plan produced it, and the patch
        // is idempotent, so it is treated as passing.
        _ => true,
    }
}

/// Applies a diff to the Nodes, one merge patch each, and reports what became of them.
///
/// One request per Node rather than anything cleverer: the diff is empty on a converged plan, so
/// the common case costs nothing, and the uncommon one is a plan rolling out — where the writes are
/// paced by the runs that produce them anyway.
///
/// A failure is logged and skipped rather than propagated. The labels are derived from recorded
/// state on every tick, so anything missed here is simply recomputed next time; failing the tick
/// instead would re-run everything around it for a label that will be retried regardless. The
/// counted failures are the caller's only sign that a retry is owed, though, because nothing else
/// about the tick changes when a label does not land.
pub async fn write_labels(
    client: &kube::Client,
    key: &str,
    writes: &[LabelWrite],
    plan: &str,
) -> LabelWrites {
    let nodes: kube::Api<Node> = kube::Api::all(client.clone());
    let mut written = LabelWrites::default();

    for write in writes {
        let patch = serde_json::json!({ "metadata": { "labels": { key: write.value } } });
        match nodes
            .patch(
                &write.node,
                &kube::api::PatchParams::default(),
                &kube::api::Patch::Merge(&patch),
            )
            .await
        {
            Ok(_) => {
                written.published += 1;
                tracing::info!(
                    "PlaybookPlan {plan}: labelled Node {} with {key}={}",
                    write.node,
                    write.value
                );
            }
            Err(error) => {
                if worth_retrying_soon(&error) {
                    written.retryable += 1;
                }
                tracing::warn!(
                    "PlaybookPlan {plan}: could not label Node {} with {key}={}: {error}",
                    write.node,
                    write.value
                );
            }
        }
    }

    written
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1beta1::{HostOutcome, HostStatus, ResolvedHosts, SecretRef, SshConfig};
    use chrono::{DateTime, FixedOffset};
    use kube::runtime::{reflector::store::Writer, watcher};
    use std::collections::BTreeMap;

    const KEY: &str = "platform.plan.ansible.cloudbending.dev/containerd";

    fn at(rfc3339: &str) -> DateTime<FixedOffset> {
        DateTime::parse_from_rfc3339(rfc3339).unwrap()
    }

    fn node(name: &str, created: &str, labels: &[(&str, &str)]) -> Node {
        Node {
            metadata: kube::core::ObjectMeta {
                name: Some(name.to_string()),
                creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    k8s_openapi::jiff::Timestamp::from_second(at(created).timestamp()).unwrap(),
                )),
                labels: Some(
                    labels
                        .iter()
                        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                        .collect(),
                ),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn store(nodes: Vec<Node>) -> Store<Node> {
        let mut writer = Writer::<Node>::default();
        let reader = writer.as_reader();
        writer.apply_watcher_event(&watcher::Event::Init);
        for node in nodes {
            writer.apply_watcher_event(&watcher::Event::InitApply(node));
        }
        writer.apply_watcher_event(&watcher::Event::InitDone);
        reader
    }

    fn managed(hosts: &[&str]) -> ResolvedInventoryGroup {
        ResolvedInventoryGroup::ManagedSsh {
            hosts: ResolvedHosts {
                name: "workers".into(),
                hosts: hosts.iter().map(|host| (*host).to_string()).collect(),
                ..Default::default()
            },
            tolerations: None,
            variables: None,
        }
    }

    fn external(hosts: &[&str]) -> ResolvedInventoryGroup {
        ResolvedInventoryGroup::Ssh {
            hosts: ResolvedHosts {
                name: "edge".into(),
                hosts: hosts.iter().map(|host| (*host).to_string()).collect(),
                ..Default::default()
            },
            static_inventory_name: "external".into(),
            config: SshConfig {
                user: "root".into(),
                secret_ref: SecretRef { name: "key".into() },
            },
            variables: None,
        }
    }

    fn applied(version: Option<&str>, applied_at: Option<&str>) -> HostStatus {
        HostStatus {
            last_applied_hash: "abc".into(),
            last_outcome: HostOutcome::Succeeded,
            applied_at: applied_at.map(at),
            applied_version: version.map(str::to_string),
            last_transition_time: Some(at("2026-01-01T00:00:00Z")),
        }
    }

    fn status_with(hosts: &[(&str, HostStatus)]) -> PlaybookPlanStatus {
        PlaybookPlanStatus {
            hosts_status: Some(
                hosts
                    .iter()
                    .map(|(host, record)| ((*host).to_string(), record.clone()))
                    .collect::<BTreeMap<_, _>>(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn the_key_is_built_from_the_plans_own_namespace_and_name() {
        assert_eq!(label_key("platform", "containerd"), KEY);
        assert_eq!(
            label_key("team-a", "harden"),
            "team-a.plan.ansible.cloudbending.dev/harden"
        );
    }

    /// The key has to fit Kubernetes' limits for every namespace and plan name the API server would
    /// accept, or the operator would build a key the Node patch is then rejected for.
    #[test]
    fn the_longest_legal_key_is_still_a_legal_key() {
        let key = label_key(&"n".repeat(63), &"p".repeat(63));
        let (prefix, name) = key.split_once('/').unwrap();

        assert!(prefix.len() <= 253, "prefix was {}", prefix.len());
        assert!(name.len() <= 63, "name was {}", name.len());
    }

    #[test]
    fn a_converged_host_is_labelled_with_the_version_it_applied() {
        let writes = desired_labels(
            KEY,
            &[managed(&["node-a"])],
            &status_with(&[(
                "node-a",
                applied(Some("1.4.2"), Some("2026-01-02T00:00:00Z")),
            )]),
            &store(vec![node("node-a", "2026-01-01T00:00:00Z", &[])]),
        );

        assert_eq!(
            writes,
            vec![LabelWrite {
                node: "node-a".into(),
                value: "1.4.2".into()
            }]
        );
    }

    /// The fleet-scale requirement. Every Node label change is broadcast to every Node watcher in
    /// the cluster, so a plan that has converged must be silent — not merely idempotent.
    #[test]
    fn a_node_that_already_carries_the_value_is_not_written_again() {
        let writes = desired_labels(
            KEY,
            &[managed(&["node-a"])],
            &status_with(&[(
                "node-a",
                applied(Some("1.4.2"), Some("2026-01-02T00:00:00Z")),
            )]),
            &store(vec![node(
                "node-a",
                "2026-01-01T00:00:00Z",
                &[(KEY, "1.4.2")],
            )]),
        );

        assert!(writes.is_empty());
    }

    #[test]
    fn a_node_carrying_an_older_version_is_updated() {
        let writes = desired_labels(
            KEY,
            &[managed(&["node-a"])],
            &status_with(&[(
                "node-a",
                applied(Some("1.5.0"), Some("2026-01-02T00:00:00Z")),
            )]),
            &store(vec![node(
                "node-a",
                "2026-01-01T00:00:00Z",
                &[(KEY, "1.4.2")],
            )]),
        );

        assert_eq!(
            writes.first().map(|write| write.value.as_str()),
            Some("1.5.0")
        );
    }

    /// A host with no version has not succeeded under a revision that declared one — it failed, was
    /// unreachable, received only part of the playbook, or its record predates the field. Every one
    /// of those must read as "nothing to advertise" rather than as an empty claim.
    #[test]
    fn a_host_that_has_applied_no_version_is_not_labelled() {
        let writes = desired_labels(
            KEY,
            &[managed(&["node-a"])],
            &status_with(&[("node-a", applied(None, Some("2026-01-02T00:00:00Z")))]),
            &store(vec![node("node-a", "2026-01-01T00:00:00Z", &[])]),
        );

        assert!(writes.is_empty());
    }

    /// Phase 0a is a prerequisite for exactly this: the record is keyed by name, and the name is all
    /// a replacement machine inherits. Labelling it would tell the whole cluster that a freshly
    /// imaged Node carries software nobody has put there.
    #[test]
    fn a_node_rebuilt_since_the_claim_is_not_labelled() {
        let writes = desired_labels(
            KEY,
            &[managed(&["node-a"])],
            &status_with(&[(
                "node-a",
                applied(Some("1.4.2"), Some("2026-01-02T00:00:00Z")),
            )]),
            &store(vec![node("node-a", "2026-01-03T00:00:00Z", &[])]),
        );

        assert!(writes.is_empty());
    }

    /// A record that predates `appliedAt` cannot be dated, so it cannot be told apart from a
    /// replacement. It is left unlabelled rather than guessed at; its next success fills the field
    /// in.
    #[test]
    fn a_claim_that_cannot_be_dated_is_not_labelled() {
        let writes = desired_labels(
            KEY,
            &[managed(&["node-a"])],
            &status_with(&[("node-a", applied(Some("1.4.2"), None))]),
            &store(vec![node("node-a", "2026-01-03T00:00:00Z", &[])]),
        );

        assert!(writes.is_empty());
    }

    /// `hostsStatus` is keyed by name alone, so an external host named like a cluster Node would
    /// otherwise have that Node labelled for work done on a different machine entirely.
    #[test]
    fn an_external_host_never_labels_a_node_that_shares_its_name() {
        let writes = desired_labels(
            KEY,
            &[external(&["node-a"])],
            &status_with(&[(
                "node-a",
                applied(Some("1.4.2"), Some("2026-01-02T00:00:00Z")),
            )]),
            &store(vec![node("node-a", "2026-01-01T00:00:00Z", &[])]),
        );

        assert!(writes.is_empty());
    }

    /// A cache miss is not evidence of anything, and the Node's own labels are what a no-op is
    /// judged against — without them the diff would write on every tick.
    #[test]
    fn a_host_with_no_node_in_the_cache_is_skipped() {
        let writes = desired_labels(
            KEY,
            &[managed(&["node-a"])],
            &status_with(&[(
                "node-a",
                applied(Some("1.4.2"), Some("2026-01-02T00:00:00Z")),
            )]),
            &store(vec![]),
        );

        assert!(writes.is_empty());
    }

    /// A host that left the inventory keeps its label: the software is still on the machine. The
    /// diff simply stops considering it, and never removes what it stops seeing.
    #[test]
    fn only_hosts_in_the_resolved_groups_are_considered() {
        let status = status_with(&[
            (
                "node-a",
                applied(Some("1.4.2"), Some("2026-01-02T00:00:00Z")),
            ),
            (
                "node-b",
                applied(Some("1.4.2"), Some("2026-01-02T00:00:00Z")),
            ),
        ]);
        let nodes = store(vec![
            node("node-a", "2026-01-01T00:00:00Z", &[]),
            node("node-b", "2026-01-01T00:00:00Z", &[(KEY, "1.4.2")]),
        ]);

        let writes = desired_labels(KEY, &[managed(&["node-a"])], &status, &nodes);

        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].node, "node-a");
    }

    fn plan_store(plans: &[(&str, &str)]) -> Store<PlaybookPlan> {
        let mut writer = Writer::<PlaybookPlan>::default();
        let reader = writer.as_reader();
        writer.apply_watcher_event(&watcher::Event::Init);
        for (namespace, name) in plans {
            let mut plan = PlaybookPlan::new(name, Default::default());
            plan.metadata.namespace = Some((*namespace).to_string());
            writer.apply_watcher_event(&watcher::Event::InitApply(plan));
        }
        writer.apply_watcher_event(&watcher::Event::InitDone);
        reader
    }

    /// The backstop for a deletion nothing reacted to. Only absence is judged — a plan that still
    /// exists is its own reconcile's business, whether or not it still provides anything.
    #[test]
    fn only_labels_whose_plan_is_gone_are_swept() {
        let nodes = store(vec![
            node(
                "node-a",
                "2026-01-01T00:00:00Z",
                &[
                    (KEY, "1.4.2"),
                    ("team-a.plan.ansible.cloudbending.dev/gone", "2.0"),
                    ("node-role.kubernetes.io/worker", ""),
                ],
            ),
            node(
                "node-b",
                "2026-01-01T00:00:00Z",
                &[("team-a.plan.ansible.cloudbending.dev/gone", "2.0")],
            ),
        ]);

        let orphans = orphaned_labels(&nodes, &plan_store(&[("platform", "containerd")]));

        assert_eq!(
            orphans,
            vec![
                Orphan {
                    node: "node-a".into(),
                    key: "team-a.plan.ansible.cloudbending.dev/gone".into()
                },
                Orphan {
                    node: "node-b".into(),
                    key: "team-a.plan.ansible.cloudbending.dev/gone".into()
                },
            ],
            "the live plan's label stays, and a foreign label is never touched"
        );
    }

    /// A plan of the same name in another namespace is a different plan. Getting this wrong would
    /// sweep a healthy plan's labels the moment a same-named plan elsewhere was deleted.
    #[test]
    fn a_plan_is_matched_within_its_own_namespace() {
        let nodes = store(vec![node(
            "node-a",
            "2026-01-01T00:00:00Z",
            &[(&label_key("platform", "harden"), "1.0")],
        )]);

        assert!(orphaned_labels(&nodes, &plan_store(&[("platform", "harden")])).is_empty());
        assert_eq!(
            orphaned_labels(&nodes, &plan_store(&[("other", "harden")])).len(),
            1,
            "same name, different namespace, different plan"
        );
    }

    /// The property the caller's `InitDone` gating exists for, stated as a test: against a store
    /// that has not synced, *everything* reads as orphaned. Nothing in this function can detect
    /// that, which is why it is documented as a precondition and gated at the call site.
    #[test]
    fn an_empty_plan_store_would_condemn_every_label() {
        let nodes = store(vec![node(
            "node-a",
            "2026-01-01T00:00:00Z",
            &[(KEY, "1.4.2")],
        )]);

        assert_eq!(orphaned_labels(&nodes, &plan_store(&[])).len(), 1);
    }

    /// What the removal paths start from. It cannot come from the plan's host set: a label outlives
    /// the host leaving the inventory, so "everything still carrying my key" is a different question
    /// from "everything I currently target".
    #[test]
    fn nodes_carrying_the_key_are_found_whatever_their_value() {
        let nodes = store(vec![
            node("node-a", "2026-01-01T00:00:00Z", &[(KEY, "1.4.2")]),
            node("node-b", "2026-01-01T00:00:00Z", &[(KEY, "1.5.0")]),
            node("node-c", "2026-01-01T00:00:00Z", &[("other", "x")]),
            node("node-d", "2026-01-01T00:00:00Z", &[]),
        ]);

        assert_eq!(nodes_carrying(KEY, &nodes), vec!["node-a", "node-b"]);
        assert!(
            nodes_carrying("team-b.plan.ansible.cloudbending.dev/other", &nodes).is_empty(),
            "another plan's key is not this plan's to remove"
        );
    }

    /// A version bump leaves every Node carrying the key at the old value until each host has run
    /// again, so only an exact match counts as reached — while the reach itself does not move.
    #[test]
    fn only_nodes_carrying_the_exact_version_count_as_reached() {
        let nodes = store(vec![
            node("node-a", "2026-01-01T00:00:00Z", &[(KEY, "1.4.2")]),
            node("node-b", "2026-01-01T00:00:00Z", &[(KEY, "1.5.0")]),
            node("node-c", "2026-01-01T00:00:00Z", &[(KEY, "1.5.0-rc1")]),
            node("node-d", "2026-01-01T00:00:00Z", &[("other", "1.5.0")]),
            node("node-e", "2026-01-01T00:00:00Z", &[]),
        ]);

        for (version, at_version) in [("1.5.0", 1), ("1.4.2", 1), ("2.0.0", 0)] {
            assert_eq!(
                label_reach(KEY, version, &nodes),
                LabelReach {
                    at_version,
                    carrying: 3
                },
                "at {version}"
            );
        }

        assert_eq!(
            label_reach("team-b.plan.ansible.cloudbending.dev/other", "1.0", &nodes),
            LabelReach {
                at_version: 0,
                carrying: 0
            },
            "another plan's key is not this plan's reach"
        );
    }

    #[test]
    fn a_plan_that_has_never_run_writes_nothing() {
        let writes = desired_labels(
            KEY,
            &[managed(&["node-a"])],
            &PlaybookPlanStatus::default(),
            &store(vec![node("node-a", "2026-01-01T00:00:00Z", &[])]),
        );

        assert!(writes.is_empty());
    }

    /// The caller shortens its requeue on a failure counted here, so what must not be counted is a
    /// refusal that the next attempt will meet again: the diff never empties, and the plan would
    /// poll the apiserver with the same refused PATCH for as long as the cluster stayed that way.
    #[test]
    fn only_a_refusal_another_attempt_could_clear_is_worth_hurrying_back_for() {
        let api_error = |code| {
            kube::Error::Api(Box::new(kube::core::Status {
                code,
                ..Default::default()
            }))
        };

        // The `nodes: patch` grant is gone, or the chart's ValidatingAdmissionPolicy is denying the
        // write. Both need an administrator; neither is fixed by asking again in 15 seconds.
        assert!(!worth_retrying_soon(&api_error(403)));
        assert!(!worth_retrying_soon(&api_error(401)));
        // The Node is gone, and leaves the diff with the cache.
        assert!(!worth_retrying_soon(&api_error(404)));

        // Nothing about the plan or the cluster's configuration decided these.
        assert!(worth_retrying_soon(&api_error(409)));
        assert!(worth_retrying_soon(&api_error(429)));
        assert!(worth_retrying_soon(&api_error(500)));
        assert!(worth_retrying_soon(&api_error(503)));
    }
}
