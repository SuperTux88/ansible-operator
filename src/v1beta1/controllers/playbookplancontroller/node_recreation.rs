//! Whether the machine behind a recorded host is still the one that record was written for.
//!
//! `hostsStatus` is keyed by host *name*, and a Node can be deleted and re-registered under that
//! same name — a re-imaged machine, a reprovisioned VM, a node pool the cloud provider rolled. The
//! fresh Node inherits nothing from its predecessor, but the *record* does: `lastAppliedHash` still
//! names the revision the old machine applied, so `find_outdated_hosts` counts the new one as
//! current and a `OneShot` plan never runs on it again.
//!
//! The question is answered by comparing identities rather than by reacting to the deletion,
//! because a deletion is an event and this has to be answerable from state alone. An operator that
//! was down while the machine was replaced, or one whose plan sat in a namespace that was not
//! enrolled at the time, never sees a deletion — only a Node that exists under a familiar name.
//! Comparing the Node's `metadata.uid` against the uid recorded with the claim needs no such
//! history, which is what makes it agree with the rest of this level-triggered reconciler. It is an
//! identity and not a timestamp on purpose: `creationTimestamp` comes from the apiserver's clock and
//! the claim's date from the operator's, so any comparison between them measures clock skew as well.

use std::collections::HashSet;

use k8s_openapi::api::core::v1::Node;
use kube::runtime::reflector::{ObjectRef, Store};

use crate::v1beta1::{PlaybookPlanStatus, ResolvedInventoryGroup};

/// Whether `node` is a different machine from the one a record with this `applied_node_uid`
/// describes.
///
/// Both halves are required, and a missing one answers "no" deliberately:
///
/// - **no `applied_node_uid`** is a record written before that field existed, or for a host whose
///   Node was not in the cache when it succeeded. Treating it as a replacement would re-run every
///   plan in the fleet on the upgrade that introduced this; the next success fills the field in,
///   and until then the record stands exactly as it was.
/// - **no `uid`** is a Node the apiserver has not stamped, which nothing but a hand-built object
///   can be.
pub fn node_replaced_since(applied_node_uid: Option<&str>, node: &Node) -> bool {
    let (Some(applied), Some(current)) = (applied_node_uid, node.metadata.uid.as_deref()) else {
        return false;
    };

    applied != current
}

/// The uid of the Node named `host`, if the cache has one — what a success on that host records as
/// the machine it was applied to.
pub fn current_node_uid(nodes: &Store<Node>, host: &str) -> Option<String> {
    nodes.get(&ObjectRef::new(host))?.metadata.uid.clone()
}

/// Drops the recorded application of every managed-ssh host whose Node is not the machine the
/// record was written about, returning the hosts that lost theirs.
///
/// Only the *claim* is dropped — `lastAppliedHash`, `appliedAt`, `appliedNodeUid` and
/// `appliedVersion` — and never the outcome or the time it was recorded: what happened to the
/// previous machine is history worth keeping, while the claim that this host carries the current
/// revision is the half that is now false. The version goes with the rest because it is what a
/// Node label is derived from, and a fresh machine that kept it would be labelled for software it
/// has never been given.
///
/// Three things are deliberately left alone:
///
/// - **hosts outside the plan's managed-ssh groups.** `hostsStatus` is keyed by name, so a
///   `StaticInventory` host that happens to share a Node's name would otherwise have its record
///   reset because an unrelated Node was replaced. Nothing about an external machine is knowable
///   from a Node object.
/// - **a host with no Node in the cache.** A miss is not evidence here: the Node may be gone, or the
///   watch may be behind. Only a Node that is *present* and different can establish a replacement.
/// - **a record with no `appliedNodeUid`** — see [`node_replaced_since`].
pub fn drop_records_for_recreated_nodes(
    nodes: &Store<Node>,
    groups: &[ResolvedInventoryGroup],
    status: &mut PlaybookPlanStatus,
) -> Vec<String> {
    let Some(hosts_status) = status.hosts_status.as_mut() else {
        return Vec::new();
    };

    let mut replaced: Vec<String> = groups
        .iter()
        .filter_map(|group| match group {
            ResolvedInventoryGroup::ManagedSsh { hosts, .. } => Some(hosts),
            ResolvedInventoryGroup::Ssh { .. } => None,
        })
        .flat_map(|hosts| hosts.hosts.iter())
        .filter(|host| {
            hosts_status.get(host.as_str()).is_some_and(|record| {
                nodes.get(&ObjectRef::new(host)).is_some_and(|node| {
                    node_replaced_since(record.applied_node_uid.as_deref(), &node)
                })
            })
        })
        .cloned()
        .collect();

    replaced.sort();
    replaced.dedup();

    for host in &replaced {
        if let Some(record) = hosts_status.get_mut(host) {
            record.last_applied_hash = String::new();
            record.applied_at = None;
            record.applied_node_uid = None;
            record.applied_version = None;
        }
    }

    replaced
}

/// Drops the `appliedNodeUid` of every host the plan reaches only through `Ssh` groups, so that a
/// record carries a machine identity only while its host is a Node.
///
/// A success stamps the uid of whatever Node shares the host's name, and `hostsStatus` is keyed by
/// name alone, so an external host named like a Node picks up that Node's uid.
/// [`drop_records_for_recreated_nodes`] rightly never acts on it, but the Node watch's wake set
/// (`mappers::plan_awaits_node`) cannot tell group kinds apart and asks [`node_replaced_since`] of
/// every targeted host. Left in place, a replacement of that unrelated Node would wake the plan on
/// every heartbeat, for a claim no reconcile ever clears. Without the uid both sides answer "not
/// replaced".
///
/// Only the uid goes: the claim itself is true of the external machine, which a Node object says
/// nothing about. A host also listed in a managed-ssh group is that Node, and keeps it.
pub fn forget_node_uids_of_external_hosts(
    groups: &[ResolvedInventoryGroup],
    status: &mut PlaybookPlanStatus,
) {
    let Some(hosts_status) = status.hosts_status.as_mut() else {
        return;
    };

    let (managed, external): (Vec<_>, Vec<_>) = groups
        .iter()
        .partition(|group| matches!(group, ResolvedInventoryGroup::ManagedSsh { .. }));
    let managed: HashSet<&str> = managed
        .iter()
        .flat_map(|group| group.hosts().hosts.iter().map(String::as_str))
        .collect();

    for host in external
        .iter()
        .flat_map(|group| group.hosts().hosts.iter())
        .filter(|host| !managed.contains(host.as_str()))
    {
        if let Some(record) = hosts_status.get_mut(host) {
            record.applied_node_uid = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1beta1::{HostOutcome, HostStatus, ResolvedHosts, SecretRef, SshConfig};
    use chrono::{DateTime, FixedOffset};
    use kube::runtime::{reflector::store::Writer, watcher};
    use std::collections::BTreeMap;

    fn at(rfc3339: &str) -> DateTime<FixedOffset> {
        DateTime::parse_from_rfc3339(rfc3339).unwrap()
    }

    fn node(name: &str, uid: Option<&str>) -> Node {
        Node {
            metadata: kube::core::ObjectMeta {
                name: Some(name.to_string()),
                uid: uid.map(str::to_string),
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
            },
            static_inventory_name: "external".into(),
            config: SshConfig {
                user: "root".into(),
                secret_ref: SecretRef { name: "key".into() },
            },
            variables: None,
        }
    }

    fn applied(hash: &str, node_uid: Option<&str>) -> HostStatus {
        HostStatus {
            last_applied_hash: hash.into(),
            last_outcome: HostOutcome::Succeeded,
            applied_at: Some(at("2026-01-01T00:00:00Z")),
            applied_node_uid: node_uid.map(str::to_string),
            applied_version: Some("1.4.2".into()),
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
    fn a_node_with_a_different_uid_is_a_different_machine() {
        assert!(node_replaced_since(
            Some("uid-1"),
            &node("node-a", Some("uid-2"))
        ));
        assert!(!node_replaced_since(
            Some("uid-1"),
            &node("node-a", Some("uid-1"))
        ));
    }

    /// No clock takes part in the answer. A Node whose `creationTimestamp` reads 30 seconds after
    /// `appliedAt` is exactly what an operator running 30 seconds behind the apiserver records for a
    /// machine it has just converged; reading that as a replacement would drop the claim and re-run
    /// the host for ever.
    #[test]
    fn a_node_created_after_the_recorded_time_is_still_the_same_machine() {
        let mut status = status_with(&[("node-a", applied("abc", Some("uid-1")))]);
        let mut fresh = node("node-a", Some("uid-1"));
        fresh.metadata.creation_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::from_second(at("2026-01-01T00:00:30Z").timestamp())
                    .unwrap(),
            ));

        let replaced = drop_records_for_recreated_nodes(
            &store(vec![fresh]),
            &[managed(&["node-a"])],
            &mut status,
        );

        assert!(replaced.is_empty());
        assert_eq!(
            status.hosts_status.unwrap()["node-a"].last_applied_hash,
            "abc"
        );
    }

    /// The upgrade path. Every record written before `appliedNodeUid` existed has none, and reading
    /// that as a replacement would mark every host in the fleet outdated at once — a cluster-wide
    /// re-run triggered by nothing but installing a new operator.
    #[test]
    fn a_record_predating_the_field_is_left_alone() {
        assert!(!node_replaced_since(None, &node("node-a", Some("uid-2"))));

        let mut status = status_with(&[("node-a", applied("abc", None))]);
        let replaced = drop_records_for_recreated_nodes(
            &store(vec![node("node-a", Some("uid-2"))]),
            &[managed(&["node-a"])],
            &mut status,
        );

        assert!(replaced.is_empty());
        assert_eq!(
            status.hosts_status.unwrap()["node-a"].last_applied_hash,
            "abc"
        );
    }

    #[test]
    fn a_node_without_a_uid_is_not_a_replacement() {
        assert!(!node_replaced_since(Some("uid-1"), &node("node-a", None)));
    }

    #[test]
    fn a_replaced_node_loses_its_claim_but_keeps_its_history() {
        let mut status = status_with(&[
            ("node-a", applied("abc", Some("uid-a-old"))),
            ("node-b", applied("abc", Some("uid-b"))),
        ]);

        let replaced = drop_records_for_recreated_nodes(
            &store(vec![
                node("node-a", Some("uid-a-new")),
                node("node-b", Some("uid-b")),
            ]),
            &[managed(&["node-a", "node-b"])],
            &mut status,
        );

        assert_eq!(replaced, vec!["node-a".to_string()]);
        let hosts = status.hosts_status.unwrap();
        assert_eq!(
            hosts["node-a"].last_applied_hash, "",
            "the fresh machine has applied nothing"
        );
        assert_eq!(hosts["node-a"].applied_at, None);
        assert_eq!(hosts["node-a"].applied_node_uid, None);
        assert_eq!(
            hosts["node-a"].applied_version, None,
            "the version a Node label would be derived from goes with the claim"
        );
        assert_eq!(
            hosts["node-a"].last_outcome,
            HostOutcome::Succeeded,
            "what happened to the previous machine is still history"
        );
        assert!(hosts["node-a"].last_transition_time.is_some());
        assert_eq!(
            hosts["node-b"].last_applied_hash, "abc",
            "a Node with the recorded uid is the machine the claim was made about"
        );
    }

    /// A miss in the cache is not evidence of a replacement — the Node may be gone, or the watch may
    /// be behind. Only a Node that is present and different establishes one.
    #[test]
    fn a_host_with_no_node_in_the_cache_keeps_its_record() {
        let mut status = status_with(&[("node-a", applied("abc", Some("uid-1")))]);

        let replaced =
            drop_records_for_recreated_nodes(&store(vec![]), &[managed(&["node-a"])], &mut status);

        assert!(replaced.is_empty());
        assert_eq!(
            status.hosts_status.unwrap()["node-a"].last_applied_hash,
            "abc"
        );
    }

    /// `hostsStatus` is keyed by name alone, so an external host named like a Node would otherwise be
    /// reset because an unrelated cluster Node was replaced. Nothing about a `StaticInventory`
    /// machine is knowable from a Node object.
    #[test]
    fn an_external_host_sharing_a_node_name_is_untouched() {
        let mut status = status_with(&[("node-a", applied("abc", Some("uid-1")))]);

        let replaced = drop_records_for_recreated_nodes(
            &store(vec![node("node-a", Some("uid-2"))]),
            &[external(&["node-a"])],
            &mut status,
        );

        assert!(replaced.is_empty());
        assert_eq!(
            status.hosts_status.unwrap()["node-a"].last_applied_hash,
            "abc"
        );
    }

    /// The other half of the case above. The wake set asks [`node_replaced_since`] of every targeted
    /// host whatever its group kind, so an external host holding a Node's uid would keep a plan
    /// woken by that Node's every heartbeat once the Node was replaced, with nothing ever clearing
    /// it. Without the uid, the question has the same answer on both sides.
    #[test]
    fn an_external_host_forgets_the_node_uid_its_success_stamped() {
        let mut status = status_with(&[
            ("edge-1", applied("abc", Some("uid-1"))),
            ("both", applied("abc", Some("uid-2"))),
            ("node-a", applied("abc", Some("uid-3"))),
        ]);

        forget_node_uids_of_external_hosts(
            &[external(&["edge-1", "both"]), managed(&["both", "node-a"])],
            &mut status,
        );

        let hosts = status.hosts_status.unwrap();
        assert_eq!(hosts["edge-1"].applied_node_uid, None);
        assert_eq!(
            hosts["edge-1"].last_applied_hash, "abc",
            "the claim is still true of the external machine"
        );
        assert_eq!(
            hosts["both"].applied_node_uid.as_deref(),
            Some("uid-2"),
            "a host a managed-ssh group lists is that Node"
        );
        assert_eq!(hosts["node-a"].applied_node_uid.as_deref(), Some("uid-3"));
    }

    #[test]
    fn a_plan_that_never_ran_has_nothing_to_drop() {
        let mut status = PlaybookPlanStatus::default();

        let replaced = drop_records_for_recreated_nodes(
            &store(vec![node("node-a", Some("uid-2"))]),
            &[managed(&["node-a"])],
            &mut status,
        );

        assert!(replaced.is_empty());
        assert!(status.hosts_status.is_none());
    }

    #[test]
    fn the_uid_recorded_for_a_host_is_its_nodes() {
        let nodes = store(vec![node("node-a", Some("uid-1"))]);

        assert_eq!(current_node_uid(&nodes, "node-a").as_deref(), Some("uid-1"));
        assert_eq!(current_node_uid(&nodes, "node-b"), None);
    }
}
