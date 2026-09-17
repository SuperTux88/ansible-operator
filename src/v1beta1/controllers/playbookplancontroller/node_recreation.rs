//! Whether the machine behind a recorded host is still the one that record was written for.
//!
//! `hostsStatus` is keyed by host *name*, and a Node can be deleted and re-registered under that
//! same name — a re-imaged machine, a reprovisioned VM, a node pool the cloud provider rolled. The
//! fresh Node inherits nothing from its predecessor, but the *record* does: `lastAppliedHash` still
//! names the revision the old machine applied, so `find_outdated_hosts` counts the new one as
//! current and a `OneShot` plan never runs on it again.
//!
//! The question is answered from state rather than by reacting to the deletion, because a deletion
//! is an event and this has to be answerable without one. An operator that was down while the
//! machine was replaced, or one whose plan sat in a namespace that was not enrolled at the time,
//! never sees a deletion — only a Node that exists under a familiar name.
//!
//! **Both sides of the comparison are stamped by the apiserver.** A Node's `creationTimestamp` is,
//! and `appliedAt` is the `Play`'s own `metadata.creationTimestamp` — when the run that made the
//! claim was prepared. That is the whole reason the claim is dated from the run's *start* rather
//! than its finish: the finish time is written by the operator pod, and comparing an operator clock
//! against an apiserver clock would measure skew as much as machine identity. An operator running
//! behind would then read a Node it had just converged as a replacement, drop the claim, run again,
//! and do it for ever — on a plan reporting itself healthy, since every one of those runs succeeds.
//!
//! One comparison answers two questions, which is why there is only one function. A Node created
//! after the run was prepared cannot be the machine that run was prepared against — Node names are
//! unique, so a Node standing there now with an *earlier* `creationTimestamp` has been there since
//! before the run and is that machine. So the same test catches a replacement that happened while
//! the result was still being recorded (asked once, in `status::apply_terminal_play_status`) and one
//! that happens any time afterwards (asked every tick, here).

use chrono::{DateTime, FixedOffset};
use k8s_openapi::api::core::v1::Node;
use kube::runtime::reflector::{ObjectRef, Store};

use crate::v1beta1::{PlaybookPlanStatus, ResolvedInventoryGroup};

/// Whether `node` is a different machine from the one a claim made by a run prepared at
/// `claimed_at` describes.
///
/// Both halves are required, and a missing one answers "no" deliberately:
///
/// - **no `claimed_at`** is a record written before the claim was dated. Treating it as a
///   replacement would re-run every plan in the fleet on the upgrade that introduced this; the next
///   success fills the field in, and until then the record stands exactly as it was.
/// - **no `creationTimestamp`** is a Node the apiserver has not stamped, which nothing but a
///   hand-built object can be.
///
/// The comparison is **strict**, so a Node created within the same second as the run that applied to
/// it is not a replacement. Both timestamps are second-precision on the wire, and a Node that joins
/// and is picked up by an inventory straight away routinely lands in the same second as the run
/// prepared for it — so of the two directions to round, the one that does not re-run a playbook is
/// also the one that is right far more often.
pub fn node_replaced_since(claimed_at: Option<DateTime<FixedOffset>>, node: &Node) -> bool {
    let (Some(claimed_at), Some(created)) = (claimed_at, node.metadata.creation_timestamp.as_ref())
    else {
        return false;
    };

    created.0.as_second() > claimed_at.timestamp()
}

/// Drops the recorded application of every managed-ssh host whose Node is newer than the run that
/// claimed it, returning the hosts that lost theirs.
///
/// This is the half of [`node_replaced_since`] that runs long after the fact: a machine rebuilt
/// days or weeks after a plan converged on it, which no check made while the result was being
/// recorded could have seen.
///
/// Only the *claim* is dropped — `lastAppliedHash`, `appliedAt` and `appliedVersion` — and never the
/// outcome or the time it was recorded: what happened to the previous machine is history worth
/// keeping, while the claim that this host carries the current revision is the half that is now
/// false. The version goes with the other two because it is what a Node label is derived from, and a
/// fresh machine that kept it would be labelled for software it has never been given.
///
/// Three things are deliberately left alone:
///
/// - **hosts outside the plan's managed-ssh groups.** `hostsStatus` is keyed by name, so a
///   `StaticInventory` host that happens to share a Node's name would otherwise have its record
///   reset because an unrelated Node was replaced. Nothing about an external machine is knowable
///   from a Node object.
/// - **a host with no Node in the cache.** A miss is not evidence here: the Node may be gone, or the
///   watch may be behind. Only a Node that is *present* and newer can establish a replacement.
/// - **a record with no `appliedAt`** — see [`node_replaced_since`].
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
                nodes
                    .get(&ObjectRef::new(host))
                    .is_some_and(|node| node_replaced_since(record.applied_at, &node))
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
            record.applied_version = None;
        }
    }

    replaced
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1beta1::{HostOutcome, HostStatus, ResolvedHosts, SecretRef, SshConfig};
    use kube::runtime::{reflector::store::Writer, watcher};
    use std::collections::BTreeMap;

    fn at(rfc3339: &str) -> DateTime<FixedOffset> {
        DateTime::parse_from_rfc3339(rfc3339).unwrap()
    }

    fn node(name: &str, created: Option<&str>) -> Node {
        Node {
            metadata: kube::core::ObjectMeta {
                name: Some(name.to_string()),
                creation_timestamp: created.map(|created| {
                    k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                        k8s_openapi::jiff::Timestamp::from_second(at(created).timestamp()).unwrap(),
                    )
                }),
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

    fn applied(hash: &str, claimed_at: Option<&str>) -> HostStatus {
        HostStatus {
            last_applied_hash: hash.into(),
            last_outcome: HostOutcome::Succeeded,
            applied_at: claimed_at.map(at),
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
    fn a_node_created_after_the_run_that_claimed_it_is_a_different_machine() {
        let claimed_at = Some(at("2026-01-01T12:00:00Z"));

        assert!(node_replaced_since(
            claimed_at,
            &node("node-a", Some("2026-01-02T00:00:00Z"))
        ));
        assert!(!node_replaced_since(
            claimed_at,
            &node("node-a", Some("2025-12-31T00:00:00Z"))
        ));
    }

    /// A Node that joins and is picked up by an inventory straight away is prepared for in the same
    /// second it was created, so a tie has to read as "the same machine" — the other way round would
    /// re-run the playbook on every freshly joined Node, for ever, which is the population this is
    /// most likely to meet.
    #[test]
    fn a_node_created_in_the_same_second_as_the_run_is_the_same_machine() {
        assert!(!node_replaced_since(
            Some(at("2026-01-01T12:00:00Z")),
            &node("node-a", Some("2026-01-01T12:00:00Z"))
        ));
    }

    /// The upgrade path. Every record written before the claim was dated has no `appliedAt`, and
    /// reading that as a replacement would mark every host in the fleet outdated at once — a
    /// cluster-wide re-run triggered by nothing but installing a new operator.
    #[test]
    fn a_record_predating_the_field_is_left_alone() {
        assert!(!node_replaced_since(
            None,
            &node("node-a", Some("2026-01-02T00:00:00Z"))
        ));

        let mut status = status_with(&[("node-a", applied("abc", None))]);
        let replaced = drop_records_for_recreated_nodes(
            &store(vec![node("node-a", Some("2026-01-02T00:00:00Z"))]),
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
    fn a_node_without_a_creation_timestamp_is_not_a_replacement() {
        assert!(!node_replaced_since(
            Some(at("2026-01-01T00:00:00Z")),
            &node("node-a", None)
        ));
    }

    #[test]
    fn a_replaced_node_loses_its_claim_but_keeps_its_history() {
        let mut status = status_with(&[
            ("node-a", applied("abc", Some("2026-01-01T00:00:00Z"))),
            ("node-b", applied("abc", Some("2026-01-01T00:00:00Z"))),
        ]);

        let replaced = drop_records_for_recreated_nodes(
            &store(vec![
                node("node-a", Some("2026-01-02T00:00:00Z")),
                node("node-b", Some("2025-12-01T00:00:00Z")),
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
            "a Node older than the run that claimed it is the machine it was claimed about"
        );
    }

    /// A miss in the cache is not evidence of a replacement — the Node may be gone, or the watch may
    /// be behind. Only a Node that is present and newer establishes one.
    #[test]
    fn a_host_with_no_node_in_the_cache_keeps_its_record() {
        let mut status = status_with(&[("node-a", applied("abc", Some("2026-01-01T00:00:00Z")))]);

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
    /// machine is knowable from a Node object — and the wake set agrees, because `eligibleHosts`
    /// records which hosts are Nodes (`ResolvedHosts::connection`).
    #[test]
    fn an_external_host_sharing_a_node_name_is_untouched() {
        let mut status = status_with(&[("node-a", applied("abc", Some("2026-01-01T00:00:00Z")))]);

        let replaced = drop_records_for_recreated_nodes(
            &store(vec![node("node-a", Some("2026-01-02T00:00:00Z"))]),
            &[external(&["node-a"])],
            &mut status,
        );

        assert!(replaced.is_empty());
        assert_eq!(
            status.hosts_status.unwrap()["node-a"].last_applied_hash,
            "abc"
        );
    }

    #[test]
    fn a_plan_that_never_ran_has_nothing_to_drop() {
        let mut status = PlaybookPlanStatus::default();

        let replaced = drop_records_for_recreated_nodes(
            &store(vec![node("node-a", Some("2026-01-02T00:00:00Z"))]),
            &[managed(&["node-a"])],
            &mut status,
        );

        assert!(replaced.is_empty());
        assert!(status.hosts_status.is_none());
    }
}
