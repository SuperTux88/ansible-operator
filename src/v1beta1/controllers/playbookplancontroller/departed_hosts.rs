//! Records in `hostsStatus` describing machines that are gone for good.
//!
//! Every write to `hostsStatus` inserts (`status::apply_terminal_play_status` only ever uses
//! `entry().or_default()`), and nothing has ever removed anything. A plan on a cluster that churns
//! Nodes therefore accumulates one entry per machine it has ever applied to and gives none back:
//! nothing reads a departed host's record, but it is carried in every status write and every read
//! for the life of the plan.
//!
//! Two conditions have to hold, and the second is what makes this safe:
//!
//! - the host is **not in the plan's resolved inventory** any more, and
//! - **no Node of that name exists.**
//!
//! The second is the important one. A host leaves the inventory for reasons that say nothing about
//! the machine — a `NodeAccessPolicy` narrowed, a label edited, a selector rewritten — and in all of
//! those the Node is still there. Pruning on absence from the inventory alone would drop the records
//! of perfectly live machines, and returning them to the inventory would then re-apply the playbook
//! to every one of them, which is a fleet-wide re-run set off by an admin widening a policy back.
//! Requiring the Node to be gone as well narrows this to the case that actually grows without bound:
//! a machine that has left the cluster.
//!
//! That protection only exists for cluster Nodes. A `StaticInventory` host never has a Node, so the
//! second condition always holds for it: removing an external host from its inventory drops its
//! record, and adding it back re-runs the playbook there. Accepted: a `StaticInventory`'s hosts are a
//! literal list, so one only leaves when an author edits it — nothing like a narrowed policy can drop
//! many live machines at once — and a host removed and re-added by hand may well have been rebuilt
//! in between, so running again is the better default anyway.
//!
//! This is deliberately **not** how recreated Nodes are handled — see `node_recreation`. That
//! question is about *identity* and has to be answered from state, because a machine replaced while
//! the operator was down leaves no deletion to react to. This one is about *housekeeping*, and being
//! late or conservative costs nothing but a stale row.

use k8s_openapi::api::core::v1::Node;
use kube::runtime::reflector::{ObjectRef, Store};

use crate::v1beta1::PlaybookPlanStatus;

/// Drops the records of hosts that have left the inventory and no longer exist as Nodes, returning
/// the host names whose records were dropped.
///
/// Skipped entirely while a run is in flight. That run was launched against the hosts the inventory
/// held at the time and is going to write a result for each of them, so pruning one now would only
/// have `apply_terminal_play_status` insert it again when the run drains — a delete and a re-add for
/// no gain. Housekeeping can wait for an idle tick; nothing depends on it happening promptly.
pub fn prune_departed_hosts(nodes: &Store<Node>, status: &mut PlaybookPlanStatus) -> Vec<String> {
    if status.active_run.is_some() {
        return Vec::new();
    }

    let PlaybookPlanStatus {
        hosts_status,
        eligible_hosts,
        ..
    } = status;
    let Some(hosts_status) = hosts_status.as_mut() else {
        return Vec::new();
    };

    let targeted: std::collections::HashSet<&str> = eligible_hosts
        .iter()
        .flat_map(|group| group.hosts.iter())
        .map(String::as_str)
        .collect();

    let departed: Vec<String> = hosts_status
        .keys()
        .filter(|host| !targeted.contains(host.as_str()))
        .filter(|host| nodes.get(&ObjectRef::new(host)).is_none())
        .cloned()
        .collect();

    for host in &departed {
        hosts_status.remove(host);
    }

    departed
}

/// The status patch that removes `departed` from the stored `hostsStatus`.
///
/// Dropping the keys from the map in memory is not enough, and this is the whole subtlety of the
/// module: status writes are JSON **merge** patches, where a patch carries only what it changes and
/// an absent key means "leave this one alone". A map serialized without its departed entries
/// therefore deletes nothing — the rows survive on the server and come straight back on the next
/// read, every tick, forever. Deleting a key takes an explicit `null`, which a typed
/// `BTreeMap<String, HostStatus>` has no way to express, so the patch is built by hand.
pub fn hosts_status_deletion_patch(departed: &[String]) -> serde_json::Value {
    let nulls: serde_json::Map<String, serde_json::Value> = departed
        .iter()
        .map(|host| (host.clone(), serde_json::Value::Null))
        .collect();

    serde_json::json!({ "status": { "hostsStatus": nulls } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1beta1::{ActiveRun, HostOutcome, HostStatus, ResolvedHosts};
    use kube::runtime::{reflector::store::Writer, watcher};
    use std::collections::BTreeMap;

    fn node(name: &str) -> Node {
        Node {
            metadata: kube::core::ObjectMeta {
                name: Some(name.to_string()),
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

    fn status_with(eligible: &[&str], recorded: &[&str]) -> PlaybookPlanStatus {
        PlaybookPlanStatus {
            eligible_hosts: vec![ResolvedHosts {
                name: "workers".into(),
                hosts: eligible.iter().map(|host| (*host).to_string()).collect(),
            }],
            hosts_status: Some(
                recorded
                    .iter()
                    .map(|host| {
                        (
                            (*host).to_string(),
                            HostStatus {
                                last_applied_hash: "abc".into(),
                                last_outcome: HostOutcome::Succeeded,
                                ..Default::default()
                            },
                        )
                    })
                    .collect::<BTreeMap<_, _>>(),
            ),
            ..Default::default()
        }
    }

    fn recorded_hosts(status: &PlaybookPlanStatus) -> Vec<String> {
        status
            .hosts_status
            .as_ref()
            .map(|hosts| hosts.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// The growth this exists to bound: a machine that has left the cluster leaves a row nothing
    /// reads, carried in every status write for the life of the plan.
    #[test]
    fn a_host_that_left_the_inventory_and_the_cluster_is_pruned() {
        let mut status = status_with(&["node-w2"], &["node-w1", "node-w2"]);

        let departed = prune_departed_hosts(&store(vec![node("node-w2")]), &mut status);

        assert_eq!(departed, vec!["node-w1".to_string()]);
        assert_eq!(recorded_hosts(&status), vec!["node-w2".to_string()]);
    }

    /// The safety case, and the reason the Node has to be gone as well. A host leaves the inventory
    /// for reasons that say nothing about the machine — a narrowed `NodeAccessPolicy`, an edited
    /// label — and dropping its record would re-apply the playbook to it the moment it came back.
    #[test]
    fn a_host_clamped_out_of_the_inventory_keeps_its_record() {
        let mut status = status_with(&[], &["node-w1"]);

        let departed = prune_departed_hosts(&store(vec![node("node-w1")]), &mut status);

        assert!(departed.is_empty());
        assert_eq!(
            status.hosts_status.unwrap()["node-w1"].last_applied_hash,
            "abc",
            "the machine is still there, so it is still recorded as current"
        );
    }

    #[test]
    fn a_host_still_in_the_inventory_is_kept_even_without_a_node() {
        let mut status = status_with(&["web.example.com"], &["web.example.com"]);

        let departed = prune_departed_hosts(&store(vec![]), &mut status);

        assert!(
            departed.is_empty(),
            "a StaticInventory host has no Node and is not departed for want of one"
        );
        assert_eq!(recorded_hosts(&status), vec!["web.example.com".to_string()]);
    }

    /// The run was launched against the hosts the inventory held then and will write a result for
    /// each, so pruning one now only means inserting it again when the run drains.
    #[test]
    fn nothing_is_pruned_while_a_run_is_in_flight() {
        let mut status = status_with(&["node-w2"], &["node-w1", "node-w2"]);
        status.active_run = Some(ActiveRun {
            execution_hash: "abc".into(),
            run_id: "run-1".into(),
            job_name: "apply-web-abc123-1".into(),
            play_uid: "uid".into(),
            hosts: vec!["node-w1".into()],
            run_number: 1,
            attempt: 1,
            triggered_slot: None,
        });

        let departed = prune_departed_hosts(&store(vec![]), &mut status);

        assert!(departed.is_empty());
        assert_eq!(
            recorded_hosts(&status),
            vec!["node-w1".to_string(), "node-w2".into()]
        );
    }

    #[test]
    fn a_plan_that_never_ran_has_nothing_to_prune() {
        let mut status = PlaybookPlanStatus::default();

        assert!(prune_departed_hosts(&store(vec![]), &mut status).is_empty());
        assert!(status.hosts_status.is_none());
    }

    /// Pins the merge-patch semantics the module depends on. A patch built from the remaining
    /// entries would delete nothing at all, and the rows would return on the next read — so what
    /// goes on the wire has to be an explicit `null` per departed key.
    #[test]
    fn the_deletion_patch_nulls_each_departed_key() {
        let patch = hosts_status_deletion_patch(&["node-w1".to_string(), "node-w3".to_string()]);

        assert_eq!(
            patch,
            serde_json::json!({
                "status": { "hostsStatus": { "node-w1": null, "node-w3": null } }
            })
        );
    }
}
