use std::collections::BTreeMap;

use serde::Deserialize;

/// Per-host outcome counters, deserialized from the compact fixed-order array the callback plugin
/// writes: `[ok, changed, unreachable, failed, skipped, rescued, ignored, completed]`. Only
/// `failed`/`unreachable` (via `is_failure`) and `completed` are consulted today; the rest mirror
/// ansible's stats and are groundwork for future per-task progression info.
#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(from = "[u32; 8]")]
pub struct HostStats {
    pub ok: u32,
    pub changed: u32,
    pub unreachable: u32,
    pub failed: u32,
    pub skipped: u32,
    pub rescued: u32,
    pub ignored: u32,
    /// The host produced a result for the completion marker the operator appends to every playbook,
    /// so the playbook did not stop short of it. Not a counter: it is the one thing ansible's
    /// counters cannot express, since a host cut short by an abort reports exactly what a host that
    /// ran everything reports.
    pub completed: bool,
}

impl From<[u32; 8]> for HostStats {
    /// Fixed wire order — must stay in lockstep with `ansible_operator_recap.py`. Changing it is
    /// a *shape*-compatible edit that would silently misread an in-flight message, so don't
    /// reorder: only ever add/remove positions (which changes the length and fails to parse).
    fn from(
        [
            ok,
            changed,
            unreachable,
            failed,
            skipped,
            rescued,
            ignored,
            completed,
        ]: [u32; 8],
    ) -> Self {
        Self {
            ok,
            changed,
            unreachable,
            failed,
            skipped,
            rescued,
            ignored,
            completed: completed != 0,
        }
    }
}

impl HostStats {
    pub fn is_failure(&self) -> bool {
        self.failed > 0 || self.unreachable > 0
    }
}

/// The recap the callback plugin writes to the Job pod's `/dev/termination-log`: a bare map of
/// hostname -> per-host counter array. Read back from the finished container's terminated state.
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(transparent)]
pub struct CallbackOutput {
    pub processed: BTreeMap<String, HostStats>,
}

/// Parses the container's termination message. Returns `None` if the message is empty or not
/// parseable — truncated at the kubelet's size cap, or a hard crash (OOM/SIGKILL) before the
/// stats hook ran. Callers must surface that as `HostOutcome::Unknown`, not `NotReached` (which
/// means Ansible legitimately never got there).
pub fn parse_callback_output(message: &str) -> Option<CallbackOutput> {
    serde_json::from_str(message.trim()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_host_array_map_positionally() {
        let msg = r#"{"host-1":[2,1,0,0,0,0,0,1],"host-2":[2,0,0,1,0,0,0,0]}"#;

        let parsed = parse_callback_output(msg).unwrap();
        assert_eq!(parsed.processed.len(), 2);

        // [ok, changed, unreachable, failed, skipped, rescued, ignored, completed]
        let h1 = &parsed.processed["host-1"];
        assert_eq!((h1.ok, h1.changed), (2, 1));
        assert!(!h1.is_failure());
        assert!(h1.completed);

        let h2 = &parsed.processed["host-2"];
        assert_eq!(h2.failed, 1);
        assert!(h2.is_failure());
        assert!(!h2.completed);
    }

    #[test]
    fn empty_message_returns_none() {
        assert!(parse_callback_output("").is_none());
        assert!(parse_callback_output("   ").is_none());
    }

    #[test]
    fn malformed_or_truncated_message_returns_none_not_panic() {
        // A tail-truncated object is no longer valid JSON.
        assert!(parse_callback_output(r#"{"host-1":[2,0,0,1,0,0"#).is_none());
        assert!(parse_callback_output("not json").is_none());
    }

    #[test]
    fn wrong_length_array_returns_none() {
        // A shape change fails to parse -> Unknown, never a silent misread. The 7-element form is
        // what a workspace rendered before the completion marker existed emits, and it must fail
        // this way rather than be read as a 7-counter host with the last field defaulted.
        assert!(parse_callback_output(r#"{"host-1":[2,0,0,1,0,0]}"#).is_none());
        assert!(parse_callback_output(r#"{"host-1":[2,0,0,1,0,0,0]}"#).is_none());
    }

    /// Completion is orthogonal to failure, and both directions occur: a host cut short by an
    /// abort has clean counters and no completion, while a host that ignored an unreachable task
    /// ran to the end with a counter set.
    #[test]
    fn completion_is_read_independently_of_the_counters() {
        let msg = r#"{"cut-short":[1,1,0,0,1,0,0,0],"ignored-unreachable":[2,0,1,0,0,0,0,1]}"#;
        let parsed = parse_callback_output(msg).unwrap();

        let cut_short = &parsed.processed["cut-short"];
        assert!(!cut_short.is_failure());
        assert!(!cut_short.completed);

        let ignored = &parsed.processed["ignored-unreachable"];
        assert!(ignored.is_failure());
        assert!(ignored.completed);
    }

    #[test]
    fn failed_and_unreachable_both_count_as_failure() {
        let failed = HostStats {
            failed: 1,
            ..Default::default()
        };
        let unreachable = HostStats {
            unreachable: 1,
            ..Default::default()
        };
        let ok = HostStats {
            ok: 3,
            rescued: 1,
            ..Default::default()
        };

        assert!(failed.is_failure());
        assert!(unreachable.is_failure());
        assert!(
            !ok.is_failure(),
            "a rescued host with no failed/unreachable counts is a success"
        );
    }
}
