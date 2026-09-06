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

/// Marks a recap the callback deflated and base64-encoded because plain JSON would not have fitted
/// the kubelet's termination-message cap. Must stay in lockstep with `COMPRESSED_PREFIX` in
/// `ansible_operator_recap.py`.
const COMPRESSED_PREFIX: &str = "z:";

/// Ceiling on what a compressed recap may inflate to.
///
/// The termination message is written by a pod running the *user's* image, so it is untrusted input
/// and a deflate stream is an amplifier: the kubelet's 4096-byte cap bounds what arrives, not what it
/// expands to. The bound is far above any real recap — 800 hosts with long cloud-provider names is
/// ~53 KB — so it can only ever reject something that was not a recap.
const MAX_INFLATED_RECAP_BYTES: u64 = 1024 * 1024;

/// Parses the container's termination message, plain or compressed. Returns `None` if the message is
/// empty or not parseable — truncated at the kubelet's size cap, or a hard crash (OOM/SIGKILL)
/// before the stats hook ran. Callers must surface that as `HostOutcome::Unknown`, not `NotReached`
/// (which means Ansible legitimately never got there).
///
/// The compressed form exists because the cap is 4096 bytes per container and a plain recap runs out
/// at roughly 60 hosts with cloud-provider node names — beyond which the message arrives as invalid
/// JSON and every host reads `Unknown` on every retry until the attempt budget is gone. Compression
/// is decided by the writer, per run, so a small fleet's message stays readable JSON; both forms are
/// accepted here forever, since which one arrives depends on the fleet rather than on a version.
pub fn parse_callback_output(message: &str) -> Option<CallbackOutput> {
    let message = message.trim();

    match message.strip_prefix(COMPRESSED_PREFIX) {
        Some(encoded) => serde_json::from_slice(&inflate(encoded)?).ok(),
        None => serde_json::from_str(message).ok(),
    }
}

fn inflate(base64_encoded: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    use std::io::Read as _;

    let deflated = base64::engine::general_purpose::STANDARD
        .decode(base64_encoded)
        .ok()?;

    // One byte past the ceiling, so an over-long stream is *rejected* rather than silently cut to
    // the limit — a truncation that happened to land on a closing brace would otherwise parse as a
    // complete recap.
    let mut inflated = Vec::new();
    flate2::read::ZlibDecoder::new(deflated.as_slice())
        .take(MAX_INFLATED_RECAP_BYTES + 1)
        .read_to_end(&mut inflated)
        .ok()?;

    (inflated.len() as u64 <= MAX_INFLATED_RECAP_BYTES).then_some(inflated)
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

    fn compressed(json: &str) -> String {
        use base64::Engine as _;
        use std::io::Write as _;

        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(json.as_bytes()).unwrap();
        format!(
            "{COMPRESSED_PREFIX}{}",
            base64::engine::general_purpose::STANDARD.encode(encoder.finish().unwrap())
        )
    }

    /// The compressed form has to reach exactly the same `CallbackOutput` as the plain one — it is a
    /// transport detail the writer picks per run based on fleet size, and nothing downstream is told
    /// which arrived.
    #[test]
    fn a_compressed_recap_parses_to_the_same_thing_as_the_plain_one() {
        let json = r#"{"host-1":[2,1,0,0,0,0,0,1],"host-2":[2,0,0,1,0,0,0,0]}"#;

        let from_plain = parse_callback_output(json).unwrap();
        let from_compressed = parse_callback_output(&compressed(json)).unwrap();

        assert_eq!(from_compressed.processed.len(), from_plain.processed.len());
        let h1 = &from_compressed.processed["host-1"];
        assert_eq!((h1.ok, h1.changed), (2, 1));
        assert!(h1.completed);
        assert!(from_compressed.processed["host-2"].is_failure());
    }

    /// The whole point of the format: a fleet whose plain recap cannot fit the kubelet's 4096-byte
    /// cap still round-trips. 200 hosts with EKS-style names is ~13 KB plain.
    #[test]
    fn a_recap_far_larger_than_the_kubelet_cap_round_trips_compressed() {
        let hosts: Vec<String> = (0..200)
            .map(|i| {
                format!(
                    r#""ip-10-0-{}-{}.eu-central-1.compute.internal":[12,3,0,0,7,0,0,1]"#,
                    i / 250,
                    i % 250
                )
            })
            .collect();
        let json = format!("{{{}}}", hosts.join(","));
        assert!(json.len() > 4096, "the plain form must exceed the cap");

        let wire = compressed(&json);
        assert!(
            wire.len() <= 4096,
            "the compressed form must fit: {} bytes",
            wire.len()
        );
        assert_eq!(parse_callback_output(&wire).unwrap().processed.len(), 200);
    }

    /// The message comes from a pod running the user's own image, so the compressed path is
    /// untrusted input and the cap bounds only what *arrives*. A stream that inflates past the
    /// ceiling is rejected like any other unreadable recap rather than allocated.
    #[test]
    fn a_decompression_bomb_is_refused_rather_than_inflated() {
        use std::io::Write as _;

        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder
            .write_all(&vec![b'a'; MAX_INFLATED_RECAP_BYTES as usize * 2])
            .unwrap();
        let bomb = {
            use base64::Engine as _;
            format!(
                "{COMPRESSED_PREFIX}{}",
                base64::engine::general_purpose::STANDARD.encode(encoder.finish().unwrap())
            )
        };
        assert!(bomb.len() < 4096, "a bomb fits the cap; that is the point");

        assert!(parse_callback_output(&bomb).is_none());
    }

    #[test]
    fn a_corrupt_compressed_message_returns_none_not_panic() {
        assert!(parse_callback_output("z:not-base64!!").is_none());
        assert!(
            parse_callback_output("z:aGVsbG8=").is_none(),
            "valid base64, not a zlib stream"
        );
        assert!(parse_callback_output("z:").is_none());
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
