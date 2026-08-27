use std::hash::{Hash, Hasher};

use chrono::{DateTime, Duration, Utc};
use k8s_openapi::{
    api::coordination::v1::{Lease, LeaseSpec},
    apimachinery::pkg::apis::meta::v1::ObjectMeta,
    jiff,
};
use kube::{
    Api,
    api::{DeleteParams, PostParams, Preconditions},
};
use tracing::{debug, warn};

use crate::v1beta1::controllers::reconcile_error::{ReconcileError, is_conflict, is_not_found};

/// How long a Lease is considered valid without being renewed. Deliberately short and renewed
/// every reconcile tick (not sized to a run's total length) so a crashed operator only leaves a
/// stale lock around for a short window before it's eligible for reclaim.
pub const LEASE_DURATION_SECONDS: i32 = 90;

/// A host whose lock this run couldn't take or keep this tick, and — when the Lease recorded one —
/// that holder's `namespace/name/run-id` identity so the caller can name the run involved.
#[derive(Debug, PartialEq, Eq)]
pub struct BlockedBy {
    pub host: String,
    /// The observed holder's identity (`namespace/name/run-id`), or `None` when we only lost a write
    /// race (a 409) and never saw who won it.
    pub holder: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LeaseDecision {
    /// No Lease exists yet for this host.
    Create,
    /// A Lease exists, is held by someone else, and has expired — safe to take over.
    Replace { resource_version: String },
    /// A Lease exists and is already held by us — needs its renewTime bumped, nothing else.
    Renew { resource_version: String },
    /// A Lease exists, is held by someone else, and has not expired.
    HeldByOther,
}

/// Pure decision logic for whether/how to acquire or renew a per-host Lease. Contains no I/O so
/// it can be unit-tested without a k8s client.
pub fn decide(existing: Option<&Lease>, desired_holder: &str, now: DateTime<Utc>) -> LeaseDecision {
    let Some(lease) = existing else {
        return LeaseDecision::Create;
    };

    let resource_version = || {
        lease
            .metadata
            .resource_version
            .clone()
            .expect("a Lease read back from the API always has a resourceVersion")
    };

    let spec = lease.spec.as_ref();
    let holder = spec.and_then(|s| s.holder_identity.as_deref());

    if holder == Some(desired_holder) {
        return LeaseDecision::Renew {
            resource_version: resource_version(),
        };
    }

    let expired = spec
        .and_then(|s| {
            let renew_time = jiff_to_chrono(&s.renew_time.as_ref()?.0)?;
            let duration = Duration::seconds(
                s.lease_duration_seconds.unwrap_or(LEASE_DURATION_SECONDS) as i64,
            );
            Some(renew_time + duration < now)
        })
        // No renewTime recorded at all (shouldn't normally happen since we always set one) —
        // treat as stale/reclaimable rather than getting stuck forever.
        .unwrap_or(true);

    if expired {
        LeaseDecision::Replace {
            resource_version: resource_version(),
        }
    } else {
        LeaseDecision::HeldByOther
    }
}

fn jiff_to_chrono(ts: &jiff::Timestamp) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(ts.as_second(), 0)
}

fn chrono_to_jiff(dt: DateTime<Utc>) -> jiff::Timestamp {
    jiff::Timestamp::from_second(dt.timestamp())
        .expect("chrono::DateTime<Utc> is always within jiff's representable range")
}

/// Deterministic Lease name for a resolved host identity (Node name or arbitrary
/// StaticInventory hostname/IP) — hashed rather than used verbatim since the latter can contain
/// characters invalid in a Kubernetes resource name (e.g. IPv6 addresses, uppercase DNS names).
pub fn lease_name(host: &str) -> String {
    let mut hasher = twox_hash::XxHash3_64::new();
    host.hash(&mut hasher);
    format!("ansible-lock-{:x}", hasher.finish())
}

fn build_lease(name: &str, holder_identity: &str, now: DateTime<Utc>) -> Lease {
    Lease {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        spec: Some(LeaseSpec {
            holder_identity: Some(holder_identity.to_string()),
            lease_duration_seconds: Some(LEASE_DURATION_SECONDS),
            renew_time: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime(
                chrono_to_jiff(now),
            )),
            acquire_time: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime(
                chrono_to_jiff(now),
            )),
            ..Default::default()
        }),
    }
}

/// A deterministic global order for acquiring per-host Leases, keyed by the (hashed) lease name so
/// it is identical for every plan regardless of how its inventory happens to enumerate the hosts.
/// `ensure_locks` acquires in this order; together with its all-or-nothing release that is what
/// keeps two plans over overlapping hosts from deadlocking — they contend for the lowest-ordered
/// lock first instead of each pinning a disjoint subset the other still needs.
fn acquisition_order(hosts: &[String]) -> Vec<&String> {
    let mut ordered: Vec<&String> = hosts.iter().collect();
    ordered.sort_by_cached_key(|host| lease_name(host));
    ordered
}

/// Acquires or renews the per-host Lease for every host in `target_hosts` under `holder_identity`,
/// all-or-nothing: on return this holder owns either *all* of the requested locks (`None`) or *none*
/// of them (`Some(BlockedBy)` naming the host — and, when known, the other run — that blocked us).
/// If any lock can't be taken this tick, the ones already taken are released before returning, so a
/// partially-held set is never left pinned across ticks waiting for the rest — which is exactly the
/// deadlock two plans over overlapping hosts would otherwise fall into. That, plus acquiring in a
/// fixed global order (`acquisition_order`), turns contention into clean serialization: one plan
/// takes the whole set and runs while the others wait their turn. Safe to call every reconcile tick
/// — locks we already hold just get their renewTime bumped.
pub async fn ensure_locks(
    api: &Api<Lease>,
    target_hosts: &[String],
    holder_identity: &str,
) -> Result<Option<BlockedBy>, ReconcileError> {
    let now = Utc::now();
    let mut blocked = None;

    for host in acquisition_order(target_hosts) {
        let name = lease_name(host);
        let existing = api.get_opt(&name).await?;
        let decision = decide(existing.as_ref(), holder_identity, now);

        let result = match decision {
            LeaseDecision::Create => {
                let lease = build_lease(&name, holder_identity, now);
                api.create(&PostParams::default(), &lease).await.map(drop)
            }
            LeaseDecision::Replace { resource_version }
            | LeaseDecision::Renew { resource_version } => {
                let mut lease = build_lease(&name, holder_identity, now);
                lease.metadata.resource_version = Some(resource_version);
                api.replace(&name, &PostParams::default(), &lease)
                    .await
                    .map(drop)
            }
            // Held by another plan and not expired. Because we acquire in a fixed global order,
            // nothing after this can complete the set either — stop, record what (and who) blocked
            // us, and fall through to release whatever we already took this tick.
            LeaseDecision::HeldByOther => {
                let holder = existing
                    .as_ref()
                    .and_then(|lease| lease.spec.as_ref())
                    .and_then(|spec| spec.holder_identity.clone());
                blocked = Some(BlockedBy {
                    host: host.clone(),
                    holder,
                });
                break;
            }
        };

        match result {
            Ok(()) => {}
            // Someone else raced us between our read and write — treat as blocked for this tick and
            // stop; we'll re-evaluate from scratch next time rather than treating it as a hard
            // failure. We didn't see the winning holder, so we can't name it.
            Err(err) if is_conflict(&err) => {
                debug!("Lease conflict for host {host}, will retry next tick");
                blocked = Some(BlockedBy {
                    host: host.clone(),
                    holder: None,
                });
                break;
            }
            Err(err) => return Err(err.into()),
        }
    }

    // All-or-nothing: if we couldn't take every requested lock, drop the ones we did take so no lock
    // is ever held across ticks by a plan that isn't running. A plan pinning a strict subset while
    // it waits for the rest is precisely the deadlock this avoids.
    if blocked.is_some() {
        release_locks(api, target_hosts, holder_identity).await?;
    }

    Ok(blocked)
}

/// What `renew_locks` should do with one host's Lease while a run is in progress. Pure so the
/// "still ours vs. lost it" branching is unit-testable without a client.
#[derive(Debug, PartialEq, Eq)]
pub enum RenewalAction {
    /// The lock is still ours, or its Lease object has gone missing — (re)assert it with a fresh
    /// renewTime. `resource_version` is `Some` to replace the existing object, `None` to create one.
    Reassert { resource_version: Option<String> },
    /// Another holder now owns the lock: this run's lease lapsed and a competing run took it over
    /// mid-flight. There's nothing safe to do about it from here beyond reporting it.
    Lost { holder: String },
}

/// Pure decision for renewing a lock we expect to already hold. Unlike `decide` (which is about
/// *acquiring*), expiry is irrelevant here: any *other* holder's identity on the Lease means we've
/// lost it, and we don't try to reclaim it out from under a live run.
pub fn renewal_decision(existing: Option<&Lease>, holder_identity: &str) -> RenewalAction {
    let Some(lease) = existing else {
        return RenewalAction::Reassert {
            resource_version: None,
        };
    };

    let holder = lease
        .spec
        .as_ref()
        .and_then(|s| s.holder_identity.as_deref());
    match holder {
        Some(other) if other != holder_identity => RenewalAction::Lost {
            holder: other.to_string(),
        },
        _ => RenewalAction::Reassert {
            resource_version: lease.metadata.resource_version.clone(),
        },
    }
}

/// What one pass of [`renew_locks`] found across a run's whole host set.
///
/// The distinction between the two contended variants is the point: only `Lost` is evidence that
/// this run no longer protects a host, and only evidence justifies abandoning an attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum RenewalOutcome {
    /// Every requested lock is (still) this run's.
    Held,
    /// Another holder was observed on one of them — its lease lapsed and a competing run took it
    /// over. Nothing can reclaim it from here; a caller whose Job does not exist yet should give the
    /// attempt up rather than run a second playbook against that host.
    Lost(BlockedBy),
    /// A write race left one lock's ownership unconfirmed this tick. Nothing was seen to have taken
    /// it, so this is a reason to look again shortly, never a reason to give an attempt up.
    Unconfirmed(BlockedBy),
}

impl RenewalOutcome {
    /// The contended host, whichever way it was contended — what the plan's `Blocked` condition
    /// reports.
    pub fn contended(&self) -> Option<&BlockedBy> {
        match self {
            RenewalOutcome::Held => None,
            RenewalOutcome::Lost(blocked) | RenewalOutcome::Unconfirmed(blocked) => Some(blocked),
        }
    }
}

/// Renews every per-host Lease this run holds, extending each for another `LEASE_DURATION_SECONDS`.
/// Called every tick while a run is in progress (`Applying`) so a run that outlasts the lease
/// duration doesn't have its locks silently reclaimed by a competing plan mid-flight.
///
/// Deliberately *not* `ensure_locks`: this never acquires locks it doesn't hold and never releases
/// on conflict (releasing a still-running run's other locks would be exactly the double-run hazard
/// we're guarding against). A contended lock is *reported* only after every still-owned lock has
/// been renewed, so one problem host cannot let the rest of the set expire.
///
/// The two contended outcomes are deliberately kept apart, because only one of them justifies giving
/// a run up: [`RenewalOutcome::Lost`] means another holder was *observed* on the Lease, while
/// [`RenewalOutcome::Unconfirmed`] means a write race left this tick unable to say — nothing was seen
/// to have taken the lock over. Collapsing the second into the first would let a transient 409 tear
/// down a healthy attempt's proxy infrastructure.
pub async fn renew_locks(
    api: &Api<Lease>,
    target_hosts: &[String],
    holder_identity: &str,
) -> Result<RenewalOutcome, ReconcileError> {
    let now = Utc::now();
    let mut lost: Option<BlockedBy> = None;
    let mut unconfirmed: Option<BlockedBy> = None;

    for host in target_hosts {
        let name = lease_name(host);
        let existing = api.get_opt(&name).await?;

        match renewal_decision(existing.as_ref(), holder_identity) {
            RenewalAction::Lost { holder } => {
                warn!(
                    "Lock for host {host} is now held by {holder}, not this run — its lease lapsed \
                     and another run took it over; both may target {host} concurrently"
                );
                lost.get_or_insert_with(|| BlockedBy {
                    host: host.clone(),
                    holder: Some(holder),
                });
            }
            RenewalAction::Reassert { resource_version } => {
                let mut lease = build_lease(&name, holder_identity, now);
                lease.metadata.resource_version = resource_version.clone();

                let result = match resource_version {
                    Some(_) => api
                        .replace(&name, &PostParams::default(), &lease)
                        .await
                        .map(drop),
                    None => api.create(&PostParams::default(), &lease).await.map(drop),
                };

                match result {
                    Ok(()) => {}
                    // Ownership is unconfirmed for this host, but continue renewing every other host
                    // before reporting it so one write race cannot let the rest of the set expire.
                    Err(err) if is_conflict(&err) => {
                        debug!("Lease renewal for host {host} conflicted; ownership unconfirmed");
                        unconfirmed.get_or_insert_with(|| BlockedBy {
                            host: host.clone(),
                            holder: None,
                        });
                    }
                    Err(err) => return Err(err.into()),
                }
            }
        }
    }

    // An observed takeover outranks a mere write race: it is the one this run can act on.
    Ok(renewal_outcome(lost, unconfirmed))
}

fn renewal_outcome(lost: Option<BlockedBy>, unconfirmed: Option<BlockedBy>) -> RenewalOutcome {
    match (lost, unconfirmed) {
        (Some(blocked), _) => RenewalOutcome::Lost(blocked),
        (None, Some(blocked)) => RenewalOutcome::Unconfirmed(blocked),
        (None, None) => RenewalOutcome::Held,
    }
}

/// Releases every Lease this run holds for `target_hosts`. Called explicitly when a run
/// finishes (success or terminal failure) — TTL expiry is the crash safety net only, not the
/// everyday release path.
///
/// Each delete carries the `resourceVersion` of the Lease the holder check was made against, so it
/// cannot outlive the observation that justified it. Without that, a release that arrives after this
/// run's own Lease expired can delete a Lease another run has since taken over, leaving that run
/// executing with no record of its lock and a third free to take the host. The `resourceVersion` is
/// what does the work here, not the UID: a takeover is a `replace` on the same object, so it keeps
/// the UID and changes only the holder and the version. The UID is sent as well, for the one shape
/// the version cannot describe — the Lease being deleted and a new one created under the same name.
pub async fn release_locks(
    api: &Api<Lease>,
    target_hosts: &[String],
    holder_identity: &str,
) -> Result<(), ReconcileError> {
    for host in target_hosts {
        let name = lease_name(host);

        let Some(existing) = api.get_opt(&name).await? else {
            continue;
        };

        let held_by_us = existing
            .spec
            .as_ref()
            .and_then(|s| s.holder_identity.as_deref())
            == Some(holder_identity);

        if !held_by_us {
            continue;
        }

        let params = DeleteParams::default().preconditions(Preconditions {
            resource_version: existing.metadata.resource_version.clone(),
            uid: existing.metadata.uid.clone(),
        });
        match api.delete(&name, &params).await {
            Ok(_) => {}
            // The Lease moved on between the read and the delete, so the object standing here now is
            // not the one the holder check passed for. Whoever holds it now is entitled to it.
            Err(err) if is_conflict(&err) => {
                debug!("Lease {name} changed while it was being released; leaving it alone");
            }
            // Already gone — released by an earlier attempt at this same cleanup, or reclaimed.
            Err(err) if is_not_found(&err) => {}
            Err(err) => return Err(err.into()),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease_with(holder: &str, renew_time: DateTime<Utc>, duration_seconds: i32) -> Lease {
        Lease {
            metadata: ObjectMeta {
                name: Some("some-lease".into()),
                resource_version: Some("42".into()),
                ..Default::default()
            },
            spec: Some(LeaseSpec {
                holder_identity: Some(holder.to_string()),
                lease_duration_seconds: Some(duration_seconds),
                renew_time: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime(
                    chrono_to_jiff(renew_time),
                )),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn decide_creates_when_absent() {
        let now = Utc::now();
        assert_eq!(decide(None, "ns/plan/hash", now), LeaseDecision::Create);
    }

    #[test]
    fn decide_renews_when_held_by_us() {
        let now = Utc::now();
        let lease = lease_with("ns/plan/hash", now - Duration::seconds(10), 90);
        assert_eq!(
            decide(Some(&lease), "ns/plan/hash", now),
            LeaseDecision::Renew {
                resource_version: "42".into()
            }
        );
    }

    #[test]
    fn decide_blocks_when_held_by_other_and_not_expired() {
        let now = Utc::now();
        let lease = lease_with("ns/other-plan/hash", now - Duration::seconds(10), 90);
        assert_eq!(
            decide(Some(&lease), "ns/plan/hash", now),
            LeaseDecision::HeldByOther
        );
    }

    #[test]
    fn decide_replaces_when_held_by_other_but_expired() {
        let now = Utc::now();
        let lease = lease_with("ns/other-plan/hash", now - Duration::seconds(200), 90);
        assert_eq!(
            decide(Some(&lease), "ns/plan/hash", now),
            LeaseDecision::Replace {
                resource_version: "42".into()
            }
        );
    }

    #[test]
    fn decide_treats_missing_renew_time_as_expired() {
        let now = Utc::now();
        let lease = Lease {
            metadata: ObjectMeta {
                name: Some("some-lease".into()),
                resource_version: Some("42".into()),
                ..Default::default()
            },
            spec: Some(LeaseSpec {
                holder_identity: Some("ns/other-plan/hash".into()),
                ..Default::default()
            }),
        };
        assert_eq!(
            decide(Some(&lease), "ns/plan/hash", now),
            LeaseDecision::Replace {
                resource_version: "42".into()
            }
        );
    }

    #[test]
    fn acquisition_order_is_independent_of_input_ordering() {
        // Two plans may enumerate the same hosts in different orders (different inventory groups).
        // The acquisition order must come out identical for both so they contend for the same lock
        // first — that shared ordering is what makes the all-or-nothing acquisition deadlock-free.
        let one = vec![
            "homelab-ctrl-0".to_string(),
            "homelab-worker-1".to_string(),
            "homelab-worker-0".to_string(),
        ];
        let two = vec![
            "homelab-worker-0".to_string(),
            "homelab-ctrl-0".to_string(),
            "homelab-worker-1".to_string(),
        ];

        assert_eq!(acquisition_order(&one), acquisition_order(&two));

        // ...and that order is ascending by lease name.
        let ordered_names: Vec<String> = acquisition_order(&one)
            .iter()
            .map(|host| lease_name(host))
            .collect();
        let mut sorted = ordered_names.clone();
        sorted.sort();
        assert_eq!(ordered_names, sorted);
    }

    #[test]
    fn renewal_reasserts_when_still_ours_or_object_missing() {
        let now = Utc::now();

        // Lease object gone -> recreate it (no resourceVersion to replace).
        assert_eq!(
            renewal_decision(None, "ns/plan/hash"),
            RenewalAction::Reassert {
                resource_version: None
            }
        );

        // Still held by us -> replace in place, carrying its resourceVersion.
        let ours = lease_with("ns/plan/hash", now - Duration::seconds(10), 90);
        assert_eq!(
            renewal_decision(Some(&ours), "ns/plan/hash"),
            RenewalAction::Reassert {
                resource_version: Some("42".into())
            }
        );
    }

    #[test]
    fn renewal_reports_loss_when_another_holder_took_over() {
        // Another holder's identity means we lost the lock mid-run — even if it's expired we do not
        // reclaim it here, we report it, so we never resurrect a lock a live run is now holding.
        let stolen = lease_with("ns/other/hash", Utc::now() - Duration::seconds(500), 90);
        assert_eq!(
            renewal_decision(Some(&stolen), "ns/plan/hash"),
            RenewalAction::Lost {
                holder: "ns/other/hash".into()
            }
        );
    }

    #[test]
    fn observed_takeover_outweighs_a_later_unconfirmed_write() {
        let lost = BlockedBy {
            host: "worker-1".into(),
            holder: Some("ns/other/run".into()),
        };
        let unconfirmed = BlockedBy {
            host: "worker-2".into(),
            holder: None,
        };

        assert_eq!(
            renewal_outcome(Some(lost), Some(unconfirmed)),
            RenewalOutcome::Lost(BlockedBy {
                host: "worker-1".into(),
                holder: Some("ns/other/run".into()),
            })
        );
        assert_eq!(
            renewal_outcome(
                None,
                Some(BlockedBy {
                    host: "worker-2".into(),
                    holder: None,
                })
            ),
            RenewalOutcome::Unconfirmed(BlockedBy {
                host: "worker-2".into(),
                holder: None,
            })
        );
        assert_eq!(renewal_outcome(None, None), RenewalOutcome::Held);
    }

    #[test]
    fn lease_name_is_deterministic_and_dns_safe() {
        let a = lease_name("worker-1");
        let b = lease_name("worker-1");
        let c = lease_name("192.168.1.42");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-'));
    }

    #[test]
    fn jiff_chrono_roundtrip_preserves_seconds() {
        let now = Utc::now();
        let now = DateTime::from_timestamp(now.timestamp(), 0).unwrap();
        let roundtripped = jiff_to_chrono(&chrono_to_jiff(now)).unwrap();
        assert_eq!(now, roundtripped);
    }
}
