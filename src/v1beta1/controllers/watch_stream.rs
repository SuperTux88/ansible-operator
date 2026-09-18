use std::time::{Duration, Instant};

use futures::{Stream, StreamExt as _, stream};
use kube::runtime::utils::Backoff;
use kube::runtime::watcher::DefaultBackoff;
use kube::runtime::{WatchStreamExt as _, watcher};
use kube::{Api, Resource};
use serde::de::DeserializeOwned;

/// The watch stream every reflector and trigger in this operator is built on: a [`watcher`] that is
/// **thrown away and rebuilt from a fresh LIST after any error**, rather than resumed.
///
/// `watcher` resumes. On an error it hands the error up and keeps the state it had — including, in
/// `State::Watching`, the very HTTP response body that produced the error. The next poll does not
/// re-request anything; it reads the next line out of that same response. That is only a subtlety
/// until the response is an error body, because `kube_client`'s watch path never checks the HTTP
/// status (`Client::request_events`, unlike `Client::request_text`, does not call
/// `handle_api_errors`) and instead frames the body by lines and parses each one as a `WatchEvent`.
/// A compact single-line `Status` is recovered by a fallback and reported as one API error; a
/// **pretty-printed** one is not, and becomes one `SerdeError` per line.
///
/// That is not hypothetical: a k3s apiserver that restarts answers the metadata watches
/// (`selector_trigger::label_changes`, which asks for `PartialObjectMetadata`) with a pretty-printed
/// `403` while its RBAC is still loading. Resuming turned that single 403 into a dozen stream
/// errors, each one paying a full backoff delay, so the operator spent five and a half minutes
/// reading an error message it had already received — four of them after the apiserver was healthy
/// again. Restarting discards the body with the watcher, so one bad response costs exactly one
/// error.
///
/// Restarting also settles the other half of that incident. A resumed watch re-asks from the
/// `resourceVersion` it last saw, which after an apiserver restart is far enough behind to be
/// refused with `410 Expired` — another error, another delay, before the re-LIST that was always
/// going to be needed. A rebuilt watcher LISTs first, so there is no stale version to be refused.
///
/// The cost is a full re-LIST per error, which is what `client-go`'s reflector has always done. It
/// is bounded by the backoff below, and it is not paid on the routine path: the apiserver closing a
/// watch at its 290s timeout ends the body cleanly, which `watcher` reports as no event at all and
/// resumes from — not as an error.
pub fn restarting_watcher<K>(
    api: Api<K>,
    config: watcher::Config,
) -> impl Stream<Item = watcher::Result<watcher::Event<K>>> + Send + 'static
where
    K: Resource + Clone + DeserializeOwned + std::fmt::Debug + Send + 'static,
{
    restarting(move || watcher(api.clone(), config.clone()).boxed())
        .backoff(WatchBackoff::default())
}

/// Yields from `start()`'s stream until it fails, then drops it and starts a new one.
///
/// Split from [`restarting_watcher`] so the restart itself can be tested without an apiserver.
fn restarting<T, E, S, F>(mut start: F) -> impl Stream<Item = Result<T, E>> + Send
where
    F: FnMut() -> S + Send + 'static,
    S: Stream<Item = Result<T, E>> + Unpin + Send + 'static,
{
    stream::unfold(None, move |current: Option<S>| {
        let mut stream = current.unwrap_or_else(&mut start);
        async move {
            let item = stream.next().await?;
            let carry = item.is_ok().then_some(stream);
            Some((item, carry))
        }
    })
}

/// The backoff for every watch stream this operator drives: kube's [`DefaultBackoff`] without the
/// reset that `StreamBackoff` performs on every `Ok` item, which is all
/// `WatchStreamExt::default_backoff` gives.
///
/// That reset undoes the backoff exactly where it is needed. A failed LIST sends `watcher` back to
/// its initial state, whose first item is `Ok(Event::Init)`, yielded before the LIST is retried, so
/// every attempt of a failing re-list starts again from the 800 ms floor. A LIST that keeps failing
/// — a grant missing at startup, a LIST refused after a `410 Gone` — then retries about once a
/// second for as long as it fails, with an `error!` line each time; only a failing *watch*, resumed
/// from a resourceVersion without an `Init`, ever grows its delay.
///
/// What is left is `DefaultBackoff`'s own reset, once two minutes pass between errors. A watch that
/// recovers and fails again inside that window resumes at the delay it had reached instead of the
/// floor: slower to retry a second blip, which is the price of not being reset by an item that
/// proves nothing.
#[derive(Default)]
pub struct WatchBackoff(DefaultBackoff);

impl Iterator for WatchBackoff {
    type Item = Duration;

    fn next(&mut self) -> Option<Duration> {
        self.0.next()
    }
}

impl Backoff for WatchBackoff {
    fn reset(&mut self) {}
}

/// [`WatchBackoff`]'s policy for a delay that several streams **share**: the same 800 ms floor, and
/// the same 30 s ceiling *divided by the number of streams sharing it*.
///
/// `Controller::run` wraps every trigger stream it has in a single `StreamBackoff`, and while that
/// waits it polls none of them. A delay is therefore paid per **error**, not per stream, and the
/// streams take turns: eleven streams reporting one error each is charged exactly as eleven errors
/// from one stream. kube's 30 s ceiling is chosen for a stream that has a delay to itself, so
/// sharing it between the `PlaybookPlan` controller's eleven streams throttles each of them to one
/// attempt every five and a half minutes — eleven times more conservative than kube intends — and
/// makes any recovery that needs one error from every stream take just as long. An apiserver
/// restart is exactly that recovery, twice over: each stream reports the death of its response body
/// and then the `410 Expired` its resumed watch earns. The controller spent 13m49s of it
/// rediscovering an apiserver that had been healthy since the first thirteen seconds.
///
/// Dividing restores kube's intent on both counts at once. Each stream is still retried about twice
/// a minute while the apiserver is away, and a recovery that needs one error per stream now costs
/// about as long as one stream's ceiling rather than one per stream — so the two errors a restart
/// costs every stream are paid off in about two ceilings, a minute or so, whatever the divisor.
///
/// **The division stops at [`FLOOR`].** Holding the per-stream rate constant means the controller's
/// own rate grows with its stream count, and an install with enough enrolled namespaces would answer
/// an apiserver that is already down with several requests a second and a `warn!` line for each.
/// Past about thirty-seven streams the ceiling is the floor instead, which bounds that at one
/// request every 800 ms and pays for it in recovery time — linear in the stream count from there,
/// about five minutes for a hundred enrolled namespaces.
///
/// No jitter, unlike [`DefaultBackoff`]: jitter spreads out clients that would otherwise retry in
/// step, and there is one of these driving one merged stream. That does make this the more
/// aggressive policy by about half, since kube's jitter is additive and its 30 s ceiling is really
/// 30–60 s — the incident's steps measured fifty seconds — and the direction is intended: a delay
/// that several streams are queueing behind should be the delay it says it is.
pub struct SharedBackoff {
    ceiling: Duration,
    /// The delay last handed out; `None` when the next one starts from the floor.
    current: Option<Duration>,
    /// When the last delay was handed out, to notice that the errors have stopped.
    last_delay: Option<Instant>,
}

/// The first delay of a run, and the smallest. kube's [`DefaultBackoff`] floor, which is not divided
/// — it is paid once per run of errors rather than once per stream — and which the divided ceiling
/// is never allowed below.
const FLOOR: Duration = Duration::from_millis(800);

/// The ceiling a stream would have to itself, and so the budget [`SharedBackoff`] divides up.
const UNSHARED_CEILING: Duration = Duration::from_secs(30);

/// How long without an error means the run is over and the next delay starts from [`FLOOR`] again.
///
/// Matches `DefaultBackoff`'s own idle-reset window so the two agree on how long "a while" is.
const IDLE_RESET: Duration = Duration::from_secs(120);

impl SharedBackoff {
    /// `streams` is how many trigger streams the `Controller` will poll through this one delay —
    /// for the `PlaybookPlan` controller, five cluster-wide plus two per enrolled namespace.
    pub fn new(streams: usize) -> Self {
        Self {
            ceiling: (UNSHARED_CEILING / u32::try_from(streams.max(1)).unwrap_or(u32::MAX))
                .max(FLOOR),
            current: None,
            last_delay: None,
        }
    }

    fn delay_at(&mut self, now: Instant) -> Duration {
        let resumed = self
            .last_delay
            .is_some_and(|at| now.duration_since(at) < IDLE_RESET);
        let delay = match self.current.filter(|_| resumed) {
            Some(previous) => (previous * 2).min(self.ceiling),
            None => FLOOR,
        };

        self.current = Some(delay);
        self.last_delay = Some(now);
        delay
    }
}

impl Iterator for SharedBackoff {
    type Item = Duration;

    fn next(&mut self) -> Option<Duration> {
        // `tokio`'s clock rather than the standard library's, matching kube's `ResetTimerBackoff`,
        // so a paused clock moves the idle reset along with the delays it is measuring.
        Some(self.delay_at(tokio::time::Instant::now().into_std()))
    }
}

impl Backoff for SharedBackoff {
    /// Honoured, unlike [`WatchBackoff`]'s, because what an `Ok` means here is different. This
    /// backoff sits behind `Controller`'s trigger selector, so the items reaching it are
    /// `ReconcileRequest`s — mapped from an object the apiserver actually delivered. A raw
    /// `watcher` stream, which is all [`WatchBackoff`] ever wraps, offers `Ok(Event::Init)` before
    /// every attempt of a failing LIST, and that proves nothing.
    fn reset(&mut self) {
        self.current = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ok_item_does_not_bring_the_delay_back_to_its_floor() {
        let mut backoff = WatchBackoff::default();
        for _ in 0..5 {
            backoff.next();
        }

        backoff.reset();

        // The floor is 800 ms, at most doubled by jitter; the sixth delay is at least 25.6 s.
        assert!(backoff.next().expect("the backoff never gives up") > Duration::from_secs(2));
    }

    /// The `PlaybookPlan` controller's own count: five cluster-wide streams plus two per enrolled
    /// namespace, for the three namespaces the cluster tests enrol.
    const STREAMS: usize = 5 + 2 * 3;

    /// Drains `errors` of them and returns what the controller spent waiting.
    fn spent_on(backoff: &mut SharedBackoff, errors: usize) -> Duration {
        let start = Instant::now();
        let mut now = start;
        for _ in 0..errors {
            now += backoff.delay_at(now);
        }
        now.duration_since(start)
    }

    /// The requirement this type exists for. An apiserver restart leaves every trigger stream with
    /// one dead response body and then one `410 Expired` for the watch it resumes, and the shared
    /// delay is paid once per error — so the whole recovery costs about two ceilings rather than two
    /// per stream, and the divisor does not change that. The incident this replaced took 13m49s.
    ///
    /// Up to `UNSHARED_CEILING / FLOOR` streams, that is; past there the ceiling is the floor, which
    /// [`a_large_install_buys_its_bounded_request_rate_with_recovery_time`] pays for.
    #[test]
    fn a_restart_costs_two_errors_per_stream_and_recovers_in_about_two_ceilings() {
        for streams in [1, 7, STREAMS, 25, 37] {
            let mut backoff = SharedBackoff::new(streams);

            let spent = spent_on(&mut backoff, 2 * streams);

            assert!(
                spent <= 2 * UNSHARED_CEILING + FLOOR,
                "{streams} streams must not spend more than two ceilings rediscovering a healthy apiserver, spent {spent:?}"
            );
        }
    }

    /// The other half of the requirement: dividing the ceiling must not turn into hammering an
    /// apiserver that is still away. Each stream gets its turn once per `streams` delays, so the
    /// whole controller costs what kube's undivided ceiling would have given one stream — and never
    /// asks more often than [`FLOOR`], however many streams are sharing.
    #[test]
    fn the_whole_controller_costs_no_more_than_one_streams_worth_of_retries() {
        for streams in [1, 7, STREAMS, 37, 45, 205] {
            let mut backoff = SharedBackoff::new(streams);
            // Long enough to be at the ceiling.
            spent_on(&mut backoff, 20);

            let delay = backoff.delay_at(Instant::now());

            assert!(
                delay >= FLOOR,
                "{streams} streams must not drive the shared delay below its floor, was {delay:?}"
            );
            assert!(
                delay * u32::try_from(streams).unwrap()
                    >= UNSHARED_CEILING - Duration::from_secs(1),
                "{streams} streams must not cost the apiserver more than one stream's worth of retries, spend {delay:?} each"
            );
        }
    }

    /// What clamping the division at [`FLOOR`] costs. An install with enough enrolled namespaces
    /// trades the recovery above for a request rate that stays bounded while the apiserver is down,
    /// and the point of the trade is that it still recovers on its own, in minutes.
    #[test]
    fn a_large_install_buys_its_bounded_request_rate_with_recovery_time() {
        // A hundred enrolled namespaces.
        let streams = 205;
        let mut backoff = SharedBackoff::new(streams);

        let spent = spent_on(&mut backoff, 2 * streams);

        assert!(
            spent > 2 * UNSHARED_CEILING,
            "the floor is what is being paid for here, and {spent:?} says it was not reached"
        );
        assert!(
            spent < Duration::from_secs(360),
            "a recovery that needs two errors from every stream must still be minutes, was {spent:?}"
        );
    }

    /// A delay to yourself is undivided, so a controller with one trigger stream is exactly kube's
    /// policy minus the jitter.
    #[test]
    fn a_single_stream_keeps_the_whole_ceiling() {
        let mut backoff = SharedBackoff::new(1);
        spent_on(&mut backoff, 20);

        assert_eq!(backoff.delay_at(Instant::now()), UNSHARED_CEILING);
    }

    /// A `ReconcileRequest` reached the controller, which only an object the apiserver delivered can
    /// produce. Unlike a raw `watcher`'s `Ok(Event::Init)`, that is worth starting over for.
    #[test]
    fn a_reconcile_request_brings_the_delay_back_to_its_floor() {
        let mut backoff = SharedBackoff::new(STREAMS);
        spent_on(&mut backoff, 20);

        backoff.reset();

        assert_eq!(backoff.delay_at(Instant::now()), FLOOR);
    }

    /// Errors that stop and start again are two runs, not one long one.
    #[test]
    fn a_quiet_spell_starts_the_next_run_from_the_floor() {
        let mut backoff = SharedBackoff::new(STREAMS);
        let start = Instant::now();
        for _ in 0..20 {
            backoff.delay_at(start);
        }

        assert_eq!(backoff.delay_at(start + IDLE_RESET), FLOOR);
    }

    /// Everything a healthy stream yields is passed through, and nothing is restarted while it
    /// keeps yielding.
    #[tokio::test]
    async fn a_stream_that_does_not_fail_is_never_restarted() {
        let mut starts = 0;
        let stream = restarting(move || {
            starts += 1;
            assert_eq!(starts, 1, "a healthy stream must not be rebuilt");
            stream::iter(vec![Ok::<_, ()>(1), Ok(2), Ok(3)]).boxed()
        });

        assert_eq!(stream.collect::<Vec<_>>().await, vec![Ok(1), Ok(2), Ok(3)]);
    }

    /// The whole point: what follows an error comes from a new stream, not from the one that
    /// failed. A resumed `watcher` would go on reading the response that produced the error.
    #[tokio::test]
    async fn an_error_is_reported_once_and_the_next_item_comes_from_a_new_stream() {
        let mut starts = 0;
        let stream = restarting(move || {
            starts += 1;
            match starts {
                // The shape of the incident: one failed response carrying several errors.
                1 => stream::iter(vec![Err("first line"), Err("second line"), Ok(1)]).boxed(),
                _ => stream::iter(vec![Ok(2)]).boxed(),
            }
        });

        assert_eq!(
            stream.collect::<Vec<_>>().await,
            vec![Err("first line"), Ok(2)],
            "the rest of the failed stream is dropped with it"
        );
    }
}
