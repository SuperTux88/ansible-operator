use std::time::Duration;

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
