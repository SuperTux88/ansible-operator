use std::time::Duration;

use kube::runtime::{utils::Backoff, watcher::DefaultBackoff};

/// The backoff for every `watcher` stream this operator drives: kube's [`DefaultBackoff`] without
/// the reset that `StreamBackoff` performs on every `Ok` item, which is all
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
}
