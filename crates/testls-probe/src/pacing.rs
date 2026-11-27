//! Start-to-start pacing for target connections within one scan future.

use std::cell::Cell;
use std::future::Future;
use std::time::Duration;

use tokio::time::{Instant, sleep};

tokio::task_local! {
    /// Joined probes share one clock; independently polled scans have their own.
    static PACER: (Duration, Cell<Option<Instant>>);
}

/// Runs one target's probes with at least `delay` between TCP connection starts.
/// The first start is immediate. Join concurrent probe futures inside the scope:
/// separately spawned tasks do not inherit it. DNS and CA fetches are independent.
pub async fn with_connection_delay<F: Future>(delay: Duration, probes: F) -> F::Output {
    PACER.scope((delay, Cell::new(None)), probes).await
}

/// Admits one start, measuring from actual admission instead of reserving future
/// slots: late wakeups cannot bunch together, and cancellation wastes no slot.
pub(crate) async fn wait() {
    loop {
        let remaining = PACER.try_with(|(delay, last)| {
            let now = Instant::now();
            let wait = last.get().map_or(Duration::ZERO, |previous| {
                delay.saturating_sub(now.duration_since(previous))
            });
            if wait.is_zero() {
                last.set(Some(now));
            }
            wait
        });
        match remaining {
            Ok(d) if !d.is_zero() => sleep(d).await,
            _ => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Joined callers cannot spend the same slot, even when several timers wake together.
    #[tokio::test(start_paused = true)]
    async fn spaces_actual_starts() {
        let gap = Duration::from_secs(2);
        let t = Instant::now();
        let start = || async {
            wait().await;
            Instant::now() - t
        };
        let (a, b, c) =
            with_connection_delay(gap, async { tokio::join!(start(), start(), start()) }).await;
        let mut times = [a, b, c];
        times.sort();
        assert_eq!(times, [Duration::ZERO, gap, gap * 2]);
        assert_eq!(with_connection_delay(gap, start()).await, gap * 2);
    }
}
