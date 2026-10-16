//! Timing spans for measuring the hot paths.
//!
//! Not a metrics system: a process-wide table of named spans that records
//! durations only while [`enable`] is on, read back with [`take`] and
//! summarised with [`report`].  Off, a span costs one relaxed atomic load.
//! The benchmarks in `bench.rs` turn it on; nothing else does.
//!
//! Span names are `area.step`, so a report sorts by area:
//! `append.*` (segment fsync, coordinator CAS), `effect.*` (the dispatch
//! sequence), `pack.*` (shipping), `seal.*` and `publish.*` (a Seal and
//! its publication).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Instant;

static ENABLED: AtomicBool = AtomicBool::new(false);
static SPANS: Mutex<BTreeMap<&'static str, Vec<u64>>> = Mutex::new(BTreeMap::new());

/// Start or stop recording.
pub fn enable(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

/// A running span; records its duration (µs) under its name when dropped.
#[must_use = "a span measures until it is dropped"]
pub struct Span {
    name: &'static str,
    start: Option<Instant>,
}

/// Start a span named `name`.
pub fn span(name: &'static str) -> Span {
    Span { name, start: ENABLED.load(Ordering::Relaxed).then(Instant::now) }
}

impl Drop for Span {
    fn drop(&mut self) {
        if let Some(start) = self.start {
            let us = start.elapsed().as_micros() as u64;
            SPANS.lock().unwrap_or_else(|e| e.into_inner()).entry(self.name).or_default().push(us);
        }
    }
}

/// Every recorded duration (µs) by span name, clearing the table.
pub fn take() -> BTreeMap<&'static str, Vec<u64>> {
    std::mem::take(&mut *SPANS.lock().unwrap_or_else(|e| e.into_inner()))
}

/// The `q` quantile (0..=1) of `v`, which must be sorted.
pub fn quantile(v: &[u64], q: f64) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v[((v.len() - 1) as f64 * q).round() as usize]
}

/// One line per span: count, p50, p95, p99 and max, in milliseconds.
pub fn report(spans: &BTreeMap<&'static str, Vec<u64>>) -> String {
    let mut out = format!("{:<22} {:>6} {:>9} {:>9} {:>9} {:>9}\n", "span", "n", "p50 ms", "p95 ms", "p99 ms", "max ms");
    for (name, v) in spans {
        let mut v = v.clone();
        v.sort_unstable();
        let ms = |us: u64| us as f64 / 1000.0;
        let _ = writeln!(
            out,
            "{:<22} {:>6} {:>9.3} {:>9.3} {:>9.3} {:>9.3}",
            name,
            v.len(),
            ms(quantile(&v, 0.50)),
            ms(quantile(&v, 0.95)),
            ms(quantile(&v, 0.99)),
            ms(*v.last().unwrap_or(&0)),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantiles() {
        let v: Vec<u64> = (1..=100).collect();
        assert_eq!(quantile(&v, 0.5), 51);
        assert_eq!(quantile(&v, 0.95), 95);
        assert_eq!(quantile(&v, 1.0), 100);
        assert_eq!(quantile(&[], 0.5), 0);
    }
}
