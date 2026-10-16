//! Benchmarks of the hot paths: measurements, not tests.
//!
//! Each one turns [`crate::timing`] on, drives the real code path many
//! times, and prints a span table plus how latency changes as the log
//! grows.  Run them alone and in release, or other tests' spans mix in:
//!
//! ```text
//! cargo test --release -p taso-warden bench:: -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `TMPDIR` picks the disk the segment, coordinator and pack store live on
//! (local NVMe for gate numbers).  `TASO_BENCH_N` sets the iterations.
//! `bench::node::*` needs `TASO_ZFS_DATASET`, as the node tests do.
//!
//! What is real: segment appends (fsync), the coordinator (redb, fsync,
//! in-process: no socket), packs over [`LocalStore`] (fsync, rename), the
//! effect engine and the publish flow.  What is fake: the provider, and
//! outside `node`, the layers and the `fs` stream.

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io;
    use std::time::Instant;

    use taso_core::envelope::{Lsn, Stream};
    use taso_core::record::{Payload, StreamCut, TurnId, Verdict};
    use taso_field::adapter::{Call, FakeProvider, Registry};

    use crate::chronicle::Layers;
    use crate::effects::Effects;
    use crate::pack::{PackPublisher, Packs};
    use crate::segment::Position;
    use crate::ship::{ByteStream, LocalStore, Sender};
    use crate::timing;
    use crate::vessel::tests::{env, ns};
    use crate::vessel::Vessel;
    use crate::zfs::{Dataset, Snapshot};

    fn n(default: usize) -> usize {
        std::env::var("TASO_BENCH_N").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
    }

    /// p50 and p95 (ms) of `durations` (µs) in consecutive blocks of `block`:
    /// how a path's latency moves as the log grows.
    fn growth(name: &str, durations: &[u64], block: usize) -> String {
        let mut out = format!("{name} by position in the run (p50 / p95 ms):\n");
        for (i, chunk) in durations.chunks(block).enumerate() {
            let mut v = chunk.to_vec();
            v.sort_unstable();
            out += &format!(
                "  {:>5}..{:<5} {:>8.3} / {:>8.3}\n",
                i * block,
                i * block + chunk.len(),
                timing::quantile(&v, 0.5) as f64 / 1000.0,
                timing::quantile(&v, 0.95) as f64 / 1000.0
            );
        }
        out
    }

    fn print(title: &str, spans: &BTreeMap<&'static str, Vec<u64>>, growth_of: &str, block: usize, wall: f64) {
        println!("\n=== {title} ===");
        println!("TMPDIR={}", std::env::var("TMPDIR").unwrap_or_else(|_| "(default)".into()));
        print!("{}", timing::report(spans));
        if let Some(v) = spans.get(growth_of) {
            print!("{}", growth(growth_of, v, block));
            println!("throughput: {:.0} per second", v.len() as f64 / wall);
        }
    }

    /// A stream of fixed size; only publishing is measured, not `zfs send`.
    struct FixedSend(usize);
    impl Sender for FixedSend {
        fn send(&self, _: &Dataset, _: Option<&str>, _: Lsn) -> io::Result<ByteStream> {
            Ok(Box::new(io::Cursor::new(vec![7u8; self.0])))
        }
    }

    /// One effect at a time through the whole sequence: intent, authorize,
    /// publish (log pack + shipped anchor), send, outcome.
    #[test]
    #[ignore = "benchmark: run alone, in release"]
    fn dispatch() {
        let count = n(1000);
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"bench").unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let packs = Packs::new(LocalStore::new(store_dir.path()), FixedSend(0), "vessels", v.id()).unwrap();
        let publisher = PackPublisher::new(packs, e.host.coord.clone(), e.host.warden);
        let mut registry = Registry::new();
        registry.register(Box::new(FakeProvider::new("mail")));
        let (mut fx, _) = Effects::open(registry, Box::new(publisher), &mut v).unwrap();

        timing::take();
        timing::enable(true);
        let start = Instant::now();
        for i in 0..count {
            let call = Call { operation: "send".into(), args: format!("user-{i}").into_bytes() };
            fx.dispatch(&mut v, "mail", call).unwrap();
        }
        let wall = start.elapsed().as_secs_f64();
        timing::enable(false);
        let spans = timing::take();
        print(&format!("dispatch: {count} effects, one Vessel"), &spans, "effect.total", count / 4, wall);
        assert_eq!(spans["effect.total"].len(), count);
    }

    fn snapshot_of<L: Layers>(v: &Vessel<L>, seal: Position) -> Snapshot {
        Snapshot { dataset: v.dataset().clone(), seal: seal.lsn, createtxg: 1, guid: 1000 + seal.lsn.get(), seal_hash: Some(seal.hash) }
    }

    /// A turn of `records` appends, then a Seal and its publication (Seal
    /// pack with a 64 KiB stream, FsShipped, log, shipped anchor).
    #[test]
    #[ignore = "benchmark: run alone, in release"]
    fn seal_and_publish() {
        let count = n(300);
        let records = 5;
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"bench").unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let packs = Packs::new(LocalStore::new(store_dir.path()), FixedSend(64 << 10), "vessels", v.id()).unwrap();

        timing::take();
        timing::enable(true);
        let start = Instant::now();
        for turn in 0..count {
            for r in 0..records {
                v.append(Stream::Fs, Payload::Raw(vec![r as u8; 200])).unwrap();
            }
            let seal = v.seal(StreamCut::EMPTY, Verdict::Clean, Lsn::new(0), TurnId::new(turn as u64 + 1)).unwrap().seal;
            v.publish_seal(&packs, &snapshot_of(&v, seal), None).unwrap();
        }
        let wall = start.elapsed().as_secs_f64();
        timing::enable(false);
        let spans = timing::take();
        print(
            &format!("seal + publish: {count} turns of {records} records, one Vessel, fake layers"),
            &spans,
            "publish.total",
            count / 4,
            wall,
        );
        assert_eq!(spans["publish.total"].len(), count);
    }

    mod node {
        use super::*;
        use crate::coordinator::Coordinator;
        use crate::ship::ZfsSend;
        use crate::vessel::Host;
        use crate::zfs::{Cli, Zfs};
        use std::process::Command;
        use std::sync::Arc;
        use taso_core::model::WardenId;

        /// The P1 gate's Seal line at its concurrency: `TASO_BENCH_VESSELS`
        /// Vessels (64) on one pool, each writing a 16 KiB file, appending
        /// a record and sealing, `TASO_BENCH_N` (20) turns each, all at
        /// once.  Gate: Seal p95 < 50 ms at p64 (v1.0 §1 P1).  On network
        /// block storage this is a warning signal, not a gate number.
        #[test]
        #[ignore = "benchmark on a ZFS pool: set TASO_ZFS_DATASET; run alone, in release"]
        fn seals_at_p64_on_zfs() {
            p64(false);
        }

        /// As `seals_at_p64_on_zfs`, with Seal snapshots batched: one
        /// channel program and one txg per batch ([`crate::snapbatch`]).
        #[test]
        #[ignore = "benchmark on a ZFS pool: set TASO_ZFS_DATASET; run alone, in release"]
        fn seals_at_p64_batched_on_zfs() {
            p64(true);
        }

        fn p64(batched: bool) {
            let turns = n(20);
            let vessels: usize =
                std::env::var("TASO_BENCH_VESSELS").ok().and_then(|v| v.parse().ok()).unwrap_or(64);
            let Ok(base) = std::env::var("TASO_ZFS_DATASET") else {
                println!("\n=== seals at p{vessels} on ZFS: skipped, TASO_ZFS_DATASET is not set ===");
                return;
            };
            let root = format!("{base}/p64{}-{}", if batched { "b" } else { "" }, std::process::id());
            let zfs = if batched { Zfs::<Cli>::cli().batched() } else { Zfs::<Cli>::cli() };
            Zfs::create(&zfs, &Dataset::new(&root).unwrap()).unwrap();
            struct Cleanup(String);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = Command::new("zfs").args(["destroy", "-R", &self.0]).status();
                }
            }
            let _c = Cleanup(root.clone());
            let tmp = tempfile::tempdir().unwrap();
            let host = Host {
                coord: Arc::new(Coordinator::open(tmp.path().join("coord.redb")).unwrap()),
                pool: Clone::clone(&zfs),
                root: Dataset::new(&root).unwrap(),
                state_dir: tmp.path().join("state"),
                warden: WardenId::new(1),
            };
            let mut all = Vec::new();
            for i in 0..vessels {
                let (v, _) = host.ensure(ns(1), format!("bench-{i}").as_bytes()).unwrap();
                let mount = zfs.dataset_info(v.dataset()).unwrap().unwrap().mountpoint.unwrap();
                all.push((v, mount));
            }

            timing::take();
            timing::enable(true);
            let start = Instant::now();
            let go = std::sync::Barrier::new(vessels);
            std::thread::scope(|scope| {
                for (v, mount) in all.iter_mut() {
                    let go = &go;
                    scope.spawn(move || {
                        go.wait();
                        for turn in 0..turns {
                            std::fs::write(mount.join(format!("f{}", turn % 4)), vec![turn as u8; 16 << 10]).unwrap();
                            v.append(Stream::Fs, Payload::Raw(vec![1; 200])).unwrap();
                            v.seal(StreamCut::EMPTY, Verdict::Clean, Lsn::new(0), TurnId::new(turn as u64 + 1)).unwrap();
                        }
                    });
                }
            });
            let wall = start.elapsed().as_secs_f64();
            timing::enable(false);
            let spans = timing::take();
            let how = if batched { "batched snapshots" } else { "one zfs snapshot per Seal" };
            let title = format!("seals at p{vessels} on ZFS, {how}: {turns} turns each, dataset {root}");
            print(&title, &spans, "seal.total", (vessels * turns / 4).max(1), wall);
            let mut seal = spans["seal.total"].clone();
            seal.sort_unstable();
            let p95 = timing::quantile(&seal, 0.95) as f64 / 1000.0;
            println!("gate (Seal p95 < 50 ms): {p95:.1} ms -> {}", if p95 < 50.0 { "within" } else { "OVER" });
            assert_eq!(seal.len(), vessels * turns);
        }

        /// As `seal_and_publish`, on a real dataset: a 64 KiB file written
        /// per turn, a ZFS snapshot per Seal, `zfs send -i` into the pack.
        #[test]
        #[ignore = "benchmark on a ZFS pool: set TASO_ZFS_DATASET; run alone, in release"]
        fn seal_and_publish_on_zfs() {
            let count = n(100);
            let Ok(base) = std::env::var("TASO_ZFS_DATASET") else {
                println!("\n=== seal + publish on ZFS: skipped, TASO_ZFS_DATASET is not set ===");
                return;
            };
            let root = format!("{base}/bench-{}", std::process::id());
            let zfs = Zfs::<Cli>::cli();
            Zfs::create(&zfs, &Dataset::new(&root).unwrap()).unwrap();
            struct Cleanup(String);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = Command::new("zfs").args(["destroy", "-R", &self.0]).status();
                }
            }
            let _c = Cleanup(root.clone());
            let tmp = tempfile::tempdir().unwrap();
            let host = Host {
                coord: Arc::new(Coordinator::open(tmp.path().join("coord.redb")).unwrap()),
                pool: Clone::clone(&zfs),
                root: Dataset::new(&root).unwrap(),
                state_dir: tmp.path().join("state"),
                warden: WardenId::new(1),
            };
            let (mut v, _) = host.ensure(ns(1), b"bench").unwrap();
            let mount = zfs.dataset_info(v.dataset()).unwrap().unwrap().mountpoint.unwrap();
            let packs = Packs::new(LocalStore::new(tmp.path().join("store")), ZfsSend::default(), "vessels", v.id()).unwrap();

            timing::take();
            timing::enable(true);
            let start = Instant::now();
            for turn in 0..count {
                std::fs::write(mount.join(format!("f{}", turn % 8)), vec![turn as u8; 64 << 10]).unwrap();
                v.append(Stream::Fs, Payload::Raw(vec![1; 200])).unwrap();
                let seal = v.seal(StreamCut::EMPTY, Verdict::Clean, Lsn::new(0), TurnId::new(turn as u64 + 1)).unwrap().seal;
                let snap = {
                    // One snapshot, not the whole list (which grows with
                    // every Seal: the 2026-10-16 finding).
                    let _t = timing::span("bench.zfs_get");
                    zfs.get(v.dataset(), seal.lsn).unwrap().expect("the Seal's snapshot")
                };
                v.publish_seal(&packs, &snap, None).unwrap();
            }
            let wall = start.elapsed().as_secs_f64();
            timing::enable(false);
            let spans = timing::take();
            print(&format!("seal + publish on ZFS: {count} turns, dataset {root}"), &spans, "publish.total", count / 4, wall);
            assert_eq!(spans["publish.total"].len(), count);
        }
    }
}
