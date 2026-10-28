//! `taso-blkd`: the block log spike's daemon (spike file 3).
//!
//! Serves branches of one [`Store`] as Linux block devices over ublk, so
//! ext4 can sit on top.  One device per attached branch; one log for all.
//!
//! ```text
//!   taso-blkd LOG SOCKET [--size-gib N] [--depth N] [--queues N] [--threads N] [--io-kib N]
//!             [--checkpoint-mib N] [--compact-pct N] [--compact-min-mib N]
//! ```
//!
//! Opens LOG (creating it if missing; recovery runs and is reported), then
//! takes commands on the Unix socket SOCKET, one per line, one answer line
//! each, starting `ok` or `err`:
//!
//! | command          | does                                             | answer               |
//! |------------------|--------------------------------------------------|----------------------|
//! | `root`           | a Template's first Seal (empty, zeros)           | `ok <seal>`          |
//! | `branch <seal> [name]` | a branch on the Seal, no device (lazy)     | `ok <branch>`        |
//! | `fork <seal> [name]` | `branch`, then `attach`                      | `ok <branch> <dev>`  |
//! | `attach <branch>`| a device for a branch (before mounting it)       | `ok <dev>`           |
//! | `seal <branch> [tag]` | freeze the branch as a Seal, tag in hex     | `ok <seal>`          |
//! | `name <branch> [name]` | name the branch (no name: take it away)    | `ok`                 |
//! | `find <name>`    | the live branch with that name                   | `ok <branch>`        |
//! | `seals <branch>` | the branch's own Seals, oldest first             | `ok <seal>:<tag> ...`|
//! | `info <layer>`   | what a layer is                                  | `ok key=value ...`   |
//! | `detach <branch>`| stop the branch's device                         | `ok`                 |
//! | `reset <branch>` | back to the Seal it stands on (detached only)    | `ok`                 |
//! | `export <seal> <base>\|- <file>` | the Seal as a stream into a new file | `ok <blocks>`  |
//! | `import <branch> <file>` | apply a stream (detached, clean branch)  | `ok <blocks>`        |
//! | `names`          | every named branch                               | `ok <name>:<branch> ...` |
//! | `checkpoint`     | flush and write `<log>.ckpt` for a fast start    | `ok <lsn>`           |
//! | `compact`        | rewrite the log with only live blocks            | `ok before=… after=… live=… records=…` |
//! | `drop <layer>`   | detach if needed, drop the branch or Seal        | `ok`                 |
//! | `flush`          | end a group                                      | `ok <lsn>`           |
//! | `stats`          | counters, for measurements                       | `ok key=value ...`   |
//! | `quit`           | stop every device, flush, then exit              | `ok`                 |
//!
//! Names are dataset names (`A-Z a-z 0-9 _ . : / -`, unique among live
//! branches); tags are opaque bytes in lowercase hex (at most 64 bytes).
//! A name given with `branch` or `fork` is checked before the branch is
//! made, so a taken name makes nothing.  Names and branches are durable at
//! the next `flush`; a Seal is durable when `seal` answers.
//!
//! `info` answers `kind=branch|seal parent=<layer>|- name=<name>|-
//! tag=<hex>|- origin=<layer>|- dev=<path>|-`.
//!
//! # Checkpoints
//!
//! A start replays the log after the last checkpoint only (see the
//! store).  The daemon writes one on `quit`, on the `checkpoint` command,
//! and by itself whenever the log has grown by `--checkpoint-mib` (256 by
//! default; 0 turns that off) since the last one.
//!
//! # Compaction
//!
//! The log only grows; overwritten, discarded and dropped blocks stay in
//! it as garbage (`stats` shows how much).  `compact` writes a new log
//! with only the live blocks and swaps it in (see the store's compaction).
//! Devices keep running: the store is held only at the start and for the
//! last records at the end.  With `--compact-pct N` (0, the default, is
//! off) the daemon compacts by itself when garbage is at least N per cent
//! of the log and at least `--compact-min-mib` (1024 by default).  One
//! compaction runs at a time.  Neither starts unless the file system has
//! room for a copy of the live blocks plus a quarter (at least 256 MiB)
//! for what arrives meanwhile; the daemon says so once and waits.  A
//! compaction stopped by `quit` or a crash leaves the old log as it was.
//!
//! # Lazy devices
//!
//! A branch is an entry in the map and costs a record in the log; a device
//! is a kernel object with threads, descriptors and kernel memory, and
//! takes milliseconds to create and remove (K2, K3, K7).  So the device is
//! separate: `branch` makes a branch only, `attach` gives it a device while
//! something mounts it, `detach` takes the device away again.  Many
//! candidate branches cost map entries; devices exist only for the ones in
//! use.  A new branch is durable at the next flush, like any map change.
//!
//! A Seal stands for every record before it, so a caller sealing a
//! mounted ext4 makes ext4 consistent first (`fsfreeze -f`, or unmount)
//! and thaws after.  The daemon does not look inside the filesystem.
//!
//! # The device
//!
//! - 4 KiB logical and physical blocks, so every request is whole blocks
//!   of the map.
//! - A **volatile write cache** and **FUA** are advertised.  Without them
//!   the kernel never sends flushes and treats every completed write as
//!   durable; with them ext4 flushes at each journal commit and the store
//!   commits a group there.  This is what makes the store's durability
//!   rule (durable at flush) the disk's.
//! - Requests of up to `--io-kib` (512 KiB by default): that is the
//!   largest request (`max_sectors_kb`) and the size of each queue's
//!   buffer.  The I/O sizes the device reports are 4 KiB, minimum and
//!   optimal alike (`minimum_io_size`, `optimal_io_size`), so mkfs.ext4
//!   sets no RAID stride or stripe width and device-mapper sees a plain
//!   4 KiB disk.  (An earlier version of this comment said mkfs.ext4 built
//!   on the 512 KiB; it does not read the maximum.)
//! - Non-rotational, which it is (no seek cost).  ext4 allocates
//!   differently on non-rotational devices; one effect: xfstests
//!   generic/347 fails on any non-rotational device, ours and loop alike
//!   (taso-test, 2026-10-19), and passes on both when marked rotational.
//! - Discard and write-zeroes both become [`Store::discard`] (reads zeros),
//!   up to 1 GiB per request.  Mount ext4 with `-o discard`: without it
//!   ext4 never says which blocks it freed, so every block it ever wrote
//!   stays live for the store, compaction cannot drop it, and Seals and
//!   exports carry it (measured on taso-test 2026-10-18: live grew to
//!   4.8 GB under fsx on a 64 MiB file).
//! - **User copy** (`UBLK_F_USER_COPY`): request data moves with `pread` /
//!   `pwrite` on the device's character file into the daemon's own buffer.
//!   No buffer is shared with the kernel.
//! - One queue and one thread per device (libublk's synchronous model),
//!   plus the thread that owns the device while it runs.  K3 measures what
//!   1000 of them cost.
//!
//! # Leftover devices
//!
//! A daemon killed without `quit` (kill -9, a crash) leaves its ublk
//! devices behind in the kernel; they would pile up and count against
//! the module's `ublks_max`.  At start, before serving, the daemon deletes
//! the ones that are its kind (libublk's record says target `taso-blk`)
//! and whose owner is no longer a running `taso-blkd`.  Devices of a live
//! daemon, and of other ublk users, are left alone.
//!
//! All devices share one store behind one lock.  Simple first; the
//! measurements say whether contention matters.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

use libublk::ctrl::{UblkCtrl, UblkCtrlBuilder};
use libublk::io::{BufDescList, UblkDev, UblkIOCtx, UblkQueue};
use libublk::{sys, BufDesc, UblkError, UblkFlags, UblkIORes};
use taso_blk::map::{Kind, LayerId, BLOCK};
use taso_blk::store::{Compacted, Store, StoreError, Syncer};

/// The ublk target name of this daemon's devices; it is how a later
/// daemon recognises leftovers as its own.
const TARGET: &str = "taso-blk";

/// Write a line to stderr, the daemon's log.  Never panics: if the log
/// cannot be written (a full disk), the line is lost and the daemon goes on.
/// `eprintln!` panics on a failed write; on taso-test (2026-10-18) that
/// panicked a device thread while it held the store, poisoned the lock, and
/// left a daemon that could not quit.
macro_rules! log {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($t)*);
    }};
}

/// The store, locked.  If a thread panicked while holding it, the store
/// is not trusted any more: it is poisoned (every call fails until the log
/// is reopened, as after a failed append) and the daemon goes on answering,
/// so `quit` still works.
fn lock_store(store: &Mutex<Store>) -> MutexGuard<'_, Store> {
    store.lock().unwrap_or_else(|p| {
        let mut s = p.into_inner();
        s.poison();
        s
    })
}

/// A plain table, locked, whether or not a thread panicked while holding
/// it (the device table stays consistent: entries are inserted or removed
/// whole).
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Largest discard or write-zeroes request the device takes: 1 GiB.
const MAX_DISCARD: u64 = 1 << 30;

/// Device geometry and queue sizes, from the command line.
#[derive(Clone, Copy)]
struct Geometry {
    size: u64,
    depth: u16,
    /// Hardware queues per device, each served by its own thread: with
    /// one, requests the kernel has in flight together (13 at a freeze,
    /// blk-trace-freeze.sh 2026-10-26) are served one after another.
    queues: u16,
    /// Serving threads per queue (the driver's `UBLK_F_PER_IO_DAEMON`,
    /// Linux 6.16+): the queue's tags are split among them, so requests
    /// the kernel has in flight together are served together; the store's
    /// mutex is then the only serialisation.
    threads: u16,
    io_bytes: u32,
    /// Log growth between automatic checkpoints, in bytes (0: none).
    checkpoint_every: u64,
    /// Compact by itself when garbage is at least this per cent of the
    /// log (0: never) ...
    compact_pct: u64,
    /// ... and at least this many bytes.
    compact_min: u64,
}

/// A running device: its ublk id and the thread that owns it.
struct Device {
    dev_id: i32,
    thread: JoinHandle<()>,
}

/// Per-operation time on the device path, for `stats`: how long a request
/// takes in `handle` altogether, and how much of that inside the store's
/// lock.  Named by lever 3 of P5 (2026-10-26): 1 MiB of write-back through
/// a branch took 37 ms with two syncs on taso-p5, and nothing in the store
/// accounts for it.
#[derive(Default, Clone, Copy)]
struct OpTime {
    count: u64,
    total_us: u64,
    store_us: u64,
    bytes: u64,
}
static OPS: Mutex<[OpTime; 4]> = Mutex::new(
    [OpTime {
        count: 0,
        total_us: 0,
        store_us: 0,
        bytes: 0,
    }; 4],
);
const OP_READ: usize = 0;
const OP_WRITE: usize = 1;
const OP_FLUSH: usize = 2;
const OP_DISCARD: usize = 3;
/// `TASO_BLKD_OPLOG=path`: one line per device request, `op bytes start_ns
/// end_ns copy_ns wait_ns store_ns` on CLOCK_MONOTONIC (blktrace's clock),
/// for the probe of where a request's time goes (blk-trace-freeze.sh).
/// Run 3 on taso-p5 (2026-10-26) put the whole write phase of a freeze in
/// our handler, 0.92 ms per 512 KiB served one after another, and four
/// threads changed nothing; the three parts name which half it is: the
/// copy between the kernel and our buffer (`copy`, outside the lock), the
/// wait for the store's lock (`wait`), the work under it (`store`).  Off
/// unless set; costs a write per request.
static OPLOG: Mutex<Option<std::io::BufWriter<File>>> = Mutex::new(None);
/// The three parts of one request, for the op log and the counters.
#[derive(Clone, Copy, Default)]
struct Split {
    copy: std::time::Duration,
    wait: std::time::Duration,
    store: std::time::Duration,
}
/// The store's lock, with the wait for it measured.
fn lock_store_timed<'a>(store: &'a Mutex<Store>, split: &mut Split) -> MutexGuard<'a, Store> {
    let t = std::time::Instant::now();
    let s = lock_store(store);
    split.wait = t.elapsed();
    s
}
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes the struct passed by reference, nothing else.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}
fn note_op(op: usize, started: std::time::Instant, split: Split, bytes: u64) {
    if let Some(w) = lock(&OPLOG).as_mut() {
        use std::io::Write;
        let end = monotonic_ns();
        let start = end - started.elapsed().as_nanos() as u64;
        let _ = writeln!(
            w,
            "{} {bytes} {start} {end} {} {} {}",
            ["read", "write", "flush", "discard"][op],
            split.copy.as_nanos(),
            split.wait.as_nanos(),
            split.store.as_nanos()
        );
        let _ = w.flush();
    }
    let mut ops = lock(&OPS);
    let o = &mut ops[op];
    o.count += 1;
    o.total_us += started.elapsed().as_micros() as u64;
    o.store_us += split.store.as_micros() as u64;
    o.bytes += bytes;
}

struct Daemon {
    store: Arc<Mutex<Store>>,
    /// The log's fdatasync, outside the store's lock, one for every group
    /// ended while the last one ran (Seals, device flushes, FUA writes).
    sync: Arc<Syncer>,
    devices: Mutex<HashMap<LayerId, Device>>,
    geometry: Geometry,
    /// A compaction is running.
    compacting: AtomicBool,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: taso-blkd LOG SOCKET [--size-gib N] [--depth N] [--queues N] [--io-kib N] [--checkpoint-mib N] [--compact-pct N] [--compact-min-mib N]";
    if args.len() < 3 {
        log!("{usage}");
        std::process::exit(64);
    }
    let (log, socket) = (PathBuf::from(&args[1]), PathBuf::from(&args[2]));
    let mut g = Geometry {
        size: 4 << 30,
        depth: 32,
        queues: 1,
        threads: 1,
        // 512 KiB: the geometry of common disks; on taso-test it measured
        // the same as 128 KiB (blk-bench, 2026-10-19, within run noise).
        io_bytes: 512 << 10,
        checkpoint_every: 256 << 20,
        compact_pct: 0,
        compact_min: 1 << 30,
    };
    let mut rest = args[3..].iter();
    while let Some(flag) = rest.next() {
        let value = rest.next().and_then(|v| v.parse::<u64>().ok());
        match (flag.as_str(), value) {
            ("--size-gib", Some(v)) if v > 0 => g.size = v << 30,
            ("--depth", Some(v)) if (1..=4096).contains(&v) => g.depth = v as u16,
            ("--queues", Some(v)) if (1..=64).contains(&v) => g.queues = v as u16,
            ("--threads", Some(v)) if (1..=64).contains(&v) => g.threads = v as u16,
            ("--io-kib", Some(v)) if v >= 4 && v % 4 == 0 && v <= 16384 => {
                g.io_bytes = (v as u32) << 10
            }
            ("--checkpoint-mib", Some(v)) if v <= 1 << 20 => g.checkpoint_every = v << 20,
            ("--compact-pct", Some(v)) if v <= 99 => g.compact_pct = v,
            ("--compact-min-mib", Some(v)) if v <= 1 << 24 => g.compact_min = v << 20,
            _ => {
                log!("bad argument {flag}\n{usage}");
                std::process::exit(64);
            }
        }
    }

    let store = if log.exists() {
        match Store::open(&log) {
            Ok((s, rec)) => {
                log!(
                    "taso-blkd: recovered {}: {} records, {} groups, {} bytes cut ({})",
                    log.display(),
                    rec.records,
                    rec.groups,
                    rec.cut,
                    match rec.checkpoint {
                        Some(lsn) => format!("from the checkpoint at record {lsn}"),
                        None => "full replay".to_string(),
                    }
                );
                s
            }
            Err(e) => fail(&format!("cannot open {}: {e}", log.display())),
        }
    } else {
        Store::create(&log)
            .unwrap_or_else(|e| fail(&format!("cannot create {}: {e}", log.display())))
    };

    let (removed, failed) = reap_dead_devices();
    if removed + failed > 0 {
        log!("taso-blkd: removed {removed} leftover devices of dead daemons ({failed} could not be removed)");
    }

    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)
        .unwrap_or_else(|e| fail(&format!("cannot bind {}: {e}", socket.display())));
    log!(
        "taso-blkd: serving {} on {} (open-file limit {})",
        log.display(),
        socket.display(),
        raise_open_files()
    );

    let sync = Arc::new(
        store
            .syncer()
            .unwrap_or_else(|e| fail(&format!("cannot clone the log's descriptor: {e}"))),
    );
    if let Ok(path) = std::env::var("TASO_BLKD_OPLOG") {
        match File::create(&path) {
            Ok(f) => *lock(&OPLOG) = Some(std::io::BufWriter::new(f)),
            Err(e) => fail(&format!("cannot create {path}: {e}")),
        }
    }
    let daemon = Arc::new(Daemon {
        store: Arc::new(Mutex::new(store)),
        sync,
        devices: Mutex::new(HashMap::new()),
        geometry: g,
        compacting: AtomicBool::new(false),
    });
    if g.checkpoint_every > 0 || g.compact_pct > 0 {
        let d = daemon.clone();
        std::thread::Builder::new()
            .name("upkeep".into())
            .spawn(move || upkeep(&d))
            .unwrap_or_else(|e| fail(&format!("cannot start the upkeep thread: {e}")));
    }
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let d = daemon.clone();
        let socket = socket.clone();
        std::thread::spawn(move || {
            if serve(&d, conn) {
                d.stop_all();
                // A clean shutdown loses nothing: end the last group, and
                // leave a checkpoint so the next start is quick.
                if let Err(e) = lock_store(&d.store).checkpoint() {
                    log!("taso-blkd: final checkpoint: {e}");
                }
                let _ = std::fs::remove_file(&socket);
                log!("taso-blkd: quit");
                std::process::exit(0);
            }
        });
    }
}

/// Raise the open-file soft limit to the hard limit and return the soft
/// limit in force.  Each live device holds about two descriptors (its
/// character device and its io_uring); the usual soft limit of 1024 stopped
/// K3 near 475 devices.
fn raise_open_files() -> u64 {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit and setrlimit only read and write the struct passed
    // by reference, which lives for the whole call.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return 0;
        }
        if lim.rlim_cur < lim.rlim_max {
            let want = libc::rlimit {
                rlim_cur: lim.rlim_max,
                rlim_max: lim.rlim_max,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &want) == 0 {
                lim = want;
            }
        }
    }
    lim.rlim_cur
}

/// Write a checkpoint whenever the log has grown by `--checkpoint-mib`
/// since the last one, and compact when garbage passes `--compact-pct`.
/// Runs for the daemon's life.
fn upkeep(d: &Daemon) {
    let g = d.geometry;
    let mut last = lock_store(&d.store).stats().log_bytes;
    // Said once until there is room again, not every 5 s.
    let mut short_of_room = false;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let stats = lock_store(&d.store).stats();
        let due = g.compact_pct > 0
            && stats.garbage_bytes >= g.compact_min
            && stats.garbage_bytes * 100 >= stats.log_bytes * g.compact_pct;
        // While another compaction (the `compact` command) runs, nothing
        // to do this round.
        if due && !d.compacting.load(Ordering::SeqCst) {
            match d.room_to_compact() {
                Err(why) => {
                    if !short_of_room {
                        log!("taso-blkd: compaction waits: {why}");
                        short_of_room = true;
                    }
                }
                Ok(()) => {
                    short_of_room = false;
                    log!(
                        "taso-blkd: compacting: {} MiB of garbage in {} MiB of log",
                        stats.garbage_bytes >> 20,
                        stats.log_bytes >> 20
                    );
                    match d.compact() {
                        Ok(c) => log!("taso-blkd: compacted: {}", compacted(&c)),
                        Err(e) if e == BUSY => {}
                        Err(e) => {
                            log!("taso-blkd: compaction: {e}");
                            // Not again at once: what failed would likely
                            // fail the same way.
                            std::thread::sleep(std::time::Duration::from_secs(60));
                        }
                    }
                    // A compaction leaves a checkpoint of the new log.
                    last = lock_store(&d.store).stats().log_bytes;
                    continue;
                }
            }
        }
        if g.checkpoint_every > 0 && stats.log_bytes.saturating_sub(last) >= g.checkpoint_every {
            let mut s = lock_store(&d.store);
            match s.checkpoint() {
                Ok(lsn) => {
                    last = s.stats().log_bytes;
                    log!(
                        "taso-blkd: checkpoint at record {lsn} ({} MiB of log)",
                        last >> 20
                    );
                }
                Err(e) => log!("taso-blkd: checkpoint: {e}"),
            }
        }
    }
}

/// What `compact` answers while a compaction is running.
const BUSY: &str = "a compaction is already running";

/// Bytes free for an unprivileged writer on the file system holding `dir`.
fn free_bytes(dir: &std::path::Path) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
    // SAFETY: `c` is a valid NUL-terminated path for the whole call, and
    // statvfs only writes the struct passed by reference.
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut st) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(st.f_bavail as u64 * st.f_frsize as u64)
    }
}

/// `before=… after=… live=… records=…` (bytes, bytes, bytes, count).
fn compacted(c: &Compacted) -> String {
    format!(
        "before={} after={} live={} records={}{}",
        c.before,
        c.after,
        c.live,
        c.records,
        if c.checkpoint {
            ""
        } else {
            " checkpoint=missing"
        }
    )
}

/// An absolute file path argument.
fn file_arg(w: Option<&&str>) -> Result<PathBuf, String> {
    let p = PathBuf::from(w.ok_or("missing file path")?);
    if !p.is_absolute() {
        return Err(format!("{} is not an absolute path", p.display()));
    }
    Ok(p)
}

/// Lowercase hex of `b`.
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Bytes from lowercase or uppercase hex.
fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("bad hex {s:?}: odd length"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(s.get(i..i + 2).unwrap_or("x"), 16)
                .map_err(|_| format!("bad hex {s:?}"))
        })
        .collect()
}

fn fail(msg: &str) -> ! {
    log!("taso-blkd: {msg}");
    std::process::exit(1);
}

/// Serve one control connection.  `true` if it asked the daemon to quit.
fn serve(d: &Daemon, conn: UnixStream) -> bool {
    let Ok(mut out) = conn.try_clone() else {
        return false;
    };
    for line in BufReader::new(conn).lines() {
        let Ok(line) = line else { return false };
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.is_empty() {
            continue;
        }
        let quit = words[0] == "quit";
        let answer = match d.command(&words) {
            Ok(a) if a.is_empty() => "ok".to_string(),
            Ok(a) => format!("ok {a}"),
            Err(e) => format!("err {e}"),
        };
        if writeln!(out, "{answer}").is_err() || quit {
            return quit;
        }
    }
    false
}

impl Daemon {
    fn command(&self, words: &[&str]) -> Result<String, String> {
        let layer = |i: usize| -> Result<LayerId, String> {
            let w = words.get(i).ok_or("missing layer id")?;
            let n: u64 = w
                .trim_start_matches('L')
                .parse()
                .map_err(|_| format!("bad layer id {w}"))?;
            self.find(n).ok_or_else(|| format!("no layer L{n}"))
        };
        let store_err = |e: taso_blk::store::StoreError| e.to_string();
        match words[0] {
            "root" => Ok(self
                .store
                .lock()
                .unwrap()
                .root_seal()
                .map_err(store_err)?
                .to_string()),
            "branch" => {
                let seal = layer(1)?;
                Ok(self.branch(seal, words.get(2).copied())?.to_string())
            }
            "fork" => {
                let seal = layer(1)?;
                let branch = self.branch(seal, words.get(2).copied())?;
                let dev = self.attach(branch)?;
                Ok(format!("{branch} {dev}"))
            }
            "name" => {
                let branch = layer(1)?;
                let name = words.get(2).copied().unwrap_or("");
                self.store
                    .lock()
                    .unwrap()
                    .name(branch, name)
                    .map_err(store_err)?;
                Ok(String::new())
            }
            "find" => {
                let name = words.get(1).ok_or("missing name")?;
                let found = lock_store(&self.store).find(name);
                found
                    .map(|b| b.to_string())
                    .ok_or_else(|| format!("no branch named {name}"))
            }
            "seals" => {
                let branch = layer(1)?;
                let s = lock_store(&self.store);
                let list: Vec<String> = s
                    .seals_of(branch)
                    .into_iter()
                    .map(|l| format!("{l}:{}", hex(s.tag(l).unwrap_or(&[]))))
                    .collect();
                Ok(list.join(" "))
            }
            "info" => {
                let l = layer(1)?;
                Ok(self.info(l)?)
            }
            "attach" => {
                let branch = layer(1)?;
                self.attach(branch)
            }
            "seal" => {
                // Resolve the id before taking the lock: `find` locks too,
                // and the store's mutex is not re-entrant.
                let branch = layer(1)?;
                let tag = unhex(words.get(2).copied().unwrap_or(""))?;
                let (seal, lsn) = lock_store(&self.store)
                    .seal_pending(branch, &tag)
                    .map_err(store_err)?;
                self.durable(lsn)?;
                Ok(seal.to_string())
            }
            "reset" => {
                let branch = layer(1)?;
                // Hold the device table so no attach can start in between;
                // the table is always taken before the store, never after.
                let devices = lock(&self.devices);
                if devices.contains_key(&branch) {
                    return Err(format!("{branch} is attached; unmount and detach it first"));
                }
                let discarded = self
                    .store
                    .lock()
                    .unwrap()
                    .reset(branch)
                    .map_err(store_err)?;
                drop(devices);
                Ok(discarded.to_string())
            }
            "export" => {
                let to = layer(1)?;
                let from = match words.get(2) {
                    Some(&"-") => None,
                    Some(_) => Some(layer(2)?),
                    None => return Err("missing base (a Seal or -)".into()),
                };
                let path = file_arg(words.get(3))?;
                // A new file only, never over an existing one.
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
                let mut w = std::io::BufWriter::new(file);
                let result = self
                    .store
                    .lock()
                    .unwrap()
                    .export(to, from, &mut w)
                    .map_err(store_err);
                let result = result.and_then(|n| {
                    let f = w.into_inner().map_err(|e| e.to_string())?;
                    f.sync_all().map_err(|e| e.to_string())?;
                    Ok(n)
                });
                if result.is_err() {
                    let _ = std::fs::remove_file(&path);
                }
                Ok(result?.to_string())
            }
            "import" => {
                let branch = layer(1)?;
                let path = file_arg(words.get(2))?;
                let file = File::open(&path)
                    .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
                let mut r = std::io::BufReader::with_capacity(1 << 20, file);
                // As for reset: the device table first, so no attach starts.
                let devices = lock(&self.devices);
                if devices.contains_key(&branch) {
                    return Err(format!("{branch} is attached; unmount and detach it first"));
                }
                let n = self
                    .store
                    .lock()
                    .unwrap()
                    .import(branch, &mut r)
                    .map_err(store_err)?;
                drop(devices);
                Ok(n.to_string())
            }
            "checkpoint" => Ok(self
                .store
                .lock()
                .unwrap()
                .checkpoint()
                .map_err(store_err)?
                .to_string()),
            "compact" => {
                self.room_to_compact()?;
                Ok(compacted(&self.compact()?))
            }
            "names" => {
                let names = lock_store(&self.store).names();
                Ok(names
                    .into_iter()
                    .map(|(n, b)| format!("{n}:{b}"))
                    .collect::<Vec<_>>()
                    .join(" "))
            }
            "detach" => {
                self.detach(layer(1)?)?;
                Ok(String::new())
            }
            "drop" => {
                let l = layer(1)?;
                let kind = self
                    .store
                    .lock()
                    .unwrap()
                    .map()
                    .kind(l)
                    .map_err(|e| e.to_string())?;
                if kind == Kind::Branch {
                    let _ = self.detach(l);
                    self.store
                        .lock()
                        .unwrap()
                        .drop_branch(l)
                        .map_err(store_err)?;
                } else {
                    lock_store(&self.store).drop_seal(l).map_err(store_err)?;
                }
                Ok(String::new())
            }
            "flush" => {
                let lsn = lock_store(&self.store).flush_pending().map_err(store_err)?;
                self.durable(lsn)?;
                Ok(lsn.to_string())
            }
            "stats" => Ok(self.stats()),
            "quit" => Ok(String::new()),
            other => Err(format!("unknown command {other}")),
        }
    }

    /// A new branch on `seal`, named `name` if given.  The name is checked
    /// first and the store lock is held throughout, so a bad or taken name
    /// makes no branch and appends nothing.
    fn branch(&self, seal: LayerId, name: Option<&str>) -> Result<LayerId, String> {
        let mut s = lock_store(&self.store);
        if let Some(n) = name {
            s.check_name(n).map_err(|e| e.to_string())?;
        }
        let branch = s.fork(seal).map_err(|e| e.to_string())?;
        if let Some(n) = name {
            // Checked above under the same lock; only an I/O error is left.
            s.name(branch, n).map_err(|e| e.to_string())?;
        }
        Ok(branch)
    }

    /// `kind=… parent=… name=… tag=… origin=… dev=…` for a live layer.
    fn info(&self, l: LayerId) -> Result<String, String> {
        // The device table first, then the store: never both at once.
        let dev = self
            .devices
            .lock()
            .unwrap()
            .get(&l)
            .map(|d| format!("/dev/ublkb{}", d.dev_id));
        let s = lock_store(&self.store);
        let kind = s.map().kind(l).map_err(|e| e.to_string())?;
        let parent = s.map().parent(l).map_err(|e| e.to_string())?;
        let or_dash = |o: Option<String>| o.unwrap_or_else(|| "-".to_string());
        Ok(format!(
            "kind={} parent={} name={} tag={} origin={} dev={}",
            if kind == Kind::Branch {
                "branch"
            } else {
                "seal"
            },
            or_dash(parent.map(|p| p.to_string())),
            or_dash(s.name_of(l).map(str::to_string)),
            or_dash(s.tag(l).map(hex)),
            or_dash(s.origin(l).map(|o| o.to_string())),
            or_dash(dev),
        ))
    }

    /// Whether the log's file system has room for a compaction: a copy
    /// of the live blocks while the old log still stands, plus room for
    /// what arrives meanwhile (a quarter of the live size, at least 256
    /// MiB).  `Err` says how much is wanted and how much there is.
    fn room_to_compact(&self) -> Result<(), String> {
        let (live, path) = {
            let s = lock_store(&self.store);
            let st = s.stats();
            (
                st.log_bytes.saturating_sub(st.garbage_bytes),
                s.path().to_path_buf(),
            )
        };
        let want = live + (live / 4).max(256 << 20);
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        let free = free_bytes(dir).map_err(|e| format!("cannot read free space: {e}"))?;
        if free < want {
            return Err(format!(
                "not enough room: wants {} MiB free, has {} MiB",
                want >> 20,
                free >> 20
            ));
        }
        Ok(())
    }

    /// Compact the log, holding the store only to begin and to finish.
    fn compact(&self) -> Result<Compacted, String> {
        if self.compacting.swap(true, Ordering::SeqCst) {
            return Err(BUSY.to_string());
        }
        struct Done<'a>(&'a AtomicBool);
        impl Drop for Done<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _done = Done(&self.compacting);
        let e = |e: taso_blk::store::StoreError| e.to_string();
        let mut c = lock_store(&self.store).compaction().map_err(e)?;
        c.copy().map_err(e)?;
        // Catch up until a round finds little, so what finish copies with
        // the store held is short.
        for _ in 0..16 {
            if c.catch_up().map_err(e)? < 256 {
                break;
            }
        }
        let done = c.finish(&mut lock_store(&self.store)).map_err(e)?;
        // The store is let go of here; the caller drops `done.old_log`,
        // whose close frees the old file's space and may take a while.
        Ok(done)
    }

    /// The live layer with id number `n`, if any.
    fn find(&self, n: u64) -> Option<LayerId> {
        lock_store(&self.store).map().live(n)
    }

    /// Start a device for `branch`.  Returns its block device path.
    fn attach(&self, branch: LayerId) -> Result<String, String> {
        if self
            .store
            .lock()
            .unwrap()
            .map()
            .kind(branch)
            .map_err(|e| e.to_string())?
            != Kind::Branch
        {
            return Err(format!("{branch} is a Seal; attach a branch"));
        }
        let mut devices = lock(&self.devices);
        if let Some(d) = devices.get(&branch) {
            return Err(format!(
                "{branch} is already attached as /dev/ublkb{}",
                d.dev_id
            ));
        }
        let (tx, rx) = mpsc::channel();
        let store = self.store.clone();
        let sync = self.sync.clone();
        let g = self.geometry;
        let thread = std::thread::Builder::new()
            .name(format!("dev-{branch}"))
            .spawn(move || run_device(store, sync, branch, g, tx))
            .map_err(|e| format!("cannot start device thread: {e}"))?;
        match rx.recv() {
            Ok(Ok(dev_id)) => {
                devices.insert(branch, Device { dev_id, thread });
                Ok(format!("/dev/ublkb{dev_id}"))
            }
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(format!("device for {branch} did not start: {e}"))
            }
            Err(_) => {
                let _ = thread.join();
                Err(format!("device for {branch} did not start"))
            }
        }
    }

    /// Stop `branch`'s device and wait for its thread.
    fn detach(&self, branch: LayerId) -> Result<(), String> {
        let d = self
            .devices
            .lock()
            .unwrap()
            .remove(&branch)
            .ok_or_else(|| format!("{branch} is not attached"))?;
        UblkCtrl::new_simple(d.dev_id)
            .and_then(|c| c.kill_dev())
            .map_err(|e| format!("cannot stop /dev/ublkb{}: {e:?}", d.dev_id))?;
        let _ = d.thread.join();
        Ok(())
    }

    fn stop_all(&self) {
        let branches: Vec<LayerId> = lock(&self.devices).keys().copied().collect();
        for b in branches {
            if let Err(e) = self.detach(b) {
                log!("taso-blkd: {e}");
            }
        }
    }

    /// Everything up to `lsn` on the medium (group commit); a failed sync
    /// poisons the store, as a failed sync under the lock did.
    fn durable(&self, lsn: u64) -> Result<(), String> {
        durable(&self.sync, &self.store, lsn).map_err(|e| e.to_string())
    }

    fn stats(&self) -> String {
        // Never hold the store lock while waiting for the device table:
        // `attach` holds the table while a new device starts, and the
        // kernel's first reads of that device need the store.
        let devices = lock(&self.devices).len();
        let s = lock_store(&self.store);
        let st = s.stats();
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let field = |k: &str| {
            status
                .lines()
                .find(|l| l.starts_with(k))
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("?")
                .to_string()
        };
        let ops = *lock(&OPS);
        let op = |name: &str, o: OpTime| {
            format!(
                " {name}={}:{}:{}:{}",
                o.count, o.total_us, o.store_us, o.bytes
            )
        };
        // op_wsplit: where the writes' time under the lock went, µs summed
        // over every write: map, copy, hash, pwrite (store.rs Stats).
        format!(
            "log_bytes={} garbage_bytes={} records={} syncs={} lsn={} layers={} devices={} threads={} rss_kib={}{}{}{}{} op_wsplit={}:{}:{}:{}",
            st.log_bytes,
            st.garbage_bytes,
            st.records,
            st.syncs + self.sync.syncs(),
            s.lsn(),
            s.map().layers(),
            devices,
            field("Threads:"),
            field("VmRSS:"),
            op("op_read", ops[OP_READ]),
            op("op_write", ops[OP_WRITE]),
            op("op_flush", ops[OP_FLUSH]),
            op("op_discard", ops[OP_DISCARD]),
            st.write_map_us,
            st.write_copy_us,
            st.write_hash_us,
            st.write_pwrite_us,
        )
    }
}

/// Delete ublk devices left behind by a `taso-blkd` that died without
/// stopping them.  Ours: libublk's json for the device names target
/// [`TARGET`].  Dead: the process that added it is not a running
/// `taso-blkd` (the kernel keeps the adder's pid in the device info from
/// the moment the device is added, so a live daemon's half-started device
/// is never taken).  Uses the asynchronous delete, which does not wait for
/// the last opener: a leftover still mounted somewhere cannot hang the
/// start.  Returns (removed, failed).
fn reap_dead_devices() -> (usize, usize) {
    let Ok(entries) = std::fs::read_dir("/sys/class/ublk-char") else {
        return (0, 0);
    };
    let mut ids: Vec<i32> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.strip_prefix("ublkc")?.parse().ok())
        .collect();
    ids.sort_unstable();
    let (mut removed, mut failed) = (0, 0);
    for id in ids {
        let Ok(ctrl) = UblkCtrl::new_simple(id) else {
            continue;
        };
        if ctrl.get_target_type_from_json().ok().as_deref() != Some(TARGET) {
            continue;
        }
        if is_taso_blkd(ctrl.dev_info().ublksrv_pid) {
            continue;
        }
        match ctrl.del_dev_async() {
            Ok(_) => removed += 1,
            Err(e) => {
                log!("taso-blkd: cannot remove leftover device {id}: {e:?}");
                failed += 1;
            }
        }
    }
    (removed, failed)
}

/// Whether `pid` is a running `taso-blkd`.
fn is_taso_blkd(pid: i32) -> bool {
    pid > 0
        && std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .is_ok_and(|c| c.trim_end() == "taso-blkd")
}

/// Own one ublk device for `branch` until it is stopped.  Sends the device
/// id (or why it failed) on `ready` once the device is live.
fn run_device(
    store: Arc<Mutex<Store>>,
    sync: Arc<Syncer>,
    branch: LayerId,
    g: Geometry,
    ready: mpsc::Sender<Result<i32, String>>,
) {
    let ctrl = match UblkCtrlBuilder::default()
        .name(TARGET)
        .id(-1)
        .nr_queues(g.queues)
        .depth(g.depth)
        .io_threads_per_queue(g.threads)
        .io_buf_bytes(g.io_bytes)
        // Threads per queue need the driver's UBLK_F_PER_IO_DAEMON, which
        // the driver advertises on the device itself (Linux 6.16+); it is
        // not a flag to pass (libublk refuses it: InvalidVal, 2026-10-26).
        .ctrl_flags(sys::UBLK_F_USER_COPY as u64)
        .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = ready.send(Err(format!("{e:?}")));
            return;
        }
    };
    let init = |dev: &mut UblkDev| -> Result<(), UblkError> {
        dev.tgt.dev_size = g.size;
        dev.tgt.params = sys::ublk_params {
            types: sys::UBLK_PARAM_TYPE_BASIC | sys::UBLK_PARAM_TYPE_DISCARD,
            basic: sys::ublk_param_basic {
                attrs: sys::UBLK_ATTR_VOLATILE_CACHE | sys::UBLK_ATTR_FUA,
                logical_bs_shift: 12,
                physical_bs_shift: 12,
                io_opt_shift: 12,
                io_min_shift: 12,
                max_sectors: g.io_bytes >> 9,
                dev_sectors: g.size >> 9,
                ..Default::default()
            },
            discard: sys::ublk_param_discard {
                discard_granularity: BLOCK as u32,
                // A discard costs a map change and one small record, not
                // I/O, so take large ones whole: freeing a big file is one
                // record instead of thousands (ext4 mounted -o discard).
                max_discard_sectors: (MAX_DISCARD >> 9) as u32,
                max_write_zeroes_sectors: (MAX_DISCARD >> 9) as u32,
                max_discard_segments: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        Ok(())
    };
    let q_store = store.clone();
    let q_sync = sync.clone();
    let queue = move |qid: u16, dev: &UblkDev| serve_queue(qid, dev, &q_store, &q_sync, branch);
    let started = ready.clone();
    let on_start = move |c: &UblkCtrl| {
        let _ = started.send(Ok(c.dev_info().dev_id as i32));
    };
    if let Err(e) = ctrl.run_target(init, queue, on_start) {
        let _ = ready.send(Err(format!("{e:?}")));
    }
    let _ = ctrl.del_dev();
}

/// Serve one queue: every request becomes one store call.
fn serve_queue(qid: u16, dev: &UblkDev, store: &Mutex<Store>, sync: &Syncer, branch: LayerId) {
    // SAFETY: fds[0] is the device's character file, opened by UblkDev and
    // kept open for the device's whole life, which outlasts this queue.
    // The kernel allows that file to be opened only once, so it is
    // borrowed, never closed here (ManuallyDrop).
    let cdev = ManuallyDrop::new(unsafe { File::from_raw_fd(dev.tgt.fds[0]) });
    let mut buf = vec![0u8; dev.dev_info.max_io_buf_bytes as usize];
    let handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
        let res = handle(q, tag, qid, &cdev, &mut buf, store, sync, branch);
        if let Err(e) =
            q.complete_io_cmd_unified(tag, BufDesc::Slice(&[]), Ok(UblkIORes::Result(res)))
        {
            log!("taso-blkd: {branch}: complete tag {tag}: {e:?}");
        }
    };
    match UblkQueue::new(qid, dev)
        .and_then(|q| q.submit_fetch_commands_unified(BufDescList::Slices(None)))
    {
        Ok(q) => q.wait_and_handle_io(handler),
        Err(e) => log!("taso-blkd: {branch}: queue {qid}: {e:?}"),
    }
}

/// One request.  Returns bytes moved, 0, or a negative errno.
/// Group commit for `lsn`; a failed sync poisons the store, as a failed
/// sync under the lock did, so every later call fails the same way.
fn durable(sync: &Syncer, store: &Mutex<Store>, lsn: u64) -> Result<(), StoreError> {
    match sync.durable(lsn) {
        Ok(_) => Ok(()),
        Err(e) => {
            lock_store(store).poison();
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)] // the queue's context, the store and its syncer
fn handle(
    q: &UblkQueue,
    tag: u16,
    qid: u16,
    cdev: &File,
    buf: &mut [u8],
    store: &Mutex<Store>,
    sync: &Syncer,
    branch: LayerId,
) -> i32 {
    let iod = q.get_iod(tag);
    let op = iod.op_flags & 0xff;
    let off = iod.start_sector << 9;
    let bytes = (iod.nr_sectors as u64) << 9;
    if op != sys::UBLK_IO_OP_FLUSH
        && (!off.is_multiple_of(BLOCK) || !bytes.is_multiple_of(BLOCK) || bytes == 0)
    {
        return -libc::EINVAL;
    }
    let (lba, n) = (off / BLOCK, bytes as usize);
    let pos = UblkIOCtx::ublk_user_copy_pos(qid, tag, 0);
    let started = std::time::Instant::now();
    let io = |e: &dyn std::fmt::Display| {
        log!("taso-blkd: {branch}: op {op} at block {lba}: {e}");
        -libc::EIO
    };
    match op {
        sys::UBLK_IO_OP_READ => {
            if n > buf.len() {
                return -libc::EINVAL;
            }
            // Bound first: the lock is let go of before any logging.
            let mut split = Split::default();
            let r = {
                let s = lock_store_timed(store, &mut split);
                let t = std::time::Instant::now();
                let r = s.read(branch, lba, &mut buf[..n]);
                split.store = t.elapsed();
                r
            };
            if let Err(e) = r {
                return io(&e);
            }
            let t = std::time::Instant::now();
            let res = match cdev.write_all_at(&buf[..n], pos) {
                Ok(()) => n as i32,
                Err(e) => io(&e),
            };
            split.copy = t.elapsed();
            note_op(OP_READ, started, split, bytes);
            res
        }
        sys::UBLK_IO_OP_WRITE => {
            if n > buf.len() {
                return -libc::EINVAL;
            }
            let mut split = Split::default();
            let t = std::time::Instant::now();
            if let Err(e) = cdev.read_exact_at(&mut buf[..n], pos) {
                return io(&e);
            }
            split.copy = t.elapsed();
            // FUA: the write's group ended under the lock, synced outside it.
            let fua = iod.op_flags & sys::UBLK_IO_F_FUA != 0;
            let r = {
                let mut s = lock_store_timed(store, &mut split);
                let t = std::time::Instant::now();
                let r = s.write(branch, lba, &buf[..n], false).and_then(|()| {
                    if fua {
                        s.flush_pending().map(Some)
                    } else {
                        Ok(None)
                    }
                });
                split.store = t.elapsed();
                r
            };
            let res = match r {
                Ok(None) => n as i32,
                Ok(Some(lsn)) => match durable(sync, store, lsn) {
                    Ok(()) => n as i32,
                    Err(e) => io(&e),
                },
                Err(e) => io(&e),
            };
            note_op(OP_WRITE, started, split, bytes);
            res
        }
        sys::UBLK_IO_OP_FLUSH => {
            let mut split = Split::default();
            let r = {
                let mut s = lock_store_timed(store, &mut split);
                let t = std::time::Instant::now();
                let r = s.flush_pending();
                split.store = t.elapsed();
                r
            };
            let res = match r.and_then(|lsn| durable(sync, store, lsn)) {
                Ok(()) => 0,
                Err(e) => io(&e),
            };
            note_op(OP_FLUSH, started, split, 0);
            res
        }
        sys::UBLK_IO_OP_DISCARD | sys::UBLK_IO_OP_WRITE_ZEROES => {
            let mut split = Split::default();
            let r = {
                let mut s = lock_store_timed(store, &mut split);
                let t = std::time::Instant::now();
                let r = s.discard(branch, lba, bytes / BLOCK);
                split.store = t.elapsed();
                r
            };
            let res = match r {
                Ok(()) => 0,
                Err(e) => io(&e),
            };
            note_op(OP_DISCARD, started, split, bytes);
            res
        }
        _ => -libc::EOPNOTSUPP,
    }
}
