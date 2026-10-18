//! `taso-blkd`: the block log spike's daemon (spike file 3).
//!
//! Serves branches of one [`Store`] as Linux block devices over ublk, so
//! ext4 can sit on top.  One device per attached branch; one log for all.
//!
//! ```text
//!   taso-blkd LOG SOCKET [--size-gib N] [--depth N] [--io-kib N]
//! ```
//!
//! Opens LOG (creating it if missing; recovery runs and is reported), then
//! takes commands on the Unix socket SOCKET, one per line, one answer line
//! each, starting `ok` or `err`:
//!
//! | command          | does                                             | answer               |
//! |------------------|--------------------------------------------------|----------------------|
//! | `root`           | a Template's first Seal (empty, zeros)           | `ok <seal>`          |
//! | `branch <seal>`  | a branch on the Seal, no device (lazy)           | `ok <branch>`        |
//! | `fork <seal>`    | `branch`, then `attach`                          | `ok <branch> <dev>`  |
//! | `attach <branch>`| a device for a branch (before mounting it)       | `ok <dev>`           |
//! | `seal <branch>`  | freeze the branch as a Seal; device stays up     | `ok <seal>`          |
//! | `detach <branch>`| stop the branch's device                         | `ok`                 |
//! | `drop <layer>`   | detach if needed, drop the branch or Seal        | `ok`                 |
//! | `flush`          | end a group                                      | `ok <lsn>`           |
//! | `stats`          | counters, for measurements                       | `ok key=value ...`   |
//! | `quit`           | stop every device, flush, then exit              | `ok`                 |
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
//! - Discard and write-zeroes both become [`Store::discard`] (reads zeros).
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
use std::os::unix::fs::FileExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;

use libublk::ctrl::{UblkCtrl, UblkCtrlBuilder};
use libublk::io::{BufDescList, UblkDev, UblkIOCtx, UblkQueue};
use libublk::{sys, BufDesc, UblkError, UblkFlags, UblkIORes};
use taso_blk::map::{Kind, LayerId, BLOCK};
use taso_blk::store::Store;

/// The ublk target name of this daemon's devices; it is how a later
/// daemon recognises leftovers as its own.
const TARGET: &str = "taso-blk";

/// Device geometry and queue sizes, from the command line.
#[derive(Clone, Copy)]
struct Geometry {
    size: u64,
    depth: u16,
    io_bytes: u32,
}

/// A running device: its ublk id and the thread that owns it.
struct Device {
    dev_id: i32,
    thread: JoinHandle<()>,
}

struct Daemon {
    store: Arc<Mutex<Store>>,
    devices: Mutex<HashMap<LayerId, Device>>,
    geometry: Geometry,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: taso-blkd LOG SOCKET [--size-gib N] [--depth N] [--io-kib N]";
    if args.len() < 3 {
        eprintln!("{usage}");
        std::process::exit(64);
    }
    let (log, socket) = (PathBuf::from(&args[1]), PathBuf::from(&args[2]));
    let mut g = Geometry { size: 4 << 30, depth: 32, io_bytes: 128 << 10 };
    let mut rest = args[3..].iter();
    while let Some(flag) = rest.next() {
        let value = rest.next().and_then(|v| v.parse::<u64>().ok());
        match (flag.as_str(), value) {
            ("--size-gib", Some(v)) if v > 0 => g.size = v << 30,
            ("--depth", Some(v)) if (1..=4096).contains(&v) => g.depth = v as u16,
            ("--io-kib", Some(v)) if v >= 4 && v % 4 == 0 && v <= 16384 => g.io_bytes = (v as u32) << 10,
            _ => {
                eprintln!("bad argument {flag}\n{usage}");
                std::process::exit(64);
            }
        }
    }

    let store = if log.exists() {
        match Store::open(&log) {
            Ok((s, rec)) => {
                eprintln!(
                    "taso-blkd: recovered {}: {} records, {} groups, {} bytes cut",
                    log.display(),
                    rec.records,
                    rec.groups,
                    rec.cut
                );
                s
            }
            Err(e) => fail(&format!("cannot open {}: {e}", log.display())),
        }
    } else {
        Store::create(&log).unwrap_or_else(|e| fail(&format!("cannot create {}: {e}", log.display())))
    };

    let (removed, failed) = reap_dead_devices();
    if removed + failed > 0 {
        eprintln!("taso-blkd: removed {removed} leftover devices of dead daemons ({failed} could not be removed)");
    }

    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).unwrap_or_else(|e| fail(&format!("cannot bind {}: {e}", socket.display())));
    eprintln!(
        "taso-blkd: serving {} on {} (open-file limit {})",
        log.display(),
        socket.display(),
        raise_open_files()
    );

    let daemon = Arc::new(Daemon { store: Arc::new(Mutex::new(store)), devices: Mutex::new(HashMap::new()), geometry: g });
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let d = daemon.clone();
        let socket = socket.clone();
        std::thread::spawn(move || {
            if serve(&d, conn) {
                d.stop_all();
                // A clean shutdown loses nothing: end the last group.
                if let Err(e) = d.store.lock().unwrap().flush() {
                    eprintln!("taso-blkd: final flush: {e}");
                }
                let _ = std::fs::remove_file(&socket);
                eprintln!("taso-blkd: quit");
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
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit and setrlimit only read and write the struct passed
    // by reference, which lives for the whole call.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return 0;
        }
        if lim.rlim_cur < lim.rlim_max {
            let want = libc::rlimit { rlim_cur: lim.rlim_max, rlim_max: lim.rlim_max };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &want) == 0 {
                lim = want;
            }
        }
    }
    lim.rlim_cur
}

fn fail(msg: &str) -> ! {
    eprintln!("taso-blkd: {msg}");
    std::process::exit(1);
}

/// Serve one control connection.  `true` if it asked the daemon to quit.
fn serve(d: &Daemon, conn: UnixStream) -> bool {
    let Ok(mut out) = conn.try_clone() else { return false };
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
            let n: u64 = w.trim_start_matches('L').parse().map_err(|_| format!("bad layer id {w}"))?;
            self.find(n).ok_or_else(|| format!("no layer L{n}"))
        };
        let store_err = |e: taso_blk::store::StoreError| e.to_string();
        match words[0] {
            "root" => Ok(self.store.lock().unwrap().root_seal().map_err(store_err)?.to_string()),
            "branch" => {
                let seal = layer(1)?;
                Ok(self.store.lock().unwrap().fork(seal).map_err(store_err)?.to_string())
            }
            "fork" => {
                let seal = layer(1)?;
                let branch = self.store.lock().unwrap().fork(seal).map_err(store_err)?;
                let dev = self.attach(branch)?;
                Ok(format!("{branch} {dev}"))
            }
            "attach" => {
                let branch = layer(1)?;
                self.attach(branch)
            }
            "seal" => {
                // Resolve the id before taking the lock: `find` locks too,
                // and the store's mutex is not re-entrant.
                let branch = layer(1)?;
                Ok(self.store.lock().unwrap().seal(branch).map_err(store_err)?.to_string())
            }
            "detach" => {
                self.detach(layer(1)?)?;
                Ok(String::new())
            }
            "drop" => {
                let l = layer(1)?;
                let kind = self.store.lock().unwrap().map().kind(l).map_err(|e| e.to_string())?;
                if kind == Kind::Branch {
                    let _ = self.detach(l);
                    self.store.lock().unwrap().drop_branch(l).map_err(store_err)?;
                } else {
                    self.store.lock().unwrap().drop_seal(l).map_err(store_err)?;
                }
                Ok(String::new())
            }
            "flush" => Ok(self.store.lock().unwrap().flush().map_err(store_err)?.to_string()),
            "stats" => Ok(self.stats()),
            "quit" => Ok(String::new()),
            other => Err(format!("unknown command {other}")),
        }
    }

    /// The live layer with id number `n`, if any.
    fn find(&self, n: u64) -> Option<LayerId> {
        self.store.lock().unwrap().map().live(n)
    }

    /// Start a device for `branch`.  Returns its block device path.
    fn attach(&self, branch: LayerId) -> Result<String, String> {
        if self.store.lock().unwrap().map().kind(branch).map_err(|e| e.to_string())? != Kind::Branch {
            return Err(format!("{branch} is a Seal; attach a branch"));
        }
        let mut devices = self.devices.lock().unwrap();
        if let Some(d) = devices.get(&branch) {
            return Err(format!("{branch} is already attached as /dev/ublkb{}", d.dev_id));
        }
        let (tx, rx) = mpsc::channel();
        let store = self.store.clone();
        let g = self.geometry;
        let thread = std::thread::Builder::new()
            .name(format!("dev-{branch}"))
            .spawn(move || run_device(store, branch, g, tx))
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
        let d = self.devices.lock().unwrap().remove(&branch).ok_or_else(|| format!("{branch} is not attached"))?;
        UblkCtrl::new_simple(d.dev_id)
            .and_then(|c| c.kill_dev())
            .map_err(|e| format!("cannot stop /dev/ublkb{}: {e:?}", d.dev_id))?;
        let _ = d.thread.join();
        Ok(())
    }

    fn stop_all(&self) {
        let branches: Vec<LayerId> = self.devices.lock().unwrap().keys().copied().collect();
        for b in branches {
            if let Err(e) = self.detach(b) {
                eprintln!("taso-blkd: {e}");
            }
        }
    }

    fn stats(&self) -> String {
        // Never hold the store lock while waiting for the device table:
        // `attach` holds the table while a new device starts, and the
        // kernel's first reads of that device need the store.
        let devices = self.devices.lock().unwrap().len();
        let s = self.store.lock().unwrap();
        let st = s.stats();
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let field = |k: &str| {
            status.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)).unwrap_or("?").to_string()
        };
        format!(
            "log_bytes={} garbage_bytes={} records={} syncs={} lsn={} layers={} devices={} threads={} rss_kib={}",
            st.log_bytes,
            st.garbage_bytes,
            st.records,
            st.syncs,
            s.lsn(),
            s.map().layers(),
            devices,
            field("Threads:"),
            field("VmRSS:")
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
    let Ok(entries) = std::fs::read_dir("/sys/class/ublk-char") else { return (0, 0) };
    let mut ids: Vec<i32> =
        entries.flatten().filter_map(|e| e.file_name().to_str()?.strip_prefix("ublkc")?.parse().ok()).collect();
    ids.sort_unstable();
    let (mut removed, mut failed) = (0, 0);
    for id in ids {
        let Ok(ctrl) = UblkCtrl::new_simple(id) else { continue };
        if ctrl.get_target_type_from_json().ok().as_deref() != Some(TARGET) {
            continue;
        }
        if is_taso_blkd(ctrl.dev_info().ublksrv_pid) {
            continue;
        }
        match ctrl.del_dev_async() {
            Ok(_) => removed += 1,
            Err(e) => {
                eprintln!("taso-blkd: cannot remove leftover device {id}: {e:?}");
                failed += 1;
            }
        }
    }
    (removed, failed)
}

/// Whether `pid` is a running `taso-blkd`.
fn is_taso_blkd(pid: i32) -> bool {
    pid > 0
        && std::fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|c| c.trim_end() == "taso-blkd")
}

/// Own one ublk device for `branch` until it is stopped.  Sends the device
/// id (or why it failed) on `ready` once the device is live.
fn run_device(store: Arc<Mutex<Store>>, branch: LayerId, g: Geometry, ready: mpsc::Sender<Result<i32, String>>) {
    let ctrl = match UblkCtrlBuilder::default()
        .name(TARGET)
        .id(-1)
        .nr_queues(1)
        .depth(g.depth)
        .io_buf_bytes(g.io_bytes)
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
                max_discard_sectors: g.io_bytes >> 9,
                max_write_zeroes_sectors: g.io_bytes >> 9,
                max_discard_segments: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        Ok(())
    };
    let q_store = store.clone();
    let queue = move |qid: u16, dev: &UblkDev| serve_queue(qid, dev, &q_store, branch);
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
fn serve_queue(qid: u16, dev: &UblkDev, store: &Mutex<Store>, branch: LayerId) {
    // SAFETY: fds[0] is the device's character file, opened by UblkDev and
    // kept open for the device's whole life, which outlasts this queue.
    // The kernel allows that file to be opened only once, so it is
    // borrowed, never closed here (ManuallyDrop).
    let cdev = ManuallyDrop::new(unsafe { File::from_raw_fd(dev.tgt.fds[0]) });
    let mut buf = vec![0u8; dev.dev_info.max_io_buf_bytes as usize];
    let handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
        let res = handle(q, tag, qid, &cdev, &mut buf, store, branch);
        if let Err(e) = q.complete_io_cmd_unified(tag, BufDesc::Slice(&[]), Ok(UblkIORes::Result(res))) {
            eprintln!("taso-blkd: {branch}: complete tag {tag}: {e:?}");
        }
    };
    match UblkQueue::new(qid, dev).and_then(|q| q.submit_fetch_commands_unified(BufDescList::Slices(None))) {
        Ok(q) => q.wait_and_handle_io(handler),
        Err(e) => eprintln!("taso-blkd: {branch}: queue {qid}: {e:?}"),
    }
}

/// One request.  Returns bytes moved, 0, or a negative errno.
fn handle(q: &UblkQueue, tag: u16, qid: u16, cdev: &File, buf: &mut [u8], store: &Mutex<Store>, branch: LayerId) -> i32 {
    let iod = q.get_iod(tag);
    let op = iod.op_flags & 0xff;
    let off = iod.start_sector << 9;
    let bytes = (iod.nr_sectors as u64) << 9;
    if op != sys::UBLK_IO_OP_FLUSH && (!off.is_multiple_of(BLOCK) || !bytes.is_multiple_of(BLOCK) || bytes == 0) {
        return -libc::EINVAL;
    }
    let (lba, n) = (off / BLOCK, bytes as usize);
    let pos = UblkIOCtx::ublk_user_copy_pos(qid, tag, 0);
    let io = |e: &dyn std::fmt::Display| {
        eprintln!("taso-blkd: {branch}: op {op} at block {lba}: {e}");
        -libc::EIO
    };
    match op {
        sys::UBLK_IO_OP_READ => {
            if n > buf.len() {
                return -libc::EINVAL;
            }
            if let Err(e) = store.lock().unwrap().read(branch, lba, &mut buf[..n]) {
                return io(&e);
            }
            match cdev.write_all_at(&buf[..n], pos) {
                Ok(()) => n as i32,
                Err(e) => io(&e),
            }
        }
        sys::UBLK_IO_OP_WRITE => {
            if n > buf.len() {
                return -libc::EINVAL;
            }
            if let Err(e) = cdev.read_exact_at(&mut buf[..n], pos) {
                return io(&e);
            }
            let fua = iod.op_flags & sys::UBLK_IO_F_FUA != 0;
            match store.lock().unwrap().write(branch, lba, &buf[..n], fua) {
                Ok(()) => n as i32,
                Err(e) => io(&e),
            }
        }
        sys::UBLK_IO_OP_FLUSH => match store.lock().unwrap().flush() {
            Ok(_) => 0,
            Err(e) => io(&e),
        },
        sys::UBLK_IO_OP_DISCARD | sys::UBLK_IO_OP_WRITE_ZEROES => {
            match store.lock().unwrap().discard(branch, lba, bytes / BLOCK) {
                Ok(()) => 0,
                Err(e) => io(&e),
            }
        }
        _ => -libc::EOPNOTSUPP,
    }
}
