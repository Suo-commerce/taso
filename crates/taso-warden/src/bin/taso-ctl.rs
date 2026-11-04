//! `taso-ctl`: the operator's view (P4 spec rev. 27 §5.8, D83; file 12),
//! and the stranger's first commands (P5 §4, C1; design
//! `Taso_design_c1_init_2026-11-04`, c-a…c-h).
//!
//! ```text
//! taso-ctl init [--data DIR] [--size-gib N] [--rootfs DIR] [--force]
//! taso-ctl status [<warden-config>]
//! taso-ctl <warden-config> explain <vessel or template id (32 hex) | candidate id (64 hex)>
//! ```
//!
//! # `init`
//!
//! Makes a fresh Linux host able to run a Warden on the block log, as
//! root, and starts nothing (D4-2: the processes are the operator's).
//! In order, **checks before writes**, every refusal one line with what
//! to do:
//!
//! 1. root; 2. no SELinux (`/sys/fs/selinux/enforce` absent: the README's
//!    host rule); 3. cgroup v2 (`/sys/fs/cgroup/cgroup.controllers`);
//!    4. `runc` on `PATH`; 5. the `ublk_drv` module available (`modinfo`);
//!    6. `/sys/kernel/rcu_expedited` present; 7. the data directory on a
//!    local filesystem (not tmpfs, NFS, overlay, FUSE, ramfs); 8. not set
//!    up already, unless `--force`.
//!
//! Then it sets the two things a Taso host needs (P5-14, lever 4; A1 does
//! the same on a measurement host) and keeps them at boot: `ublk_drv`
//! loaded (`/etc/modules-load.d/taso.conf`) and `rcu_expedited=1`
//! (`/etc/tmpfiles.d/taso-rcu.conf`); makes the directories; writes the
//! single-node config to `/etc/taso/warden.json` — the local coordinator,
//! the block log, `"effects": "hold"` (D4-5: a Vessel acts outward only
//! once its entry says so) — after parsing it as the Warden would, so it
//! never writes a config the Warden refuses; and prints the two commands
//! that start the block log and the Warden, in order, and the three
//! sentences a stranger must read (D91, A2, L2).  Idempotent: run again it
//! says "already set up" and changes nothing.
//!
//! # `status`
//!
//! Reads the config, asks the block log `stats`, and says what runs.
//!
//! # `explain`
//!
//! Rebuilds every decision about a Vessel, a Template or a Candidate from
//! the coordinator log's accepted records alone, and checks them against
//! the store ([`taso_warden::explain`]): every record intact and carried
//! by the pack the log names, every derived id what its fields derive,
//! every content object present and hashing to its key.  It uses the
//! config's coordinator and store (a `"local"` coordinator only while its
//! daemon is not running: redb locks the file).  Output: one JSON object,
//! `{"explain": {…}, "checks": {"passed": n, "failed": ["…", …]}}`.
//!
//! # Exit status
//!
//! 0 done (`explain`: every check held; `status`: the block log answers);
//! 1 it could not be done (`explain`: no such id, the coordinator or the
//! store unreachable; `status`: the block log does not answer; `init`: a
//! write failed); 2 a bad command line or configuration; 3 `init`
//! refused the host; 4 `explain`ed, a check failed (something changed
//! after it was accepted).

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use serde_json::json;
use taso_warden::coordinator::{Coord, Coordinator, LogConfig};
use taso_warden::coordsrv::RemoteCoord;
use taso_warden::coordstore::CoordStore;
use taso_warden::daemon::{Config, CoordConf, StorageConf};
use taso_warden::explain::{explain, Subject};

const USAGE: &str = "usage: taso-ctl init [--data DIR] [--size-gib N] [--rootfs DIR] [--force]
       taso-ctl status [<warden-config>]
       taso-ctl <warden-config> explain <vessel or template id (32 hex) | candidate id (64 hex)>";

const CONFIG: &str = "/etc/taso/warden.json";
const DATA: &str = "/var/lib/taso";
const RUN: &str = "/run/taso";
const LANDLOCK: &str = "/usr/lib/taso/landlock";
const MODULES_CONF: &str = "/etc/modules-load.d/taso.conf";
const RCU_CONF: &str = "/etc/tmpfiles.d/taso-rcu.conf";
const RCU: &str = "/sys/kernel/rcu_expedited";

fn usage(why: &str) -> ExitCode {
    eprintln!("taso-ctl: {why}\n{USAGE}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("init") => init(&args[1..]),
        Some("status") => status(args.get(1).map(String::as_str)),
        Some(_) if args.len() == 3 && args[1] == "explain" => explain_cmd(&args[0], &args[2]),
        Some(_) => usage("unknown command"),
        None => usage("a command is needed"),
    }
}

// ── init ──────────────────────────────────────────────────────────────

struct InitArgs {
    data: PathBuf,
    size_gib: u64,
    rootfs: Option<PathBuf>,
    force: bool,
}

fn init_args(args: &[String]) -> Result<InitArgs, String> {
    let mut a = InitArgs {
        data: PathBuf::from(DATA),
        size_gib: 64,
        rootfs: None,
        force: false,
    };
    let mut it = args.iter();
    while let Some(w) = it.next() {
        let value = |it: &mut std::slice::Iter<String>| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{w} needs a value"))
        };
        match w.as_str() {
            "--data" => a.data = PathBuf::from(value(&mut it)?),
            "--size-gib" => {
                a.size_gib = value(&mut it)?
                    .parse()
                    .ok()
                    .filter(|n: &u64| (1..=65536).contains(n))
                    .ok_or("--size-gib takes 1..=65536")?
            }
            "--rootfs" => a.rootfs = Some(PathBuf::from(value(&mut it)?)),
            "--force" => a.force = true,
            other => return Err(format!("unknown option {other}")),
        }
    }
    for (name, p) in [("--data", Some(&a.data)), ("--rootfs", a.rootfs.as_ref())] {
        if let Some(p) = p {
            if !p.is_absolute() {
                return Err(format!("{name} must be an absolute path"));
            }
        }
    }
    Ok(a)
}

/// A refusal: the host as found, and what to do (c-b).
struct Refused(String);

fn refuse(why: impl Into<String>) -> Refused {
    Refused(why.into())
}

/// The eight checks, in order, writing nothing.  `Ok(true)` is "already
/// set up"; `Ok(false)` is a host to set up.
fn check_host(a: &InitArgs) -> Result<bool, Refused> {
    // 1. root: /etc, a kernel module and a sysfs setting are written.
    if !rustix::process::geteuid().is_root() {
        return Err(refuse("init must run as root (sudo taso-ctl init …)"));
    }
    // 2. SELinux (the README's host rule): a labelled file can never
    // become a Template (P4 D32).
    if Path::new("/sys/fs/selinux/enforce").exists() {
        return Err(refuse(
            "SELinux is enabled on this host: unsupported (Taso runs on Linux without SELinux, \
             e.g. Ubuntu or Debian; see README.md, Supported hosts)",
        ));
    }
    // 3. cgroup v2: runc puts each agent in its own cgroup.
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return Err(refuse(
            "no cgroup v2 at /sys/fs/cgroup: the Warden runs agents under runc, which needs it \
             (boot with systemd.unified_cgroup_hierarchy=1, the default on Ubuntu 22.04 and later)",
        ));
    }
    // 4. runc.
    if find_on_path("runc").is_none() {
        return Err(refuse(
            "runc is not on PATH: the Warden starts agents with it (apt install runc)",
        ));
    }
    // 5. ublk: the block log appears to a Vessel as a block device the
    // Warden's taso-blkd serves; modinfo looks the module up, loads nothing.
    let modinfo = std::process::Command::new("modinfo")
        .args(["-n", "ublk_drv"])
        .output();
    let module_known = matches!(&modinfo, Ok(o) if o.status.success())
        || Path::new("/sys/module/ublk_drv").exists();
    if !module_known {
        return Err(refuse(format!(
            "this kernel ({}) has no ublk_drv module: Taso needs Linux 6.0 or later with \
             CONFIG_BLK_DEV_UBLK (on Ubuntu: apt install linux-modules-extra-$(uname -r))",
            kernel_release()
        )));
    }
    // 6. expedited RCU (P5-14): without it a Seal's freeze pays three
    // slow grace periods.
    if !Path::new(RCU).exists() {
        return Err(refuse(format!(
            "{RCU} is missing: this kernel cannot be told to expedite RCU, which a Taso host needs"
        )));
    }
    // 7. the data directory's filesystem: the block log is one big file
    // that must be synced; tmpfs, NFS, overlay and FUSE are refused.
    let probe = nearest_existing(&a.data);
    match rustix::fs::statfs(&probe) {
        Ok(st) => {
            let magic = st.f_type as u64;
            let bad = match magic {
                0x0102_1994 => Some("tmpfs"),
                0x0000_6969 => Some("NFS"),
                0x794c_7630 => Some("overlay"),
                0x6573_5546 => Some("FUSE"),
                0x8584_58f6 => Some("ramfs"),
                _ => None,
            };
            if let Some(kind) = bad {
                return Err(refuse(format!(
                    "{} is on {kind}: the block log needs a local ext4 or XFS filesystem (--data DIR)",
                    probe.display()
                )));
            }
        }
        Err(e) => {
            return Err(refuse(format!(
                "cannot read the filesystem of {}: {e}",
                probe.display()
            )))
        }
    }
    // 8. already set up?
    let config_there = Path::new(CONFIG).exists();
    let log_there = a.data.join("blk.log").exists();
    if (config_there || log_there) && !a.force {
        return Ok(true);
    }
    Ok(false)
}

fn init(args: &[String]) -> ExitCode {
    let a = match init_args(args) {
        Ok(a) => a,
        Err(e) => return usage(&e),
    };
    if let Some(r) = &a.rootfs {
        if !r.is_dir() {
            return usage(&format!("--rootfs {}: not a directory", r.display()));
        }
    }
    match check_host(&a) {
        Err(Refused(why)) => {
            eprintln!("taso-ctl init: refused: {why}");
            return ExitCode::from(3);
        }
        Ok(true) => {
            println!(
                "taso-ctl init: already set up ({CONFIG} or {} exists): nothing changed. \
                 --force rewrites the config; taso-ctl status says what runs.",
                a.data.join("blk.log").display()
            );
            return ExitCode::SUCCESS;
        }
        Ok(false) => {}
    }
    // The config first, as the Warden would read it: nothing is written
    // to the host before the config it is for is known to be accepted.
    let socket = PathBuf::from(RUN).join("blk.sock");
    let text = init_config(&a, Path::new(LANDLOCK).exists());
    if let Err(e) = Config::parse(&text) {
        eprintln!("taso-ctl init: the config it would write is refused by the Warden: {e}");
        return ExitCode::from(1);
    }
    // The host: the module now and at boot; expedited RCU now and at boot.
    let steps: Vec<(&str, Result<(), String>)> = vec![
        (
            "ublk_drv kept at boot",
            write_file(MODULES_CONF, "ublk_drv\n"),
        ),
        ("ublk_drv loaded", modprobe("ublk_drv")),
        (
            "rcu_expedited kept at boot",
            write_file(RCU_CONF, "w /sys/kernel/rcu_expedited - - - - 1\n"),
        ),
        ("rcu_expedited set", write_file(RCU, "1")),
    ];
    for (what, r) in steps {
        if let Err(e) = r {
            eprintln!("taso-ctl init: {what}: {e}");
            return ExitCode::from(1);
        }
        println!("  {what}");
    }
    // The directories, the config.
    for d in [
        a.data.clone(),
        a.data.join("state"),
        a.data.join("store"),
        a.data.join("spool"),
        a.data.join("mnt"),
        PathBuf::from(RUN).join("run"),
        PathBuf::from(CONFIG)
            .parent()
            .expect("a file path")
            .to_path_buf(),
    ] {
        if let Err(e) = std::fs::create_dir_all(&d) {
            eprintln!("taso-ctl init: mkdir {}: {e}", d.display());
            return ExitCode::from(1);
        }
    }
    println!("  directories under {} and {RUN}", a.data.display());
    if let Err(e) = write_file(CONFIG, &text) {
        eprintln!("taso-ctl init: {CONFIG}: {e}");
        return ExitCode::from(1);
    }
    println!("  {CONFIG} written (effects held by default; no Vessels yet)");
    // What to do next, and what to know (c-g).
    println!(
        "\nStart the block log, then the Warden once `taso-ctl status` says the block log answers:\n\
         \n  taso-blkd {log} {sock} --size-gib {size}\n  taso-wardend {CONFIG}\n\
         \nAdd a Vessel to \"vessels\" in {CONFIG} (its entry needs a rootfs: {rootfs}).\n\
         \nRead before running an agent:\n\
         - Taso records; it does not police. Its guarantee holds only when every persistent \
         writable device the agent can reach is the Warden's, and every external writable service \
         is controlled by the hosting environment (spec D91).\n\
         - On a virtual machine the disk's durability under power loss is the provider's promise, \
         asserted by you, not checked by the Warden (P5 A2).\n\
         - An agent's SQLite at synchronous=full costs four syncs a turn and buys the Seal nothing \
         under load; synchronous=normal is enough, a Seal is the durable acknowledgement.",
        log = a.data.join("blk.log").display(),
        sock = socket.display(),
        size = a.size_gib,
        rootfs = match &a.rootfs {
            Some(r) => format!("{} is set as the node's", r.display()),
            None => "none set; unpack the demo-agent image and run `taso-ctl init --rootfs DIR --force`, \
                     or put a \"runtime\": {\"rootfs\": …} on the entry"
                .to_string(),
        },
    );
    ExitCode::SUCCESS
}

/// The single-node config `init` writes (c-d): the local coordinator, the
/// block log under `--data`, effects held by default, no Vessels yet.
fn init_config(a: &InitArgs, landlock: bool) -> String {
    let mut runtime = json!({
        "host_uid_base": 200000,
    });
    if landlock {
        runtime["landlock_shim"] = json!(LANDLOCK);
    }
    if let Some(r) = &a.rootfs {
        runtime["rootfs"] = json!(r);
    }
    let config = json!({
        "warden": 1,
        "coordinator": {"local": a.data.join("coord.redb")},
        "root": "taso/vessels",
        "storage": {"blk": {
            "socket": PathBuf::from(RUN).join("blk.sock"),
            "mounts": a.data.join("mnt"),
            "spool": a.data.join("spool"),
        }},
        "state_dir": a.data.join("state"),
        "store": a.data.join("store"),
        "prefix": "vessels",
        "run_dir": PathBuf::from(RUN).join("run"),
        "batched_snapshots": true,
        "runtime": runtime,
        "effects": "hold",
        "vessels": [],
    });
    serde_json::to_string_pretty(&config).expect("a JSON value prints")
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(name))
            .find(|f| f.is_file())
    })
}

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

/// `p`, or the nearest ancestor that exists (the filesystem a new
/// directory would be on).
fn nearest_existing(p: &Path) -> PathBuf {
    let mut q = p.to_path_buf();
    while !q.exists() {
        match q.parent() {
            Some(parent) => q = parent.to_path_buf(),
            None => return PathBuf::from("/"),
        }
    }
    q
}

fn write_file(path: &str, content: &str) -> Result<(), String> {
    if let Some(d) = Path::new(path).parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("mkdir {}: {e}", d.display()))?;
    }
    std::fs::write(path, content).map_err(|e| e.to_string())
}

fn modprobe(module: &str) -> Result<(), String> {
    let o = std::process::Command::new("modprobe")
        .arg(module)
        .output()
        .map_err(|e| format!("cannot run modprobe: {e}"))?;
    if !o.status.success() {
        return Err(String::from_utf8_lossy(&o.stderr).trim().to_string());
    }
    if !Path::new("/dev/ublk-control").exists() {
        return Err("loaded, but /dev/ublk-control did not appear".into());
    }
    Ok(())
}

// ── status ────────────────────────────────────────────────────────────

fn status(config_path: Option<&str>) -> ExitCode {
    let path = config_path.unwrap_or(CONFIG);
    let config = match read_config(path) {
        Ok(c) => c,
        Err(e) => return usage(&format!("{path}: {e}")),
    };
    let rcu = std::fs::read_to_string(RCU)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".into());
    println!(
        "host: ublk_drv {}, rcu_expedited {rcu}{}",
        if Path::new("/sys/module/ublk_drv").exists() {
            "loaded"
        } else {
            "not loaded"
        },
        if rcu == "1" {
            ""
        } else {
            " (a Taso host needs 1)"
        }
    );
    println!(
        "config: {path}; {} Vessel(s){}; effects {} by default; rootfs {}",
        config.vessels.len(),
        if config.vessels.is_empty() {
            String::new()
        } else {
            format!(
                " ({})",
                config
                    .vessels
                    .iter()
                    .map(|v| v.subject.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
        match config.effects {
            Some(taso_warden::daemon::EffectsConf::Hold) => "held",
            Some(taso_warden::daemon::EffectsConf::Dispatch) => "released",
            None => "by origin",
        },
        match &config.runtime.rootfs {
            Some(r) => r.display().to_string(),
            None => "not set".into(),
        }
    );
    let StorageConf::Blk { socket, .. } = &config.storage else {
        println!("storage: zfs (taso-ctl status reads the block log only)");
        return ExitCode::SUCCESS;
    };
    match taso_blk::client::Client::connect(socket).and_then(|mut c| c.stats()) {
        Ok(st) => {
            let get = |k: &str| st.get(k).cloned().unwrap_or_else(|| "?".into());
            let mib = get("log_bytes")
                .parse::<u64>()
                .map(|b| b >> 20)
                .unwrap_or(0);
            println!(
                "block log: answering at {}; {} device(s), {} layer(s), {} MiB of log, {} records",
                socket.display(),
                get("devices"),
                get("layers"),
                mib,
                get("records")
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!(
                "block log: not answering at {} ({e}); start it: taso-blkd <log> {} --size-gib N",
                socket.display(),
                socket.display()
            );
            ExitCode::from(1)
        }
    }
}

fn read_config(path: &str) -> Result<Config, String> {
    std::fs::read_to_string(path)
        .map_err(|e| e.to_string())
        .and_then(|t| Config::parse(&t).map_err(|e| e.to_string()))
}

// ── explain ───────────────────────────────────────────────────────────

fn explain_cmd(cfg: &str, id: &str) -> ExitCode {
    let Some(subject) = Subject::parse(id) else {
        return usage("an id is 32 or 64 hex digits");
    };
    let config = match read_config(cfg) {
        Ok(c) => c,
        Err(e) => return usage(&format!("{cfg}: {e}")),
    };
    let store = match config.store.open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("taso-ctl: opening the store: {e}");
            return ExitCode::from(1);
        }
    };
    let coord: Arc<dyn Coord> = match &config.coordinator {
        CoordConf::Remote { socket } => Arc::new(RemoteCoord::new(socket)),
        CoordConf::Local { path, .. } => match Coordinator::open_with(
            path,
            LogConfig {
                store: Arc::new(CoordStore::new(store.clone(), &config.prefix)),
                ..LogConfig::default()
            },
        ) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                eprintln!("taso-ctl: coordinator {}: {e}", path.display());
                return ExitCode::from(1);
            }
        },
    };
    match explain(coord.as_ref(), &store, &config.prefix, subject) {
        Ok(e) => {
            let failed: Vec<&str> = e.failed().iter().map(|c| c.what.as_str()).collect();
            let passed = e.checks.len() - failed.len();
            println!(
                "{}",
                json!({"explain": e.explain, "checks": {"passed": passed, "failed": failed}})
            );
            if failed.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(4)
            }
        }
        Err(why) => {
            println!("{}", json!({"error": why}));
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `init` writes is what the Warden reads (c-d): parsed as the
    /// Warden parses it, with and without a rootfs and the Landlock shim,
    /// holding by default, naming the block log, listing no Vessel.
    #[test]
    fn the_config_init_writes_is_accepted_by_the_warden() {
        for (rootfs, landlock) in [(None, false), (Some(PathBuf::from("/srv/agent")), true)] {
            let a = InitArgs {
                data: PathBuf::from("/var/lib/taso"),
                size_gib: 64,
                rootfs: rootfs.clone(),
                force: false,
            };
            let text = init_config(&a, landlock);
            let c = Config::parse(&text).unwrap_or_else(|e| panic!("{text}\n{e}"));
            assert_eq!(c.effects, Some(taso_warden::daemon::EffectsConf::Hold));
            assert!(c.vessels.is_empty());
            assert_eq!(c.runtime.rootfs, rootfs);
            assert_eq!(c.runtime.landlock_shim.is_some(), landlock);
            assert!(
                matches!(&c.storage, StorageConf::Blk { socket, .. } if socket == Path::new("/run/taso/blk.sock"))
            );
            assert!(matches!(&c.coordinator, CoordConf::Local { .. }));
        }
    }

    #[test]
    fn init_args_are_checked() {
        assert!(init_args(&["--size-gib".into(), "0".into()]).is_err());
        assert!(init_args(&["--data".into(), "relative".into()]).is_err());
        assert!(init_args(&["--bogus".into()]).is_err());
        let a = init_args(&["--data".into(), "/srv/taso".into(), "--force".into()]).unwrap();
        assert!(a.force && a.data == Path::new("/srv/taso") && a.size_gib == 64);
    }
}
