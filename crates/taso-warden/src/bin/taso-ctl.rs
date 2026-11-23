//! `taso-ctl`: the operator's view (P4 spec rev. 27 §5.8, D83; file 12),
//! and the stranger's first commands (P5 §4, C1; design
//! `Taso_design_c1_init_2026-11-04`, c-a…c-h).
//!
//! ```text
//! taso-ctl init [--data DIR] [--size-gib N] [--rootfs DIR] [--force]
//! taso-ctl status [<warden-config>]
//! taso-ctl demo [--config PATH]
//! taso-ctl proposals <vessel> [--config PATH]
//! taso-ctl approve <vessel> <op> [--config PATH]
//! taso-ctl deny <vessel> <op> [reason…] [--config PATH]
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
//! (`/etc/tmpfiles.d/taso-rcu.conf`), and the run directories under
//! `/run/taso` made at boot (`/etc/tmpfiles.d/taso-run.conf`: `/run` is
//! emptied at every boot); makes the directories; writes the
//! single-node config to `/etc/taso/warden.json` — the local coordinator,
//! the block log, `"effects": "hold"` (D4-5: a Vessel acts outward only
//! once its entry says so) — after parsing it as the Warden would, so it
//! never writes a config the Warden refuses; and prints the two commands
//! that start the block log and the Warden, in order, and the three
//! sentences a stranger must read (D91, A2, L2).  Idempotent: run again it
//! says "already set up", leaves the config as it is, and only makes the
//! run directories again if a reboot took them.
//!
//! # `status`
//!
//! Reads the config, asks the block log `stats`, and says what runs.
//!
//! # `demo`
//!
//! Adds the demo Vessel to the config and starts nothing (P5 C3, K-d: the
//! Vessel entry only): subject `demo`, uid slot 1, one fork slot (2), its
//! agent `taso-sim` from the demo-agent image (Dockerfile target
//! `agent-demo`), 20 turns of small SQLite transactions at
//! `synchronous=normal` and one fork whose child seals on its own.  The
//! node's rootfs must be set (the unpacked image: `init --rootfs DIR`).
//! The new config is parsed as the Warden would before it is written, and
//! written whole to a temporary file renamed over the old one.  Run again
//! it says "already there" and changes nothing.
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
//! # `proposals`
//!
//! Asks the running Warden, on its decider socket (as root, or as the
//! Warden's uid), what one Vessel holds: the actions its agent asked for
//! that nothing has released (design `Taso_design_proposals_inbox`, 4a).
//! A read: nothing is recorded, released or refused.  `<vessel>` is its
//! `subject` in the config, a fork's name (`<subject>-fork-<n>`), or its
//! id (32 hex).  Output: one JSON object a line for each held action, in
//! the order they were asked,
//! `{"op", "lsn", "provider", "request_hex", "request_text", "footprint_hex",
//! "retry", "consequence", "sealed"}` (`request_hex` is the exact bytes;
//! `request_text` the same as text, `null` if they are not UTF-8;
//! `sealed`: the Vessel's last Seal covers it, so it survives a restart),
//! then one last line `{"vessel", "held", "last_seal"}`.  A held action
//! is what an agent asked for, not a licence to send: only the sender
//! socket's `Open` list is.
//!
//! # `approve`, `deny`
//!
//! Decide one held action, by the `op` that `proposals` printed (design
//! §1b, §1c), on the same socket.  `approve` releases it: the Warden
//! records the release and ships it before it answers, and the Vessel's
//! sender then finds it on `Open`.  Only an action that is `sealed`, of a
//! Vessel that is running, can be approved.  `deny` closes it as not
//! applied with the reason (the words after the op; at most 1 KiB), which
//! its agent reads; nothing is sent.  One JSON line:
//! `{"vessel", "op", "approved": true, "before"}` or `"denied": true`
//! (`before`: the same decision was recorded earlier, nothing was
//! written), `{…, "refused": "<why>"}` when the Warden will not take it
//! (not a held action, not sealed yet, not running, an earlier effect
//! unresolved, not shipped), or `{…, "error": "<why>"}` when it could not
//! answer now: the same command may be run again.
//!
//! # Exit status
//!
//! 0 done (`explain`: every check held; `status`: the block log answers;
//! `proposals`: the Warden answered; `approve`, `deny`: taken, now or
//! before);
//! 1 it could not be done (`explain`: no such id, the coordinator or the
//! store unreachable; `status`: the block log does not answer; `init`,
//! `demo`: a write failed; `proposals`, `approve`, `deny`: the Warden
//! does not answer, cannot answer for that Vessel, or refused: its line
//! says which and why); 2 a bad command line or configuration (`demo`:
//! no config, or no rootfs in it); 3 `init`
//! refused the host; 4 `explain`ed, a check failed (something changed
//! after it was accepted).

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use serde_json::json;
use taso_warden::coordinator::{Coord, Coordinator};
use taso_warden::coordsrv::RemoteCoord;
use taso_warden::daemon::{Config, CoordConf};
use taso_warden::explain::{explain, Subject};

const USAGE: &str = "usage: taso-ctl init [--data DIR] [--size-gib N] [--rootfs DIR] [--force]
       taso-ctl status [<warden-config>]
       taso-ctl demo [--config PATH]
       taso-ctl proposals <vessel> [--config PATH]
       taso-ctl approve <vessel> <op> [--config PATH]
       taso-ctl deny <vessel> <op> [reason...] [--config PATH]
       taso-ctl <warden-config> explain <vessel or template id (32 hex) | candidate id (64 hex)>";

const CONFIG: &str = "/etc/taso/warden.json";
const DATA: &str = "/var/lib/taso";
const RUN: &str = "/run/taso";
const LANDLOCK: &str = "/usr/lib/taso/landlock";
const MODULES_CONF: &str = "/etc/modules-load.d/taso.conf";
const RCU_CONF: &str = "/etc/tmpfiles.d/taso-rcu.conf";
/// Keeps the run directories at boot: `/run` is emptied at every boot.
const RUN_CONF: &str = "/etc/tmpfiles.d/taso-run.conf";

/// The directories under [`RUN`] the block log's socket and the Warden's
/// run directory live in.  `/run` is a tmpfs, emptied at every boot.
fn run_dirs() -> [PathBuf; 2] {
    [PathBuf::from(RUN), PathBuf::from(RUN).join("run")]
}

/// The tmpfiles.d lines that make [`run_dirs`] at boot.
fn run_conf() -> String {
    run_dirs()
        .iter()
        .map(|d| format!("d {} 0755 root root -\n", d.display()))
        .collect()
}

/// Make [`run_dirs`] if a boot took them; `true` if one was made.
fn make_run_dirs() -> Result<bool, String> {
    let mut made = false;
    for d in run_dirs() {
        if !d.is_dir() {
            std::fs::create_dir_all(&d).map_err(|e| format!("mkdir {}: {e}", d.display()))?;
            made = true;
        }
    }
    Ok(made)
}
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
        Some("demo") => demo(&args[1..]),
        Some("proposals") => proposals(&args[1..]),
        Some("approve") => decide(&args[1..], true),
        Some("deny") => decide(&args[1..], false),
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
            // After a reboot `/run` is empty: the block log's socket
            // directory is made again here, the one thing a set-up host
            // may lack.  `init` used to say "nothing changed" and point at
            // --force, which writes a new config over the operator's and
            // loses its Vessel entries (audit 2026-11-09, taso-ctl init
            // after a reboot).
            match make_run_dirs() {
                Ok(true) => println!("  {RUN} made again (a reboot empties /run)"),
                Ok(false) => {}
                Err(e) => {
                    eprintln!("taso-ctl init: {e}");
                    return ExitCode::from(1);
                }
            }
            // A host set up before the data directories were private.
            if let Err(e) = make_data_dirs(&a.data, |line| println!("  {line}")) {
                eprintln!("taso-ctl init: {e}");
                return ExitCode::from(1);
            }
            println!(
                "taso-ctl init: already set up ({CONFIG} or {} exists): the config is left as it is. \
                 taso-ctl status says what runs. (--force writes a new config over it, \
                 and its Vessel entries are lost.)",
                a.data.join("blk.log").display()
            );
            return ExitCode::SUCCESS;
        }
        Ok(false) => {}
    }
    // The config first, as the Warden would read it: nothing is written
    // to the host before the config it is for is known to be accepted.
    let socket = PathBuf::from(RUN).join("blk.sock");
    let landlock = shim_in(a.rootfs.as_deref());
    let text = init_config(&a, landlock);
    if let Err(e) = Config::parse(&text) {
        eprintln!("taso-ctl init: the config it would write is refused by the Warden: {e}");
        return ExitCode::from(1);
    }
    // The host: the module now and at boot; expedited RCU now and at boot.
    // One at a time, the first failure stopping the rest (review fix M5,
    // Kimi's M5: all four used to run before any result was looked at).
    let mut steps: Vec<Step> = vec![
        (
            "ublk_drv kept at boot",
            Box::new(|| write_file(MODULES_CONF, "ublk_drv\n")),
        ),
        ("ublk_drv loaded", Box::new(|| modprobe("ublk_drv"))),
        (
            "rcu_expedited kept at boot",
            Box::new(|| write_file(RCU_CONF, "w /sys/kernel/rcu_expedited - - - - 1\n")),
        ),
        ("rcu_expedited set", Box::new(|| write_file(RCU, "1"))),
        (
            "/run/taso kept at boot",
            Box::new(|| write_file(RUN_CONF, &run_conf())),
        ),
    ];
    if let Err(e) = run_steps(&mut steps, |what| println!("  {what}")) {
        eprintln!("taso-ctl init: {e}");
        return ExitCode::from(1);
    }
    // The directories, the config.
    if let Err(e) = make_data_dirs(&a.data, |line| println!("  {line}")) {
        eprintln!("taso-ctl init: {e}");
        return ExitCode::from(1);
    }
    for d in [
        run_dirs()[1].clone(),
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
    println!(
        "  {CONFIG} written (effects held by default; Landlock {}; no Vessels yet)",
        if landlock {
            "on: the shim is in the rootfs"
        } else {
            "off: no shim at usr/lib/taso/landlock in a rootfs"
        }
    );
    // What to do next, and what to know (c-g).  The Warden on a static
    // config runs the Vessels listed and ends when they are done -- with
    // none listed it ends at once (found on the first stranger's VM,
    // 2026-11-04) -- so the Vessel comes first in the order printed.
    println!(
        "\nNext, in this order:\n\
         \n1. Add a Vessel to \"vessels\" in {CONFIG}. Its entry needs a rootfs: {rootfs}.\n\
         2. Start the block log:        taso-blkd {log} {sock} --size-gib {size}\n\
         3. When `taso-ctl status` says the block log answers, start the Warden:  taso-wardend {CONFIG}\n\
         \x20  The Warden runs the Vessels listed and ends when they are done; with none listed it ends at once.\n\
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

/// The directories under `--data` and their modes (audit 2026-11-16, S1:
/// they were made with the default mode, 0755 under umask 022, and every
/// Vessel's data under them was readable by any local user).
///
/// `state`, `store` and `spool` hold Vessels' data and nothing an agent
/// reaches through them: the owner's alone.  `data` itself and `mnt` hold
/// the Vessels' mounts, and an agent's mapped uids must pass through
/// their parents to reach its work directory: others may pass, not list
/// (0711).  The block log in `data` is private itself (taso-blk).
fn data_dirs(data: &Path) -> [(PathBuf, u32); 5] {
    [
        (data.to_path_buf(), 0o711),
        (data.join("state"), 0o700),
        (data.join("store"), 0o700),
        (data.join("spool"), 0o700),
        (data.join("mnt"), 0o711),
    ]
}

/// Make [`data_dirs`] with their modes.  One already there only loses
/// what others have beyond its mode (the owner's and the group's access
/// are the operator's), and `said` hears of each change (D&D S1-a b).
fn make_data_dirs(data: &Path, mut said: impl FnMut(&str)) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    for (d, mode) in data_dirs(data) {
        let set = |m: u32| {
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(m))
                .map_err(|e| format!("chmod {}: {e}", d.display()))
        };
        if !d.is_dir() {
            // Any parents `--data` needs are made passable, as `data` is.
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o711)
                .create(&d)
                .map_err(|e| format!("mkdir {}: {e}", d.display()))?;
            set(mode)?; // exactly, whatever the umask
            continue;
        }
        let now = std::fs::metadata(&d)
            .map_err(|e| format!("{}: {e}", d.display()))?
            .permissions()
            .mode()
            & 0o7777;
        let to = now & !(0o007 & !mode);
        if to != now {
            set(to)?;
            said(&format!(
                "{}: others' access taken away ({now:o} -> {to:o}); it holds Vessels' data",
                d.display()
            ));
        }
    }
    Ok(())
}

/// Whether the agents' rootfs carries the Landlock shim at [`LANDLOCK`]:
/// the shim runs inside the agent's container, so it is looked for there,
/// not on the host (the demo-agent image carries it; before 2026-11-05
/// `init` looked on the host, and a host without it wrote a config
/// without Landlock for an image that had it).  No rootfs: no shim known.
fn shim_in(rootfs: Option<&Path>) -> bool {
    rootfs.is_some_and(|r| r.join(LANDLOCK.trim_start_matches('/')).is_file())
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

/// One host step of `init`: what it does, and doing it.
type Step<'a> = (&'static str, Box<dyn FnMut() -> Result<(), String> + 'a>);

/// Run `steps` in order, telling `done` of each that succeeds; the first
/// failure stops the rest and says which steps already took effect (they
/// are each idempotent: running `init` again after fixing the cause
/// finishes the job).
fn run_steps(steps: &mut [Step], mut done: impl FnMut(&str)) -> Result<(), String> {
    let mut made: Vec<&str> = Vec::new();
    for (what, step) in steps.iter_mut() {
        if let Err(e) = step() {
            let before = if made.is_empty() {
                "nothing was changed before it".to_string()
            } else {
                format!("done before it, and left: {}", made.join(", "))
            };
            return Err(format!("{what}: {e} (stopped here; {before})"));
        }
        done(what);
        made.push(what);
    }
    Ok(())
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
    println!("{}", agent_limits(&config));
    let socket = &config.storage.socket;
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

/// The agents' limits as `status` says them: the node's, then each Vessel
/// that sets its own; none set reads \"unlimited\" (review fix M3: Vessels
/// are unlimited by default, the operator limits them).
fn agent_limits(config: &Config) -> String {
    let say = |m: Option<u64>, p: Option<u64>| {
        format!(
            "memory {}, processes {}",
            m.map_or("unlimited".to_string(), |b| format!("{} MiB", b >> 20)),
            p.map_or("unlimited".to_string(), |n| n.to_string())
        )
    };
    let node = (config.runtime.memory_bytes, config.runtime.pids);
    let mut out = format!(
        "agent limits: {} (runtime.memory_bytes, runtime.pids)",
        say(node.0, node.1)
    );
    for v in &config.vessels {
        let own = (
            v.runtime.as_ref().and_then(|r| r.memory_bytes).or(node.0),
            v.runtime.as_ref().and_then(|r| r.pids).or(node.1),
        );
        if own != node {
            out.push_str(&format!("; {}: {}", v.subject, say(own.0, own.1)));
        }
    }
    out
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
        CoordConf::Local {
            path,
            deleted_quarantine,
            ..
        } => match Coordinator::open_with(
            path,
            taso_warden::coordinator::reading_store(
                store.clone(),
                &config.prefix,
                *deleted_quarantine,
            ),
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

// ── the decider socket: proposals ─────────────────────────────────────

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The arguments without `--config PATH` (anywhere among them), and the
/// config's path.
fn config_arg(args: &[String]) -> Result<(Vec<&str>, &str), String> {
    let mut rest = Vec::new();
    let mut path = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--config" {
            let p = it.next().ok_or("--config needs a path")?;
            if path.replace(p.as_str()).is_some() {
                return Err("--config is given twice".into());
            }
        } else {
            rest.push(a.as_str());
        }
    }
    Ok((rest, path.unwrap_or(CONFIG)))
}

/// `<vessel> [--config PATH]`: the Vessel's argument and the config's
/// path.
fn vessel_args(args: &[String]) -> Result<(&str, &str), String> {
    match config_arg(args)? {
        (rest, path) if rest.len() == 1 => Ok((rest[0], path)),
        _ => Err("a Vessel is needed: its subject, a fork's name or its id".into()),
    }
}

/// `<vessel> <op> [reason…] [--config PATH]`: the Vessel's argument, the
/// op, the reason (a denial's: the words after the op, or that none was
/// given; an approval takes none) and the config's path.
fn decide_args(args: &[String], approval: bool) -> Result<(&str, u64, String, &str), String> {
    let (rest, path) = config_arg(args)?;
    let [vessel, op, reason @ ..] = rest.as_slice() else {
        return Err("a Vessel and an op are needed (`taso-ctl proposals` prints both)".into());
    };
    let op = op
        .parse::<u64>()
        .map_err(|_| format!("{op:?} is not an op (a number)"))?;
    if approval && !reason.is_empty() {
        return Err("an approval takes a Vessel and an op, nothing more".into());
    }
    let reason = if reason.is_empty() {
        "no reason given".to_string()
    } else {
        reason.join(" ")
    };
    if reason.len() > taso_core::decider::MAX_DENY_REASON {
        return Err(format!(
            "a reason of {} bytes is over {}",
            reason.len(),
            taso_core::decider::MAX_DENY_REASON
        ));
    }
    Ok((vessel, op, reason, path))
}

/// The id of the Vessel `arg` names: an id (32 hex) as it is; a
/// configured `subject`; or a fork's name (`<subject>-fork-<n>`), which
/// lives in its parent's namespace.  A name that fits no entry, or
/// entries in two namespaces, is refused: never guessed.
fn vessel_of(config: &Config, arg: &str) -> Result<taso_core::envelope::ChronicleId, String> {
    if arg.len() == 32 {
        if let Some(Subject::Chronicle(id)) = Subject::parse(arg) {
            return Ok(id);
        }
    }
    let parent = arg
        .rsplit_once("-fork-")
        .filter(|(_, n)| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()))
        .map(|(p, _)| p);
    let mut ids: Vec<_> = config
        .vessels
        .iter()
        .filter(|v| v.subject == arg || Some(v.subject.as_str()) == parent)
        .map(|v| taso_core::record::vessel_id(v.namespace, arg.as_bytes()))
        .collect();
    ids.dedup();
    match ids.as_slice() {
        [id] => Ok(*id),
        [] => Err(format!(
            "{arg:?} is not a Vessel of this config, a fork of one, or an id (32 hex)"
        )),
        _ => Err(format!(
            "{arg:?} names Vessels in more than one namespace: give its id (32 hex)"
        )),
    }
}

/// One held action as `proposals` prints it.
fn proposal_json(i: &taso_core::decider::ProposalItem) -> serde_json::Value {
    json!({
        "op": i.intent.op.get(),
        "lsn": i.lsn.get(),
        "provider": i.intent.provider,
        "request_hex": hex(&i.intent.request),
        "request_text": std::str::from_utf8(&i.intent.request).ok(),
        "footprint_hex": hex(&i.intent.footprint),
        "retry": format!("{:?}", i.intent.retry),
        "consequence": format!("{:?}", i.intent.consequence),
        "sealed": i.sealed,
    })
}

fn proposals(args: &[String]) -> ExitCode {
    let (arg, path) = match vessel_args(args) {
        Ok(a) => a,
        Err(e) => return usage(&e),
    };
    let config = match read_config(path) {
        Ok(c) => c,
        Err(e) => return usage(&format!("{path}: {e}")),
    };
    let vessel = match vessel_of(&config, arg) {
        Ok(v) => v,
        Err(e) => return usage(&e),
    };
    let socket = &config.decider.socket;
    let answer = taso_warden::decidesrv::DeciderClient::connect(socket)
        .map_err(|e| format!("the Warden's decider socket {}: {e}", socket.display()))
        .and_then(|mut c| c.proposals_all(vessel));
    match answer {
        Ok((items, last_seal)) => {
            for i in &items {
                println!("{}", proposal_json(i));
            }
            println!(
                "{}",
                json!({
                    "vessel": hex(vessel.as_bytes()),
                    "held": items.len(),
                    "last_seal": last_seal.map(|l| l.get()),
                })
            );
            ExitCode::SUCCESS
        }
        Err(why) => {
            println!(
                "{}",
                json!({"vessel": hex(vessel.as_bytes()), "error": why})
            );
            ExitCode::from(1)
        }
    }
}

/// What `approve` and `deny` print for the Warden's answer, and whether
/// the decision is taken.
fn decision_json(
    vessel: &taso_core::envelope::ChronicleId,
    op: u64,
    approval: bool,
    answer: &Result<taso_warden::decidesrv::Ruled, String>,
) -> (serde_json::Value, bool) {
    use taso_warden::decidesrv::Ruled;
    let mut j = json!({"vessel": hex(vessel.as_bytes()), "op": op});
    let taken = match answer {
        Ok(Ruled::Done { before }) => {
            j[if approval { "approved" } else { "denied" }] = json!(true);
            j["before"] = json!(before);
            true
        }
        Ok(Ruled::Refused(why)) => {
            j["refused"] = json!(why);
            false
        }
        Err(why) => {
            j["error"] = json!(why);
            false
        }
    };
    (j, taken)
}

fn decide(args: &[String], approval: bool) -> ExitCode {
    use taso_warden::decidesrv::{DeciderClient, Ruling};
    let (arg, op, reason, path) = match decide_args(args, approval) {
        Ok(a) => a,
        Err(e) => return usage(&e),
    };
    let config = match read_config(path) {
        Ok(c) => c,
        Err(e) => return usage(&format!("{path}: {e}")),
    };
    let vessel = match vessel_of(&config, arg) {
        Ok(v) => v,
        Err(e) => return usage(&e),
    };
    let ruling = if approval {
        Ruling::Approve
    } else {
        Ruling::Deny(reason)
    };
    let socket = &config.decider.socket;
    let answer = DeciderClient::connect(socket)
        .map_err(|e| format!("the Warden's decider socket {}: {e}", socket.display()))
        .and_then(|mut c| c.decide(vessel, op, &ruling));
    let (line, taken) = decision_json(&vessel, op, approval, &answer);
    println!("{line}");
    if taken {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

// ── demo ──────────────────────────────────────────────────────────────

/// The demo Vessel's subject, and its namespace (32 hex: any fixed value;
/// the id is derived from both).
const DEMO_SUBJECT: &str = "demo";
const DEMO_NAMESPACE: &str = "de0de0de0de0de0de0de0de0de0de0de";

/// The demo Vessel's entry: `taso-sim` turns and one fork (K-d).
fn demo_entry() -> serde_json::Value {
    json!({
        "namespace": DEMO_NAMESPACE,
        "subject": DEMO_SUBJECT,
        "uid_slot": 1,
        "forks": {"slots": [2]},
        "runtime": {"args": [
            "/usr/bin/taso-sim", "--turns", "20", "--txns", "4", "--rows", "8",
            "--row-bytes", "256", "--synchronous", "normal", "--forks", "1",
            "--stats", "/work/sim-stats.json",
        ]},
    })
}

/// The config with the demo Vessel added, checked as the Warden reads it;
/// `Ok(None)`: it is there already.  `Err`: why not, and what to do.
fn add_demo(text: &str) -> Result<Option<String>, String> {
    let mut v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    let rootfs = v
        .pointer("/runtime/rootfs")
        .and_then(|r| r.as_str())
        .map(str::to_owned);
    if rootfs.is_none() {
        return Err(
            "the config names no rootfs for the agents: unpack the demo-agent image \
                    (README, Install on one machine) and run `taso-ctl init --rootfs DIR --force`"
                .into(),
        );
    }
    let vessels = v
        .get_mut("vessels")
        .and_then(|x| x.as_array_mut())
        .ok_or("the config has no \"vessels\" list")?;
    if vessels
        .iter()
        .any(|e| e.get("subject").and_then(|s| s.as_str()) == Some(DEMO_SUBJECT))
    {
        return Ok(None);
    }
    vessels.push(demo_entry());
    let out = serde_json::to_string_pretty(&v).expect("a JSON value prints") + "\n";
    Config::parse(&out).map_err(|e| format!("the Warden would refuse it: {e}"))?;
    Ok(Some(out))
}

fn demo(args: &[String]) -> ExitCode {
    let path = match args {
        [] => PathBuf::from(CONFIG),
        [flag, p] if flag == "--config" => PathBuf::from(p),
        _ => return usage("demo takes only --config PATH"),
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "taso-ctl demo: {}: {e} (run `taso-ctl init` first)",
                path.display()
            );
            return ExitCode::from(2);
        }
    };
    let out = match add_demo(&text) {
        Ok(Some(out)) => out,
        Ok(None) => {
            println!(
                "taso-ctl demo: the demo Vessel is already in {}: nothing changed.",
                path.display()
            );
            return ExitCode::SUCCESS;
        }
        Err(why) => {
            eprintln!("taso-ctl demo: {}: {why}", path.display());
            return ExitCode::from(2);
        }
    };
    // Whole or not at all: a temporary file beside it, renamed over it.
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, &out).and_then(|()| std::fs::rename(&tmp, &path)) {
        let _ = std::fs::remove_file(&tmp);
        eprintln!("taso-ctl demo: {}: {e}", path.display());
        return ExitCode::from(1);
    }
    println!(
        "taso-ctl demo: the demo Vessel added to {} (subject \"{DEMO_SUBJECT}\": 20 turns, one fork). \
         Start the block log, then the Warden, as `taso-ctl init` printed.",
        path.display()
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn chmod(p: &Path, m: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }

    /// Audit 2026-11-16, S1: `init`'s directories were made with the
    /// default mode.  Now `state`, `store` and `spool` are the owner's
    /// alone, and `data` and `mnt` let others pass (an agent's mapped uids
    /// reach its mount through them) but not list, exactly, whatever the
    /// umask; a parent `--data` needs is made passable too.  Nothing is
    /// said for a new layout.
    #[test]
    fn init_makes_the_data_directories_private() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("new/taso");
        let mut said = Vec::new();
        make_data_dirs(&data, |l| said.push(l.to_string())).unwrap();
        assert!(said.is_empty(), "{said:?}");
        assert_eq!(mode(&dir.path().join("new")) & 0o007, 0o001);
        for (d, want) in [
            ("", 0o711),
            ("state", 0o700),
            ("store", 0o700),
            ("spool", 0o700),
            ("mnt", 0o711),
        ] {
            assert_eq!(mode(&data.join(d)), want, "{d:?}");
        }
    }

    /// Audit 2026-11-16, S1 (D&D S1-a b): on a host set up before, `init`
    /// only takes away what others have beyond each directory's mode,
    /// keeps the owner's and the group's, and says each change; run again
    /// it has nothing to say.
    #[test]
    fn init_takes_others_access_away_from_an_old_layout() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("taso");
        for d in ["state", "store", "spool", "mnt"] {
            std::fs::create_dir_all(data.join(d)).unwrap();
        }
        chmod(&data, 0o755);
        chmod(&data.join("state"), 0o775);
        chmod(&data.join("store"), 0o755);
        chmod(&data.join("spool"), 0o750);
        chmod(&data.join("mnt"), 0o755);
        let mut said = Vec::new();
        make_data_dirs(&data, |l| said.push(l.to_string())).unwrap();
        for (d, want) in [
            ("", 0o751),
            ("state", 0o770),
            ("store", 0o750),
            ("spool", 0o750),
            ("mnt", 0o751),
        ] {
            assert_eq!(mode(&data.join(d)), want, "{d:?}");
        }
        assert_eq!(said.len(), 4, "spool had nothing to take: {said:?}");
        assert!(said[0].contains("755 -> 751"), "{said:?}");
        let mut again = Vec::new();
        make_data_dirs(&data, |l| again.push(l.to_string())).unwrap();
        assert!(again.is_empty(), "{again:?}");
    }

    /// Audit 2026-11-09, `init` made the block log's socket directory under
    /// `/run`, which a reboot empties, and nothing made it again at boot.
    /// It is kept by a tmpfiles.d entry, for both run directories.
    #[test]
    fn the_run_directories_are_kept_at_boot() {
        assert_eq!(
            run_conf(),
            "d /run/taso 0755 root root -\nd /run/taso/run 0755 root root -\n"
        );
        // The block log's socket is in the first.
        assert_eq!(
            PathBuf::from(RUN).join("blk.sock").parent(),
            Some(run_dirs()[0].as_path())
        );
    }

    /// Review fix M5 (Kimi's M5): the first failing step stops the rest,
    /// and the error names what was already done.
    #[test]
    fn a_failing_step_stops_the_rest_and_names_what_was_done() {
        let ran = std::cell::RefCell::new(Vec::new());
        let mut steps: Vec<Step> = vec![
            (
                "one",
                Box::new(|| {
                    ran.borrow_mut().push(1);
                    Ok(())
                }),
            ),
            (
                "two",
                Box::new(|| {
                    ran.borrow_mut().push(2);
                    Err("no module".into())
                }),
            ),
            (
                "three",
                Box::new(|| {
                    ran.borrow_mut().push(3);
                    Ok(())
                }),
            ),
        ];
        let mut said = Vec::new();
        let e = run_steps(&mut steps, |w| said.push(w.to_string())).unwrap_err();
        drop(steps);
        assert_eq!(*ran.borrow(), [1, 2], "the third never ran");
        assert_eq!(said, ["one"]);
        assert!(e.starts_with("two: no module"), "{e}");
        assert!(e.contains("done before it, and left: one"), "{e}");
        let mut first: Vec<Step> = vec![("only", Box::new(|| Err("x".into())))];
        let e = run_steps(&mut first, |_| {}).unwrap_err();
        assert!(e.contains("nothing was changed before it"), "{e}");
    }

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
            assert_eq!(c.storage.socket, Path::new("/run/taso/blk.sock"));
            assert!(matches!(&c.coordinator, CoordConf::Local { .. }));
        }
    }

    /// Review fix M3: `status` says the agents' limits, \"unlimited\"
    /// when none is set, and each Vessel that sets its own.
    #[test]
    fn status_says_the_agents_limits() {
        let a = InitArgs {
            data: PathBuf::from("/var/lib/taso"),
            size_gib: 64,
            rootfs: Some(PathBuf::from("/srv/agent-rootfs")),
            force: false,
        };
        let c = Config::parse(&init_config(&a, false)).unwrap();
        assert_eq!(
            agent_limits(&c),
            "agent limits: memory unlimited, processes unlimited (runtime.memory_bytes, runtime.pids)"
        );
        let mut v: serde_json::Value = serde_json::from_str(&init_config(&a, false)).unwrap();
        v["runtime"]["pids"] = serde_json::json!(512);
        let mut e = demo_entry();
        e["runtime"]["memory_bytes"] = serde_json::json!(268_435_456u64);
        v["vessels"] = serde_json::json!([e]);
        let c = Config::parse(&v.to_string()).unwrap();
        assert_eq!(
            agent_limits(&c),
            "agent limits: memory unlimited, processes 512 (runtime.memory_bytes, runtime.pids); demo: memory 256 MiB, processes 512"
        );
    }

    /// 4a: a Vessel is named by its subject, a fork's name or its id;
    /// anything else is refused, never guessed.
    #[test]
    fn a_vessel_is_named_by_subject_fork_name_or_id() {
        use taso_core::record::vessel_id;
        let a = init_args(&["--rootfs".into(), "/srv/rootfs".into()]).unwrap();
        let text = add_demo(&init_config(&a, false)).unwrap().unwrap();
        let config = Config::parse(&text).unwrap();
        let ns = config.vessels[0].namespace;
        let demo = vessel_id(ns, DEMO_SUBJECT.as_bytes());
        assert_eq!(vessel_of(&config, DEMO_SUBJECT), Ok(demo));
        assert_eq!(vessel_of(&config, &hex(demo.as_bytes())), Ok(demo));
        assert_eq!(
            vessel_of(&config, "demo-fork-11"),
            Ok(vessel_id(ns, b"demo-fork-11"))
        );
        for bad in ["other", "other-fork-1", "demo-fork-", "demo-fork-x", ""] {
            assert!(vessel_of(&config, bad).is_err(), "{bad:?}");
        }
        let s = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(vessel_args(&s(&["demo"])), Ok(("demo", CONFIG)));
        assert_eq!(
            vessel_args(&s(&["demo", "--config", "/c"])),
            Ok(("demo", "/c"))
        );
        assert_eq!(
            vessel_args(&s(&["--config", "/c", "demo"])),
            Ok(("demo", "/c"))
        );
        assert!(vessel_args(&s(&[])).is_err());
        assert!(vessel_args(&s(&["demo", "extra"])).is_err());
    }

    /// Approve, Deny: the command line (the reason is the words after
    /// the op; an approval takes none; `--config` anywhere) and the line
    /// printed for each of the Warden's answers.
    #[test]
    fn decisions_are_parsed_and_printed() {
        use taso_warden::decidesrv::Ruled;
        let s = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            decide_args(&s(&["demo", "7"]), true),
            Ok(("demo", 7, "no reason given".into(), CONFIG))
        );
        assert_eq!(
            decide_args(
                &s(&["--config", "/c", "demo", "7", "not", "on the list"]),
                false
            ),
            Ok(("demo", 7, "not on the list".into(), "/c"))
        );
        assert_eq!(
            decide_args(&s(&["demo", "7", "why", "--config", "/c"]), false),
            Ok(("demo", 7, "why".into(), "/c"))
        );
        for (bad, approval) in [
            (s(&["demo"]), true),
            (s(&["demo", "seven"]), true),
            (s(&["demo", "7", "extra"]), true),
            (s(&["demo", "7", "--config"]), false),
            (s(&["demo", "7", &"x".repeat(1025)]), false),
        ] {
            assert!(decide_args(&bad, approval).is_err(), "{bad:?}");
        }
        let v = taso_core::envelope::ChronicleId::from_bytes([5; 16]);
        let (j, taken) = decision_json(&v, 7, true, &Ok(Ruled::Done { before: false }));
        assert!(taken);
        assert_eq!(j["approved"], true);
        assert_eq!(j["before"], false);
        assert_eq!(j["op"], 7);
        assert_eq!(j["vessel"], "05".repeat(16));
        let (j, taken) = decision_json(&v, 7, false, &Ok(Ruled::Done { before: true }));
        assert!(taken && j["denied"] == true && j["before"] == true && j["approved"].is_null());
        let (j, taken) = decision_json(&v, 7, true, &Ok(Ruled::Refused("not sealed".into())));
        assert!(!taken && j["refused"] == "not sealed" && j["error"].is_null());
        let (j, taken) = decision_json(&v, 7, true, &Err("ask again".into()));
        assert!(!taken && j["error"] == "ask again" && j["refused"].is_null());
    }

    /// 4a: a held action is printed with its exact request bytes, and as
    /// text only when they are text.
    #[test]
    fn a_held_action_prints_its_exact_request() {
        use taso_core::decider::ProposalItem;
        use taso_core::envelope::Lsn;
        use taso_core::record::{Consequence, Dispatch, IntentRecord, OpId, RetryPolicy};
        let mut i = ProposalItem {
            lsn: Lsn::new(12),
            intent: IntentRecord {
                op: OpId::new(3),
                provider: "fetch".into(),
                request: b"https://example.org/a".to_vec(),
                footprint: b"web".to_vec(),
                dispatch: Dispatch::Immediate,
                retry: RetryPolicy::UnsafeToRetry,
                consequence: Consequence::Irreversible,
                authority: Vec::new(),
                barrier: None,
            },
            sealed: true,
        };
        let j = proposal_json(&i);
        assert_eq!(j["op"], 3);
        assert_eq!(j["lsn"], 12);
        assert_eq!(j["request_text"], "https://example.org/a");
        assert_eq!(j["request_hex"], hex(b"https://example.org/a"));
        assert_eq!(j["footprint_hex"], "776562");
        assert_eq!(j["sealed"], true);
        i.intent.request = vec![0xff, 0x00];
        let j = proposal_json(&i);
        assert_eq!(j["request_hex"], "ff00");
        assert!(j["request_text"].is_null());
    }

    #[test]
    fn init_args_are_checked() {
        assert!(init_args(&["--size-gib".into(), "0".into()]).is_err());
        assert!(init_args(&["--data".into(), "relative".into()]).is_err());
        assert!(init_args(&["--bogus".into()]).is_err());
        let a = init_args(&["--data".into(), "/srv/taso".into(), "--force".into()]).unwrap();
        assert!(a.force && a.data == Path::new("/srv/taso") && a.size_gib == 64);
    }

    /// `demo` adds one entry the Warden accepts, refuses a config with no
    /// rootfs, and changes nothing the second time (K-d).
    #[test]
    fn demo_adds_one_entry_the_warden_accepts() {
        let mut a = InitArgs {
            data: PathBuf::from("/var/lib/taso"),
            size_gib: 64,
            rootfs: None,
            force: false,
        };
        let err = add_demo(&init_config(&a, true)).unwrap_err();
        assert!(err.contains("--rootfs"), "{err}");
        a.rootfs = Some(PathBuf::from("/var/lib/taso/agent"));
        let out = add_demo(&init_config(&a, true)).unwrap().expect("added");
        let c = Config::parse(&out).unwrap();
        assert_eq!(c.vessels.len(), 1);
        let v = &c.vessels[0];
        assert_eq!((v.subject.as_str(), v.uid_slot), (DEMO_SUBJECT, 1));
        assert_eq!(v.forks.as_ref().map(|f| f.slots.clone()), Some(vec![2]));
        let args = v
            .runtime
            .as_ref()
            .and_then(|r| r.args.as_ref())
            .expect("its own command line");
        assert_eq!(args[0], "/usr/bin/taso-sim");
        assert!(args.windows(2).any(|w| w == ["--forks", "1"]));
        assert_eq!(add_demo(&out).unwrap(), None, "already there");
    }

    #[test]
    fn demo_refuses_what_is_not_a_config() {
        assert!(add_demo("not json").is_err());
        assert!(add_demo(r#"{"runtime": {"rootfs": "/srv/a"}}"#).is_err());
    }

    /// C3-i: deploy/docker/warden.json, the Warden's config in compose, is
    /// what `init` and then `demo` write, with the container's paths (the
    /// data under /var/lib/taso, the agent at /srv/taso/agent with the
    /// shim) and one difference: taso-blkd's socket is in /run/taso-blk,
    /// the volume compose shares between the two containers.  A key renamed
    /// or a demo changed here fails this test, not a later `compose up`.
    #[test]
    fn the_compose_config_is_what_init_and_demo_write() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/docker/warden.json");
        let text = std::fs::read_to_string(&path).expect("deploy/docker/warden.json");
        Config::parse(&text).expect("the Warden reads deploy/docker/warden.json");
        let a = InitArgs {
            data: PathBuf::from("/var/lib/taso"),
            size_gib: 64,
            rootfs: Some(PathBuf::from("/srv/taso/agent")),
            force: false,
        };
        let written = add_demo(&init_config(&a, true)).unwrap().expect("added");
        let mut want: serde_json::Value = serde_json::from_str(&written).unwrap();
        want["storage"]["blk"]["socket"] = json!("/run/taso-blk/blk.sock");
        let got: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            got,
            want,
            "deploy/docker/warden.json differs from init + demo:\n{}",
            serde_json::to_string_pretty(&want).unwrap()
        );
    }

    /// The shim is looked for inside the rootfs, never on the host.
    #[test]
    fn the_landlock_shim_is_looked_for_in_the_rootfs() {
        assert!(!shim_in(None));
        let dir = tempfile::tempdir().unwrap();
        assert!(!shim_in(Some(dir.path())), "an empty rootfs has no shim");
        let shim = dir.path().join("usr/lib/taso/landlock");
        std::fs::create_dir_all(shim.parent().unwrap()).unwrap();
        std::fs::create_dir(&shim).unwrap();
        assert!(!shim_in(Some(dir.path())), "a directory is not the shim");
        std::fs::remove_dir(&shim).unwrap();
        std::fs::write(&shim, b"").unwrap();
        assert!(shim_in(Some(dir.path())));
    }
}
