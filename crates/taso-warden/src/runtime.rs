//! Running a Vessel: OCI-class isolation under runc (v1.0 §3, Phase 1).
//!
//! The spec says what Phase 1 isolation is, and says it plainly: user
//! namespace, seccomp, Landlock on the dataset path, a network namespace
//! whose only route is the Field socket, no credentials.  This module
//! turns that into an OCI runtime `config.json` ([`oci_config`]) and drives
//! `runc` ([`Runc`]).
//!
//! # What the Vessel gets
//!
//! - **Its own user namespace.**  Root inside maps to an unprivileged host
//!   range (`host_uid_base .. +65536`); no capabilities in any set;
//!   `noNewPrivileges`.
//! - **Its own pid, ipc, uts, mount, cgroup and network namespaces.**  The
//!   network namespace is new and empty: not even an interface to bring up
//!   beyond `lo`.  The only way to the world is the Field socket,
//!   bind-mounted at [`FIELD_SOCKET`].
//! - **A read-only root filesystem.**  Writable: `/work` (the Vessel's
//!   dataset, bind-mounted, `nosuid,nodev`) and `/tmp` (tmpfs).
//! - **No host environment.**  The process gets `PATH`, `HOME=/work` and
//!   `TASO_FIELD`; nothing from the Warden's environment, so no
//!   credentials can leak in.
//! - **seccomp**: default allow, with an explicit deny list of syscalls an
//!   agent never needs and that widen the attack surface (namespaces and
//!   mounts, kernel modules, BPF, ptrace and cross-process memory, keyring,
//!   clock and reboot).  Phase 3 hardens further; this is the pilot's
//!   threat model (v1.0 §3).
//! - **Landlock** is not part of the OCI spec and runc does not apply it.
//!   If [`VesselSpec::landlock_shim`] is set, the shim (a binary in the
//!   rootfs) runs first, restricts writes to `/work` and `/tmp`, and execs
//!   the agent.  The shim is the `taso-landlock` crate; it refuses to run
//!   the agent on a kernel without Landlock.
//!
//! The dataset must be owned by the mapped root so the agent can write it:
//! [`prepare_work_dir`].  A fork or succession into another uid slot keeps
//! its parent's files untouched on disk; its `/work` is an idmapped mount
//! that shows the parent's range as its own ([`VesselSpec::disk_uid_base`],
//! fencing review F6).
//!
//! The image must already contain every mount target ([`check_rootfs`]):
//! inside a user namespace runc creates mount targets as the Vessel's
//! unprivileged root, which cannot write into a host-owned, read-only
//! image — so a missing `/run/taso/field.sock` fails the start.
//!
//! Normative references: v1.0 §3 (isolation rules), §7 (negative space).

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

/// Where the Field socket appears inside the Vessel.
pub const FIELD_SOCKET: &str = "/run/taso/field.sock";

/// Where the Vessel's dataset appears inside the Vessel.
pub const WORK_DIR: &str = "/work";

/// Size of each Vessel's uid/gid range.
pub const ID_RANGE: u32 = 65536;

/// Syscalls refused with `EPERM`.
pub const DENIED_SYSCALLS: &[&str] = &[
    // namespaces and mounts
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    "unshare",
    "setns",
    "mount_setattr",
    "move_mount",
    "open_tree",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    // kernel modules, kexec, BPF, perf
    "init_module",
    "finit_module",
    "delete_module",
    "kexec_load",
    "kexec_file_load",
    "bpf",
    "perf_event_open",
    // other processes' memory
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "kcmp",
    // kernel keyring
    "keyctl",
    "add_key",
    "request_key",
    // host-wide state
    "reboot",
    "swapon",
    "swapoff",
    "settimeofday",
    "clock_settime",
    "clock_adjtime",
    "adjtimex",
    "acct",
    "quotactl",
    "syslog",
    "vhangup",
    "iopl",
    "ioperm",
    // handles that escape mounts, fault handling across processes
    "open_by_handle_at",
    "name_to_handle_at",
    "userfaultfd",
    "lookup_dcookie",
];

/// Everything needed to run one Vessel.
#[derive(Clone, Debug)]
pub struct VesselSpec {
    /// The runc container id (the Vessel id in hex).
    pub id: String,
    /// The image's root filesystem, mounted read-only.
    pub rootfs: PathBuf,
    /// The Vessel's dataset mountpoint, bound at [`WORK_DIR`].
    pub work: PathBuf,
    /// The Vessel's Field socket on the host, bound at [`FIELD_SOCKET`].
    pub socket: PathBuf,
    /// First host uid/gid of the Vessel's range.
    pub host_uid_base: u32,
    /// First host uid/gid of the range that owns the files of `work` on
    /// disk, when it is not the Vessel's own: a fork or succession into
    /// another `uid_slot` keeps its parent's files as they are, and the
    /// work mount is idmapped to show them in this Vessel's range
    /// ([`oci_config`]).  `None`, or `Some(host_uid_base)`: the files are
    /// already the Vessel's own; no idmapping.
    pub disk_uid_base: Option<u32>,
    /// The agent's command line.
    pub args: Vec<String>,
    /// Extra environment, `KEY=value`.  Never the Warden's own.
    pub env: Vec<String>,
    /// A Landlock shim inside the rootfs that runs before `args`.
    pub landlock_shim: Option<String>,
    /// Memory limit in bytes.
    pub memory_bytes: Option<u64>,
    /// Maximum number of processes.
    pub pids: Option<u64>,
}

/// Why a spec cannot be turned into a config.
#[derive(Debug, PartialEq, Eq)]
pub enum SpecError {
    /// The container id is not `[a-zA-Z0-9_.-]{1,128}`.
    BadId(String),
    /// A host path is not absolute.
    NotAbsolute(PathBuf),
    /// No command line.
    NoArgs,
    /// The uid range would wrap or start at 0.
    BadUidRange(u32),
    /// An environment entry is not `KEY=value`, or sets a reserved key.
    BadEnv(String),
}

impl fmt::Display for SpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadId(id) => write!(f, "invalid container id {id:?}"),
            Self::NotAbsolute(p) => write!(f, "{} is not an absolute path", p.display()),
            Self::NoArgs => write!(f, "no command line"),
            Self::BadUidRange(b) => write!(f, "uid range starting at {b} is not usable"),
            Self::BadEnv(e) => write!(f, "invalid environment entry {e:?}"),
        }
    }
}

impl std::error::Error for SpecError {}

const RESERVED_ENV: &[&str] = &["PATH", "HOME", "TASO_FIELD"];

/// The OCI runtime `config.json` for `spec`.
pub fn oci_config(spec: &VesselSpec) -> Result<Value, SpecError> {
    let id_ok = !spec.id.is_empty()
        && spec.id.len() <= 128
        && spec
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    if !id_ok {
        return Err(SpecError::BadId(spec.id.clone()));
    }
    for p in [&spec.rootfs, &spec.work, &spec.socket] {
        if !p.is_absolute() {
            return Err(SpecError::NotAbsolute(p.clone()));
        }
    }
    if spec.args.is_empty() {
        return Err(SpecError::NoArgs);
    }
    let usable = |base: u32| base != 0 && base.checked_add(ID_RANGE).is_some();
    if !usable(spec.host_uid_base) {
        return Err(SpecError::BadUidRange(spec.host_uid_base));
    }
    // The range the work directory's files are owned by on disk, if not the
    // Vessel's own.  It must be a whole other range: one that partly
    // overlaps the Vessel's would show some of its own ids as other ids.
    let disk_uid_base = match spec.disk_uid_base {
        Some(d) if d != spec.host_uid_base => {
            if !usable(d) || d.abs_diff(spec.host_uid_base) < ID_RANGE {
                return Err(SpecError::BadUidRange(d));
            }
            Some(d)
        }
        _ => None,
    };
    for e in &spec.env {
        let key = e.split_once('=').map(|(k, _)| k);
        let ok = key.is_some_and(|k| {
            !k.is_empty()
                && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && !RESERVED_ENV.contains(&k)
        });
        if !ok {
            return Err(SpecError::BadEnv(e.clone()));
        }
    }

    let mut args: Vec<String> = Vec::new();
    if let Some(shim) = &spec.landlock_shim {
        args.push(shim.clone());
        args.push("--".into());
    }
    args.extend(spec.args.iter().cloned());

    let mut env = vec![
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        format!("HOME={WORK_DIR}"),
        format!("TASO_FIELD={FIELD_SOCKET}"),
    ];
    env.extend(spec.env.iter().cloned());

    let mut work_mount = json!({ "destination": WORK_DIR, "type": "bind", "source": spec.work,
                                 "options": ["rbind", "rw", "nosuid", "nodev"] });
    if let Some(disk) = disk_uid_base {
        // Show the disk's range as the Vessel's, nothing on disk changed
        // (fencing review F6).  In a mount mapping `containerID` is the id
        // on disk and `hostID` the id the mount shows: the kernel's
        // idmappings.rst ("u1000:k1125" shows disk 1000 as 1125) and runc,
        // which puts both fields unchanged into the namespace it hands to
        // `mount_setattr(MOUNT_ATTR_IDMAP)`.  Ids outside the disk range
        // (e.g. host root's) stay unmapped: shown as the overflow id, not
        // writable as.  `ridmap`: recursive like the `rbind`, and named so a
        // runtime without idmapped mounts fails instead of ignoring it.
        let map = json!([{ "containerID": disk, "hostID": spec.host_uid_base, "size": ID_RANGE }]);
        work_mount["options"]
            .as_array_mut()
            .expect("options is an array")
            .push(json!("ridmap"));
        work_mount["uidMappings"] = map.clone();
        work_mount["gidMappings"] = map;
    }

    let no_caps = json!([]);
    let mut resources = json!({ "devices": [{ "allow": false, "access": "rwm" }] });
    if let Some(m) = spec.memory_bytes {
        resources["memory"] = json!({ "limit": m, "swap": m });
    }
    if let Some(p) = spec.pids {
        resources["pids"] = json!({ "limit": p });
    }

    Ok(json!({
        "ociVersion": "1.2.0",
        "hostname": format!("vessel-{}", &spec.id[..spec.id.len().min(12)]),
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "args": args,
            "env": env,
            "cwd": WORK_DIR,
            "noNewPrivileges": true,
            "capabilities": {
                "bounding": no_caps, "effective": no_caps, "inheritable": no_caps,
                "permitted": no_caps, "ambient": no_caps
            },
            "rlimits": [{ "type": "RLIMIT_NOFILE", "hard": 4096, "soft": 4096 }]
        },
        "root": { "path": spec.rootfs, "readonly": true },
        "mounts": [
            { "destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"] },
            { "destination": "/dev", "type": "tmpfs", "source": "tmpfs",
              "options": ["nosuid", "strictatime", "mode=755", "size=65536k"] },
            { "destination": "/dev/pts", "type": "devpts", "source": "devpts",
              "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"] },
            { "destination": "/dev/shm", "type": "tmpfs", "source": "shm",
              "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"] },
            { "destination": "/dev/mqueue", "type": "mqueue", "source": "mqueue",
              "options": ["nosuid", "noexec", "nodev"] },
            { "destination": "/sys", "type": "none", "source": "/sys",
              "options": ["rbind", "nosuid", "noexec", "nodev", "ro"] },
            { "destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
              "options": ["nosuid", "nodev", "mode=1777", "size=1g"] },
            work_mount,
            { "destination": FIELD_SOCKET, "type": "bind", "source": spec.socket,
              "options": ["bind", "rw", "nosuid", "nodev", "noexec"] }
        ],
        "linux": {
            "namespaces": [
                { "type": "pid" }, { "type": "network" }, { "type": "ipc" }, { "type": "uts" },
                { "type": "mount" }, { "type": "user" }, { "type": "cgroup" }
            ],
            "uidMappings": [{ "containerID": 0, "hostID": spec.host_uid_base, "size": ID_RANGE }],
            "gidMappings": [{ "containerID": 0, "hostID": spec.host_uid_base, "size": ID_RANGE }],
            "resources": resources,
            "seccomp": {
                "defaultAction": "SCMP_ACT_ALLOW",
                "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"],
                "syscalls": [{ "names": DENIED_SYSCALLS, "action": "SCMP_ACT_ERRNO", "errnoRet": 1 }]
            },
            "maskedPaths": [
                "/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
                "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi",
                "/sys/firmware", "/sys/devices/virtual/powercap"
            ],
            "readonlyPaths": [
                "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"
            ]
        }
    }))
}

/// Directories every Vessel image must contain.
pub const REQUIRED_DIRS: &[&str] = &["proc", "dev", "sys", "tmp", "work", "run/taso"];

/// Files every Vessel image must contain (bind-mount targets).
pub const REQUIRED_FILES: &[&str] = &["run/taso/field.sock"];

/// The mount targets `rootfs` is missing (empty if it is usable).
pub fn check_rootfs(rootfs: &Path) -> Vec<String> {
    let mut missing = Vec::new();
    for d in REQUIRED_DIRS {
        if !rootfs.join(d).is_dir() {
            missing.push(format!("/{d}/"));
        }
    }
    for f in REQUIRED_FILES {
        if !rootfs.join(f).is_file() {
            missing.push(format!("/{f}"));
        }
    }
    missing
}

/// Make the dataset mountpoint writable by the Vessel's root (host uid
/// `host_uid_base`): chown the top directory, mode 0750.  Files the agent
/// creates are then owned by its range, never by host root.
///
/// Only if the dataset is this Vessel's.  The top directory's owner is a
/// durable mark of whose it is: it travels with the dataset (`zfs send`
/// keeps owners), so it holds across Warden restarts and nodes, where the
/// source guard's memory does not.  Accepted:
/// - owned by host root (uid and gid 0): a fresh dataset, never prepared
///   (also one rolled back to its birth Seal, which froze it fresh);
/// - owned by exactly `host_uid_base` (uid and gid): prepared before for
///   this Vessel, here or on another node.
///
/// Anything else is refused with `PermissionDenied` and **nothing is
/// changed**: another Vessel's range (a slot that changed, or a dataset that
/// is not this Vessel's), a stray owner, or a fork from a parent in another
/// slot (whose files are the parent's range: see [`work_dir_range`]).  A
/// path that is not a plain directory (a symlink included) is refused with
/// `InvalidInput`.
pub fn prepare_work_dir(work: &Path, host_uid_base: u32) -> io::Result<()> {
    work_dir_range(work, host_uid_base, None).map(|_| ())
}

/// [`prepare_work_dir`] for a Vessel that may run over files of another
/// range, and which range they are: the `disk_uid_base` to run it with
/// ([`VesselSpec::disk_uid_base`]).
///
/// `inherited` is the disk range of the Vessel's lineage when it is a fork
/// or succession (its parent's, checked by the caller against the lineage),
/// `None` for a Vessel born from the void.  The top directory's owner now
/// marks the dataset's **disk range**, set once when it is first prepared
/// and never changed (fencing review F6, decisions D2/D3 of 2026-10-21):
/// - fresh (0:0): prepared into the Vessel's own range as before, mode 0750;
///   returns `host_uid_base`.  A fork of its parent's birth Seal is fresh,
///   so it becomes its own and needs no idmapping;
/// - owned by exactly `host_uid_base`: returns `host_uid_base`, unchanged;
/// - owned by exactly the `inherited` range: returns it, and **nothing on
///   disk is changed** (not the owner, not the mode): the work mount is
///   idmapped instead;
/// - anything else: refused with `PermissionDenied`, nothing changed.
///
/// In the three accepted cases a `lost+found` directory still owned by
/// `0:0` (ext4 on the block log makes it so) is given to the returned
/// range, and nothing else in it ([`own_lost_found`], P4 file 4d).
///
/// An `inherited` range that is 0, wraps, or partly overlaps the Vessel's
/// own is refused with `InvalidInput` before anything is read (the same
/// rule as [`oci_config`]); one equal to `host_uid_base` is the same as
/// `None`.
pub fn work_dir_range(work: &Path, host_uid_base: u32, inherited: Option<u32>) -> io::Result<u32> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let usable = |b: u32| b != 0 && b.checked_add(ID_RANGE).is_some();
    let inherited = match inherited {
        Some(d) if d != host_uid_base => {
            if !usable(d) || d.abs_diff(host_uid_base) < ID_RANGE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "inherited uid range {d} is not usable next to this Vessel's ({host_uid_base})"
                    ),
                ));
            }
            Some(d)
        }
        _ => None,
    };
    let m = std::fs::symlink_metadata(work)?;
    if !m.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is not a directory (a symlink is not accepted)",
                work.display()
            ),
        ));
    }
    let (uid, gid) = (m.uid(), m.gid());
    let is = |b: u32| uid == b && gid == b;
    if let Some(d) = inherited.filter(|d| is(*d)) {
        own_lost_found(work, d)?;
        return Ok(d);
    }
    if !is(0) && !is(host_uid_base) {
        let lineage = match inherited {
            Some(d) => format!(", nor its lineage's ({d})"),
            None => String::new(),
        };
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is owned by {uid}:{gid}, not by this Vessel's range ({host_uid_base}){lineage} nor fresh (0:0): \
                 another Vessel's dataset, or its uid_slot changed; refusing to run it here",
                work.display()
            ),
        ));
    }
    std::os::unix::fs::chown(work, Some(host_uid_base), Some(host_uid_base))?;
    std::fs::set_permissions(work, std::fs::Permissions::from_mode(0o750))?;
    own_lost_found(work, host_uid_base)?;
    Ok(host_uid_base)
}

/// The name of ext4's reserved directory (P4 spec §4.1.6, `fs.reserved`).
pub const LOST_FOUND: &str = "lost+found";

/// Give a `lost+found` that `mkfs` left as `0:0` to the dataset's disk
/// range (P4 file 4d, Jarmo's decision (a), 2026-10-24).  A reserved entry
/// is owned by slot 0 of the range the tree is stored in (spec §4.1.6), so
/// one left at host `0:0` makes every walk of the Vessel's Seals refuse it
/// `ReservedMismatch` (found by `scripts/p4-genesis.sh blk`).  Only the
/// directory itself changes, and only from exactly `0:0`: anything else —
/// absent (ZFS), another owner, not a directory (a symlink is never
/// followed) — is left as it is, for the walk to judge.
fn own_lost_found(work: &Path, range: u32) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let p = work.join(LOST_FOUND);
    match std::fs::symlink_metadata(&p) {
        Ok(m) if m.file_type().is_dir() && m.uid() == 0 && m.gid() == 0 => {
            std::os::unix::fs::lchown(&p, Some(range), Some(range))
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Write `config.json` for `spec` into `bundle` (created if missing).
pub fn write_bundle(bundle: &Path, spec: &VesselSpec) -> Result<PathBuf, BundleError> {
    let config = oci_config(spec).map_err(BundleError::Spec)?;
    std::fs::create_dir_all(bundle).map_err(BundleError::Io)?;
    let path = bundle.join("config.json");
    let text = serde_json::to_vec_pretty(&config).expect("a JSON value serializes");
    std::fs::write(&path, text).map_err(BundleError::Io)?;
    Ok(path)
}

/// Why a bundle could not be written.
#[derive(Debug)]
pub enum BundleError {
    /// The spec is invalid.
    Spec(SpecError),
    /// The file system failed.
    Io(io::Error),
}

// ── runc ────────────────────────────────────────────────────────────

/// What `runc state` reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Created, not started.
    Created,
    /// Running.
    Running,
    /// Stopped.
    Stopped,
    /// Paused.
    Paused,
    /// Anything else runc says.
    Other(String),
}

impl Status {
    fn parse(s: &str) -> Self {
        match s {
            "created" => Status::Created,
            "running" => Status::Running,
            "stopped" => Status::Stopped,
            "paused" => Status::Paused,
            other => Status::Other(other.to_string()),
        }
    }
}

/// What [`Runc::sweep`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Swept {
    /// Containers removed.
    pub deleted: Vec<String>,
    /// Containers that could not be removed, with runc's reason.
    pub failed: Vec<(String, String)>,
}

/// Runs `runc` with arguments; the seam for tests.
pub trait RuncRunner {
    /// Run and return (success, stdout, stderr).
    fn run(&self, args: &[String]) -> io::Result<(bool, String, String)>;
}

/// The real `runc`, with its state under `root`.
#[derive(Clone, Debug)]
pub struct RuncCli {
    program: PathBuf,
    root: PathBuf,
}

impl RuncCli {
    /// `runc` on `PATH`, keeping container state in `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            program: PathBuf::from("runc"),
            root: root.into(),
        }
    }
}

impl RuncRunner for RuncCli {
    fn run(&self, args: &[String]) -> io::Result<(bool, String, String)> {
        // runc creates its root on `run`/`create`, but other subcommands
        // (`list`, at least on runc 1.x) fail on a missing one.  Create it
        // first, as runc would (0700), so an empty root is just empty.
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&self.root)?;
        }
        let out = Command::new(&self.program)
            .arg("--root")
            .arg(&self.root)
            .args(args)
            .output()
            .map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{} not found: is runc installed?", self.program.display()),
                ),
                _ => e,
            })?;
        Ok((
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }
}

/// The runc driver.
pub struct Runc<R: RuncRunner> {
    runner: R,
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

impl<R: RuncRunner> Runc<R> {
    /// A driver over `runner`.
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    fn ok(&self, args: Vec<String>) -> io::Result<String> {
        let (ok, out, err) = self.runner.run(&args)?;
        if ok {
            Ok(out)
        } else {
            Err(io::Error::other(format!(
                "runc {}: {}",
                args.join(" "),
                err.trim()
            )))
        }
    }

    /// Run the container in the foreground until it exits.  Returns whether
    /// it exited successfully and what runc and the agent printed on
    /// stderr (the reason, when it did not).  Used for one-shot Vessels.
    pub fn run(&self, bundle: &Path, id: &str) -> io::Result<(bool, String)> {
        let (ok, _, err) =
            self.runner
                .run(&s(&["run", "--bundle", &bundle.to_string_lossy(), id]))?;
        Ok((ok, err))
    }

    /// Create the container (not started).
    pub fn create(&self, bundle: &Path, id: &str) -> io::Result<()> {
        self.ok(s(&["create", "--bundle", &bundle.to_string_lossy(), id]))
            .map(|_| ())
    }

    /// Start a created container.
    pub fn start(&self, id: &str) -> io::Result<()> {
        self.ok(s(&["start", id])).map(|_| ())
    }

    /// Its status, or `None` if runc does not know it.
    pub fn state(&self, id: &str) -> io::Result<Option<Status>> {
        let (ok, out, err) = self.runner.run(&s(&["state", id]))?;
        if !ok {
            return if err.contains("does not exist") || err.contains("not exist") {
                Ok(None)
            } else {
                Err(io::Error::other(format!("runc state {id}: {}", err.trim())))
            };
        }
        let v: Value = serde_json::from_str(&out)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Some(Status::parse(v["status"].as_str().unwrap_or(""))))
    }

    /// Every container in this runc root, with its status.  runc prints
    /// `null` (or nothing) for an empty or missing root; both are an empty
    /// list.  An entry without a string `id` is an error, not skipped: a
    /// sweep must not miss a container because its entry was odd.
    pub fn list(&self) -> io::Result<Vec<(String, Status)>> {
        let out = self.ok(s(&["list", "--format", "json"]))?;
        let bad =
            |why: String| io::Error::new(io::ErrorKind::InvalidData, format!("runc list: {why}"));
        let v: Value = if out.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&out).map_err(|e| bad(e.to_string()))?
        };
        let entries = match v {
            Value::Null => return Ok(Vec::new()),
            Value::Array(a) => a,
            other => return Err(bad(format!("expected an array, got {other}"))),
        };
        entries
            .iter()
            .map(|e| {
                let id = e["id"]
                    .as_str()
                    .ok_or_else(|| bad(format!("entry without an id: {e}")))?;
                Ok((
                    id.to_string(),
                    Status::parse(e["status"].as_str().unwrap_or("")),
                ))
            })
            .collect()
    }

    /// Remove every container in this runc root, running or not
    /// (`delete --force` kills a running one first).  For a daemon that
    /// holds its run directory's lock: whatever is in its root was left by
    /// a dead incarnation.  Tries every container even when one fails, and
    /// reports both lists.
    pub fn sweep(&self) -> io::Result<Swept> {
        let mut swept = Swept::default();
        for (id, _) in self.list()? {
            match self.delete(&id) {
                Ok(()) => swept.deleted.push(id),
                Err(e) => swept.failed.push((id, e.to_string())),
            }
        }
        Ok(swept)
    }

    /// Send SIGKILL to every process of the container.
    pub fn kill(&self, id: &str) -> io::Result<()> {
        self.ok(s(&["kill", "--all", id, "KILL"])).map(|_| ())
    }

    /// Remove the container (forcibly, if it still runs).
    pub fn delete(&self, id: &str) -> io::Result<()> {
        self.ok(s(&["delete", "--force", id])).map(|_| ())
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn spec() -> VesselSpec {
        VesselSpec {
            id: "ab12cd34".into(),
            rootfs: "/var/lib/taso/images/hermes/rootfs".into(),
            work: "/tasotest/vessel/v-ab12cd34".into(),
            socket: "/run/taso/v/ab12cd34.sock".into(),
            host_uid_base: 200_000,
            disk_uid_base: None,
            args: vec!["/usr/bin/hermes".into(), "--serve".into()],
            env: vec!["HERMES_MODE=agent".into()],
            landlock_shim: None,
            memory_bytes: Some(2 << 30),
            pids: Some(512),
        }
    }

    fn mount<'a>(c: &'a Value, dest: &str) -> &'a Value {
        c["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["destination"] == dest)
            .unwrap()
    }

    #[test]
    fn isolation_rules_are_in_the_config() {
        let c = oci_config(&spec()).unwrap();
        // User namespace with an unprivileged range.
        let ns: Vec<&str> = c["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["type"].as_str().unwrap())
            .collect();
        for want in ["user", "network", "pid", "mount", "ipc", "uts", "cgroup"] {
            assert!(ns.contains(&want), "namespace {want}");
        }
        assert_eq!(c["linux"]["uidMappings"][0]["hostID"], 200_000);
        assert_eq!(c["linux"]["uidMappings"][0]["size"], ID_RANGE);
        // A new network namespace with no path: empty, not the host's.
        let net = c["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["type"] == "network")
            .unwrap();
        assert!(net.get("path").is_none());
        // No capabilities, no new privileges.
        for set in [
            "bounding",
            "effective",
            "inheritable",
            "permitted",
            "ambient",
        ] {
            assert_eq!(c["process"]["capabilities"][set], json!([]), "{set}");
        }
        assert_eq!(c["process"]["noNewPrivileges"], true);
        // Read-only root; writable only /work and /tmp; the socket bound in.
        assert_eq!(c["root"]["readonly"], true);
        assert_eq!(mount(&c, WORK_DIR)["source"], "/tasotest/vessel/v-ab12cd34");
        assert!(mount(&c, WORK_DIR)["options"]
            .as_array()
            .unwrap()
            .contains(&json!("nosuid")));
        assert_eq!(
            mount(&c, FIELD_SOCKET)["source"],
            "/run/taso/v/ab12cd34.sock"
        );
        assert_eq!(c["process"]["cwd"], WORK_DIR);
        // Resources.
        assert_eq!(c["linux"]["resources"]["pids"]["limit"], 512);
        assert_eq!(c["linux"]["resources"]["memory"]["limit"], 2u64 << 30);
    }

    #[test]
    fn seccomp_denies_the_escape_hatches() {
        let c = oci_config(&spec()).unwrap();
        let names: Vec<&str> = c["linux"]["seccomp"]["syscalls"][0]["names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap())
            .collect();
        for must in [
            "mount",
            "unshare",
            "setns",
            "ptrace",
            "bpf",
            "init_module",
            "keyctl",
            "open_by_handle_at",
        ] {
            assert!(names.contains(&must), "{must}");
        }
        assert_eq!(
            c["linux"]["seccomp"]["syscalls"][0]["action"],
            "SCMP_ACT_ERRNO"
        );
    }

    #[test]
    fn environment_is_only_what_the_spec_says() {
        // Built only from the spec: nothing from the Warden's environment.
        let c = oci_config(&spec()).unwrap();
        let env: Vec<&str> = c["process"]["env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e.as_str().unwrap())
            .collect();
        assert_eq!(env.len(), 4);
        assert!(env.contains(&"TASO_FIELD=/run/taso/field.sock"));
        assert!(env.contains(&"HOME=/work"));
        assert!(env.contains(&"HERMES_MODE=agent"));
        assert!(!env
            .iter()
            .any(|e| e.starts_with("UPCLOUD_TOKEN") || e.starts_with("AWS_")));
    }

    #[test]
    fn landlock_shim_runs_first() {
        let mut sp = spec();
        sp.landlock_shim = Some("/usr/lib/taso/landlock".into());
        let c = oci_config(&sp).unwrap();
        assert_eq!(
            c["process"]["args"],
            json!(["/usr/lib/taso/landlock", "--", "/usr/bin/hermes", "--serve"])
        );
    }

    #[test]
    fn invalid_specs_are_refused() {
        type Case = (Box<dyn Fn(&mut VesselSpec)>, fn(&SpecError) -> bool);
        let cases: Vec<Case> = vec![
            (Box::new(|s| s.id = "../x".into()), |e| {
                matches!(e, SpecError::BadId(_))
            }),
            (Box::new(|s| s.id = String::new()), |e| {
                matches!(e, SpecError::BadId(_))
            }),
            (Box::new(|s| s.work = "relative".into()), |e| {
                matches!(e, SpecError::NotAbsolute(_))
            }),
            (Box::new(|s| s.args.clear()), |e| {
                matches!(e, SpecError::NoArgs)
            }),
            (Box::new(|s| s.host_uid_base = 0), |e| {
                matches!(e, SpecError::BadUidRange(_))
            }),
            (Box::new(|s| s.host_uid_base = u32::MAX - 10), |e| {
                matches!(e, SpecError::BadUidRange(_))
            }),
            (Box::new(|s| s.env = vec!["PATH=/evil".into()]), |e| {
                matches!(e, SpecError::BadEnv(_))
            }),
            (Box::new(|s| s.env = vec!["TASO_FIELD=/x".into()]), |e| {
                matches!(e, SpecError::BadEnv(_))
            }),
            (Box::new(|s| s.env = vec!["NOEQUALS".into()]), |e| {
                matches!(e, SpecError::BadEnv(_))
            }),
            (Box::new(|s| s.env = vec!["BAD-KEY=1".into()]), |e| {
                matches!(e, SpecError::BadEnv(_))
            }),
        ];
        for (i, (mutate, is)) in cases.into_iter().enumerate() {
            let mut sp = spec();
            mutate(&mut sp);
            let err = oci_config(&sp).unwrap_err();
            assert!(is(&err), "case {i}: {err:?}");
        }
    }

    /// Slot 1 (the parent, owner of the files on disk) and slot 2 (the
    /// child) over the deploy base 200000, as in `f6-idmap-probe.sh`.
    const SLOT_A: u32 = 200_000 + ID_RANGE;
    const SLOT_B: u32 = 200_000 + 2 * ID_RANGE;

    fn forked() -> VesselSpec {
        let mut sp = spec();
        sp.host_uid_base = SLOT_B;
        sp.disk_uid_base = Some(SLOT_A);
        sp
    }

    #[test]
    fn work_mount_is_idmapped_across_slots() {
        let c = oci_config(&forked()).unwrap();
        let w = mount(&c, WORK_DIR);
        // Direction, from the sources (verified 2026-10-21, not assumed):
        // - kernel Documentation/filesystems/idmappings.rst: the mount
        //   idmapping u1000:k1125:r1 shows a file owned by 1000 on disk as
        //   1125 — the namespace side is the disk, the kernel side is what
        //   the mount shows;
        // - runc v1.4.0 specconv toConfigIDMap + internal/userns: the OCI
        //   containerID/hostID go unchanged into that namespace's uid_map.
        // So containerID = the disk's range (A), hostID = the shown range (B).
        let want = json!([{ "containerID": SLOT_A, "hostID": SLOT_B, "size": ID_RANGE }]);
        assert_eq!(w["uidMappings"], want);
        assert_eq!(w["gidMappings"], want);
        // Explicit and recursive, matching rbind (runc applies mappings
        // without the option non-recursively; the spec says SHOULD name it).
        let opts = w["options"].as_array().unwrap();
        assert!(opts.contains(&json!("ridmap")), "{opts:?}");
        assert!(!opts.contains(&json!("idmap")), "{opts:?}");
        // Still a bind mount (runc refuses idmapping on anything else),
        // still nosuid,nodev.
        for o in ["rbind", "rw", "nosuid", "nodev"] {
            assert!(opts.contains(&json!(o)), "{o}: {opts:?}");
        }
        // The container's own user namespace is unchanged: the child's range.
        assert_eq!(c["linux"]["uidMappings"][0]["hostID"], SLOT_B);
        assert_eq!(c["linux"]["gidMappings"][0]["hostID"], SLOT_B);
        // Nothing else is idmapped.
        for m in c["mounts"].as_array().unwrap() {
            if m["destination"] != WORK_DIR {
                assert!(m.get("uidMappings").is_none(), "{m}");
                assert!(m.get("gidMappings").is_none(), "{m}");
            }
        }
    }

    #[test]
    fn work_mount_is_plain_within_a_slot() {
        // None and Some(own base) both mean "the files are mine": the config
        // is byte-for-byte what it was before F6.
        let plain = oci_config(&spec()).unwrap();
        let mut same = spec();
        same.disk_uid_base = Some(same.host_uid_base);
        assert_eq!(oci_config(&same).unwrap(), plain);
        let w = mount(&plain, WORK_DIR);
        assert!(w.get("uidMappings").is_none());
        assert!(w.get("gidMappings").is_none());
        assert_eq!(w["options"], json!(["rbind", "rw", "nosuid", "nodev"]));
    }

    #[test]
    fn bad_disk_ranges_are_refused() {
        // 0 (host root's files), a wrapping range, and a range that partly
        // overlaps the Vessel's own (not a slot apart: a misconfiguration
        // that would show some of the child's own ids as other ids).
        for disk in [0, u32::MAX - 10, SLOT_B - 1, SLOT_B + ID_RANGE - 1] {
            let mut sp = forked();
            sp.disk_uid_base = Some(disk);
            assert_eq!(
                oci_config(&sp).unwrap_err(),
                SpecError::BadUidRange(disk),
                "disk base {disk}"
            );
        }
        // Exactly one slot apart either way is fine.
        for disk in [SLOT_B - ID_RANGE, SLOT_B + ID_RANGE] {
            let mut sp = forked();
            sp.disk_uid_base = Some(disk);
            assert!(oci_config(&sp).is_ok(), "disk base {disk}");
        }
    }

    #[test]
    fn rootfs_must_provide_mount_targets() {
        let dir = tempfile::tempdir().unwrap();
        let missing = check_rootfs(dir.path());
        assert!(missing.contains(&"/work/".to_string()));
        assert!(missing.contains(&"/run/taso/field.sock".to_string()));
        for d in REQUIRED_DIRS {
            std::fs::create_dir_all(dir.path().join(d)).unwrap();
        }
        assert_eq!(
            check_rootfs(dir.path()),
            vec!["/run/taso/field.sock".to_string()]
        );
        std::fs::write(dir.path().join("run/taso/field.sock"), b"").unwrap();
        assert!(check_rootfs(dir.path()).is_empty());
    }

    #[test]
    fn bundle_is_written_as_json_runc_can_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_bundle(&dir.path().join("b"), &spec()).unwrap();
        let back: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(back, oci_config(&spec()).unwrap());
    }

    // ── runc driver ─────────────────────────────────────────────────

    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<Vec<String>>>,
        replies: RefCell<Vec<(bool, String, String)>>,
    }

    impl RuncRunner for Fake {
        fn run(&self, args: &[String]) -> io::Result<(bool, String, String)> {
            self.calls.borrow_mut().push(args.to_vec());
            Ok(self.replies.borrow_mut().remove(0))
        }
    }

    fn fake(replies: &[(bool, &str, &str)]) -> Runc<Fake> {
        let f = Fake::default();
        *f.replies.borrow_mut() = replies
            .iter()
            .map(|(a, b, c)| (*a, b.to_string(), c.to_string()))
            .collect();
        Runc::new(f)
    }

    #[test]
    fn driver_builds_exact_arguments() {
        let r = fake(&[
            (true, "", ""),
            (true, "", ""),
            (true, "", ""),
            (true, "", ""),
        ]);
        r.create(Path::new("/b"), "v1").unwrap();
        r.start("v1").unwrap();
        r.kill("v1").unwrap();
        r.delete("v1").unwrap();
        assert_eq!(
            *r.runner.calls.borrow(),
            vec![
                s(&["create", "--bundle", "/b", "v1"]),
                s(&["start", "v1"]),
                s(&["kill", "--all", "v1", "KILL"]),
                s(&["delete", "--force", "v1"]),
            ]
        );
    }

    #[test]
    fn state_parses_and_unknown_is_none() {
        let r = fake(&[
            (
                true,
                r#"{"ociVersion":"1.2.0","id":"v1","pid":42,"status":"running"}"#,
                "",
            ),
            (false, "", "container does not exist"),
            (false, "", "permission denied"),
        ]);
        assert_eq!(r.state("v1").unwrap(), Some(Status::Running));
        assert_eq!(r.state("v1").unwrap(), None);
        assert!(r.state("v1").is_err());
    }

    #[test]
    fn list_parses_entries_and_empty_roots() {
        let r = fake(&[
            (
                true,
                r#"[{"id":"a","status":"running","pid":7},{"id":"b","status":"stopped"}]"#,
                "",
            ),
            (true, "null\n", ""),
            (true, "", ""),
            (true, "[]", ""),
        ]);
        assert_eq!(
            r.list().unwrap(),
            vec![("a".into(), Status::Running), ("b".into(), Status::Stopped)]
        );
        assert_eq!(r.list().unwrap(), vec![]);
        assert_eq!(r.list().unwrap(), vec![]);
        assert_eq!(r.list().unwrap(), vec![]);
        assert_eq!(
            *r.runner.calls.borrow(),
            vec![s(&["list", "--format", "json"]); 4]
        );
    }

    #[test]
    fn list_refuses_what_it_cannot_read() {
        for out in [
            r#"[{"status":"running"}]"#,
            r#"[{"id":7}]"#,
            r#"{"id":"a"}"#,
            "not json",
        ] {
            let r = fake(&[(true, out, "")]);
            assert_eq!(
                r.list().unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{out}"
            );
        }
        let r = fake(&[(false, "", "permission denied")]);
        assert!(r
            .list()
            .unwrap_err()
            .to_string()
            .contains("permission denied"));
    }

    #[test]
    fn sweep_deletes_every_container_and_reports_failures() {
        let r = fake(&[
            (
                true,
                r#"[{"id":"a","status":"running"},{"id":"b","status":"created"},{"id":"c","status":"stopped"}]"#,
                "",
            ),
            (true, "", ""),
            (false, "", "device busy"),
            (true, "", ""),
        ]);
        let swept = r.sweep().unwrap();
        assert_eq!(swept.deleted, vec!["a".to_string(), "c".to_string()]);
        assert_eq!(swept.failed.len(), 1);
        assert_eq!(swept.failed[0].0, "b");
        assert!(swept.failed[0].1.contains("device busy"), "{swept:?}");
        assert_eq!(
            *r.runner.calls.borrow(),
            vec![
                s(&["list", "--format", "json"]),
                s(&["delete", "--force", "a"]),
                s(&["delete", "--force", "b"]),
                s(&["delete", "--force", "c"]),
            ]
        );
    }

    #[test]
    fn sweep_of_an_empty_root_does_nothing() {
        let r = fake(&[(true, "null", "")]);
        assert_eq!(r.sweep().unwrap(), Swept::default());
        assert_eq!(r.runner.calls.borrow().len(), 1);
    }

    #[test]
    fn cli_creates_its_root_before_running() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("a/runc");
        let cli = RuncCli {
            program: "true".into(),
            root: root.clone(),
        };
        let (ok, _, _) = cli.run(&s(&["list"])).unwrap();
        assert!(ok);
        assert!(root.is_dir());
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // An existing root is left as it is.
        cli.run(&s(&["list"])).unwrap();
    }

    // ── prepare_work_dir: whose dataset is it ───────────────────────

    use std::os::unix::fs::MetadataExt;

    fn owner(p: &Path) -> (u32, u32) {
        let m = std::fs::metadata(p).unwrap();
        (m.uid(), m.gid())
    }

    fn running_as_root() -> bool {
        let dir = tempfile::tempdir().unwrap();
        owner(dir.path()).0 == 0
    }

    /// A directory owned by someone who is neither root nor the Vessel's
    /// range: as root, chowned to a foreign range; otherwise it is simply
    /// the test user's own (non-root, and not 200000).
    fn foreign_dir() -> (tempfile::TempDir, (u32, u32)) {
        let dir = tempfile::tempdir().unwrap();
        if running_as_root() {
            std::os::unix::fs::chown(dir.path(), Some(300_000), Some(300_000)).unwrap();
        }
        let o = owner(dir.path());
        assert!(o != (0, 0) && o != (200_000, 200_000), "{o:?}");
        (dir, o)
    }

    #[test]
    fn another_owners_dataset_is_refused_and_left_as_it_was() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, before) = foreign_dir();
        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        let e = prepare_work_dir(dir.path(), 200_000).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            e.to_string()
                .contains("not by this Vessel's range (200000)"),
            "{e}"
        );
        assert_eq!(owner(dir.path()), before, "owner unchanged");
        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode(),
            mode,
            "mode unchanged"
        );
    }

    #[test]
    fn only_a_plain_directory_is_prepared() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"").unwrap();
        assert_eq!(
            prepare_work_dir(&file, 200_000).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let link = dir.path().join("l");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert_eq!(
            prepare_work_dir(&link, 200_000).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(prepare_work_dir(&dir.path().join("missing"), 200_000).is_err());
    }

    /// Root-owned (fresh) is prepared; then it is the Vessel's and is
    /// accepted again; a half match (uid ours, gid not) is refused, as is
    /// another slot's range.  Needs root to set owners.
    #[test]
    #[ignore = "needs root"]
    fn fresh_then_ours_is_accepted_and_nothing_else() {
        use std::os::unix::fs::PermissionsExt;
        assert!(running_as_root(), "run as root");
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::chown(dir.path(), Some(0), Some(0)).unwrap();
        prepare_work_dir(dir.path(), 200_000).unwrap();
        assert_eq!(owner(dir.path()), (200_000, 200_000));
        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o750
        );
        prepare_work_dir(dir.path(), 200_000).unwrap();
        assert_eq!(
            owner(dir.path()),
            (200_000, 200_000),
            "prepared again: unchanged"
        );
        // The next slot's range, as after a slot change: refused.
        assert_eq!(
            prepare_work_dir(dir.path(), 200_000 + 65_536)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        // Half ours.
        std::os::unix::fs::chown(dir.path(), Some(200_000), Some(0)).unwrap();
        assert_eq!(
            prepare_work_dir(dir.path(), 200_000).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        std::os::unix::fs::chown(dir.path(), Some(0), Some(200_000)).unwrap();
        assert_eq!(
            prepare_work_dir(dir.path(), 200_000).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    // ── work_dir_range: forks over their lineage's range (F6 step 3a) ──

    /// Slot 1 (a parent: the lineage's disk range), slot 2 (its child),
    /// slot 3 (anyone else), over the deploy base 200000.
    const PARENT: u32 = 200_000 + ID_RANGE;
    const CHILD: u32 = 200_000 + 2 * ID_RANGE;
    const OTHER: u32 = 200_000 + 3 * ID_RANGE;

    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn inherited_range_is_checked_before_anything_is_read() {
        let missing = Path::new("/nonexistent/taso-f6");
        for d in [0, u32::MAX - 10, CHILD - 1, CHILD + ID_RANGE - 1] {
            assert_eq!(
                work_dir_range(missing, CHILD, Some(d)).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "inherited {d}"
            );
        }
        // A good range, or the Vessel's own (= None): the path is read.
        for d in [Some(PARENT), Some(CHILD), None] {
            assert_eq!(
                work_dir_range(missing, CHILD, d).unwrap_err().kind(),
                io::ErrorKind::NotFound,
                "{d:?}"
            );
        }
    }

    #[test]
    #[ignore = "needs root"]
    fn fork_runs_over_its_lineages_range_and_nothing_changes() {
        use std::os::unix::fs::PermissionsExt;
        assert!(running_as_root(), "run as root");
        let dir = tempfile::tempdir().unwrap();
        // As the parent left it; an unusual mode, to see it is not touched.
        std::os::unix::fs::chown(dir.path(), Some(PARENT), Some(PARENT)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for _ in 0..2 {
            assert_eq!(
                work_dir_range(dir.path(), CHILD, Some(PARENT)).unwrap(),
                PARENT
            );
            assert_eq!(owner(dir.path()), (PARENT, PARENT), "owner unchanged");
            assert_eq!(mode(dir.path()), 0o700, "mode unchanged");
        }
        // Without the lineage it is another range's dataset, as before.
        assert_eq!(
            work_dir_range(dir.path(), CHILD, None).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            prepare_work_dir(dir.path(), CHILD).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(owner(dir.path()), (PARENT, PARENT));
    }

    #[test]
    #[ignore = "needs root"]
    fn fork_of_a_birth_seal_becomes_its_own() {
        assert!(running_as_root(), "run as root");
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::chown(dir.path(), Some(0), Some(0)).unwrap();
        assert_eq!(
            work_dir_range(dir.path(), CHILD, Some(PARENT)).unwrap(),
            CHILD
        );
        assert_eq!(owner(dir.path()), (CHILD, CHILD));
        assert_eq!(mode(dir.path()), 0o750);
        // From then on it is the child's own: accepted with or without the
        // lineage, and the parent's range no longer matches it.
        assert_eq!(
            work_dir_range(dir.path(), CHILD, Some(PARENT)).unwrap(),
            CHILD
        );
        assert_eq!(work_dir_range(dir.path(), CHILD, None).unwrap(), CHILD);
        assert_eq!(owner(dir.path()), (CHILD, CHILD));
    }

    #[test]
    #[ignore = "needs root"]
    fn a_fork_refuses_any_other_range_and_changes_nothing() {
        use std::os::unix::fs::PermissionsExt;
        assert!(running_as_root(), "run as root");
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for (uid, gid) in [
            (OTHER, OTHER), // a third range: not this lineage's
            (PARENT, 0),    // half the parent's
            (0, PARENT),
            (PARENT, CHILD), // mixed
            (CHILD, PARENT),
        ] {
            std::os::unix::fs::chown(dir.path(), Some(uid), Some(gid)).unwrap();
            assert_eq!(
                work_dir_range(dir.path(), CHILD, Some(PARENT))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied,
                "{uid}:{gid}"
            );
            assert_eq!(owner(dir.path()), (uid, gid), "{uid}:{gid} unchanged");
            assert_eq!(mode(dir.path()), 0o700, "{uid}:{gid} mode unchanged");
        }
    }

    // ── lost+found follows the disk range (P4 file 4d, decision (a)) ──

    /// A `lost+found` as `mkfs.ext4` leaves it: `0:0`, mode 0700.
    fn lost_found(work: &Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = work.join(LOST_FOUND);
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::chown(&p, Some(0), Some(0)).unwrap();
        p
    }

    #[test]
    #[ignore = "needs root"]
    fn a_fresh_datasets_lost_found_joins_its_range() {
        assert!(running_as_root(), "run as root");
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::chown(dir.path(), Some(0), Some(0)).unwrap();
        let lf = lost_found(dir.path());
        assert_eq!(work_dir_range(dir.path(), CHILD, None).unwrap(), CHILD);
        assert_eq!(owner(&lf), (CHILD, CHILD));
        assert_eq!(mode(&lf), 0o700, "mode unchanged");
        // Again: nothing more changes.
        assert_eq!(work_dir_range(dir.path(), CHILD, None).unwrap(), CHILD);
        assert_eq!(owner(&lf), (CHILD, CHILD));
    }

    #[test]
    #[ignore = "needs root"]
    fn an_existing_vessels_lost_found_is_fixed_at_its_next_start() {
        assert!(running_as_root(), "run as root");
        let dir = tempfile::tempdir().unwrap();
        // Prepared before file 4d: the top is the Vessel's, lost+found 0:0.
        std::os::unix::fs::chown(dir.path(), Some(CHILD), Some(CHILD)).unwrap();
        let lf = lost_found(dir.path());
        assert_eq!(work_dir_range(dir.path(), CHILD, None).unwrap(), CHILD);
        assert_eq!(owner(&lf), (CHILD, CHILD));
    }

    #[test]
    #[ignore = "needs root"]
    fn a_forks_lost_found_joins_its_lineages_range() {
        assert!(running_as_root(), "run as root");
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::chown(dir.path(), Some(PARENT), Some(PARENT)).unwrap();
        let lf = lost_found(dir.path());
        assert_eq!(
            work_dir_range(dir.path(), CHILD, Some(PARENT)).unwrap(),
            PARENT
        );
        assert_eq!(owner(dir.path()), (PARENT, PARENT), "top unchanged");
        assert_eq!(owner(&lf), (PARENT, PARENT));
    }

    #[test]
    #[ignore = "needs root"]
    fn lost_found_is_left_alone_unless_it_is_a_root_owned_directory() {
        assert!(running_as_root(), "run as root");
        // Another owner: left for the walk to judge.
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::chown(dir.path(), Some(0), Some(0)).unwrap();
        let lf = lost_found(dir.path());
        std::os::unix::fs::chown(&lf, Some(OTHER), Some(OTHER)).unwrap();
        work_dir_range(dir.path(), CHILD, None).unwrap();
        assert_eq!(owner(&lf), (OTHER, OTHER));
        // Half root: left too.
        std::os::unix::fs::chown(&lf, Some(0), Some(OTHER)).unwrap();
        work_dir_range(dir.path(), CHILD, None).unwrap();
        assert_eq!(owner(&lf), (0, OTHER));

        // A symlink named lost+found is never followed.
        let dir = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::os::unix::fs::chown(dir.path(), Some(0), Some(0)).unwrap();
        std::os::unix::fs::chown(target.path(), Some(0), Some(0)).unwrap();
        std::os::unix::fs::symlink(target.path(), dir.path().join(LOST_FOUND)).unwrap();
        work_dir_range(dir.path(), CHILD, None).unwrap();
        assert_eq!(owner(target.path()), (0, 0), "target untouched");

        // A refused dataset: its lost+found is not touched either.
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::chown(dir.path(), Some(OTHER), Some(OTHER)).unwrap();
        let lf = lost_found(dir.path());
        assert!(work_dir_range(dir.path(), CHILD, None).is_err());
        assert_eq!(owner(&lf), (0, 0));

        // No lost+found (ZFS): nothing to do.
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::chown(dir.path(), Some(0), Some(0)).unwrap();
        assert_eq!(work_dir_range(dir.path(), CHILD, None).unwrap(), CHILD);
    }

    #[test]
    fn missing_runc_says_so() {
        let cli = RuncCli {
            program: "/nonexistent/runc".into(),
            root: "/tmp".into(),
        };
        let e = Runc::new(cli).start("v1").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(e.to_string().contains("is runc installed?"), "{e}");
    }

    #[test]
    fn failures_keep_runc_stderr() {
        let r = fake(&[(false, "", "cannot start: rootfs missing\n")]);
        let e = r.start("v1").unwrap_err().to_string();
        assert!(e.contains("rootfs missing"), "{e}");
    }

    // ── a real container ────────────────────────────────────────────

    mod node {
        use super::*;
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::net::UnixListener;

        /// A rootfs holding only `/bin/sh` and its shared libraries.
        fn tiny_rootfs(root: &Path) {
            let sh = std::fs::canonicalize("/bin/sh").unwrap();
            let mut files = vec![sh.clone()];
            let ldd = Command::new("ldd").arg(&sh).output().unwrap();
            for tok in String::from_utf8_lossy(&ldd.stdout).split_whitespace() {
                if tok.starts_with('/') {
                    files.push(PathBuf::from(tok));
                }
            }
            for d in ["bin", "proc", "dev", "sys", "tmp", "work", "run/taso"] {
                std::fs::create_dir_all(root.join(d)).unwrap();
            }
            std::fs::write(root.join("run/taso/field.sock"), b"").unwrap();
            std::fs::copy(&sh, root.join("bin/sh")).unwrap();
            for f in &files[1..] {
                let dst = root.join(f.strip_prefix("/").unwrap());
                std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
                std::fs::copy(f, dst).unwrap();
            }
        }

        /// Copy the host program `prog` into `root` at `prog`'s own path
        /// (not where a symlink at that path points: on a host whose
        /// coreutils are links into another package, the target's path does
        /// not exist inside the Vessel), and the libraries `ldd` names at
        /// theirs.  The file is copied under the name it is called by, which
        /// is also what a multi-call binary dispatches on.
        fn add_binary(root: &Path, prog: &str) {
            let real = std::fs::canonicalize(prog).unwrap();
            let ldd = Command::new("ldd").arg(&real).output().unwrap();
            let libs = String::from_utf8_lossy(&ldd.stdout)
                .split_whitespace()
                .filter(|t| t.starts_with('/'))
                .map(PathBuf::from)
                .collect::<Vec<_>>();
            let to = |f: &Path| root.join(f.strip_prefix("/").unwrap());
            let copies = std::iter::once((real.clone(), to(Path::new(prog))))
                .chain(libs.iter().map(|l| (l.clone(), to(l))));
            for (from, dst) in copies {
                std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
                std::fs::copy(&from, &dst).unwrap();
            }
        }

        const AGENT: &str = r#"
echo work-ok > /work/out
if (echo x > /escape) 2>/dev/null; then echo root-rw >> /work/out; else echo root-ro >> /work/out; fi
[ -S /run/taso/field.sock ] && echo sock-ok >> /work/out
while read l; do echo "$l"; done < /proc/net/dev > /work/net
while read l; do echo "$l"; done < /proc/self/uid_map > /work/uid
while read l; do echo "$l"; done < /proc/self/status > /work/status
"#;

        /// One Vessel under runc: it can write /work and see its socket,
        /// cannot write /, has only `lo`, runs as an unprivileged range
        /// with no capabilities, seccomp on, no new privileges.
        #[test]
        #[ignore = "needs runc and root"]
        fn vessel_runs_isolated_under_runc() {
            let dir = tempfile::tempdir().unwrap();
            let rootfs = dir.path().join("rootfs");
            tiny_rootfs(&rootfs);
            assert_eq!(check_rootfs(&rootfs), Vec::<String>::new());
            let work = dir.path().join("work");
            std::fs::create_dir(&work).unwrap();
            let base = 200_000;
            prepare_work_dir(&work, base).unwrap();
            // The work dir's parents must be traversable by the mapped range.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            let sock = dir.path().join("field.sock");
            let _listener = UnixListener::bind(&sock).unwrap();

            let spec = VesselSpec {
                id: format!("taso-test-{}", std::process::id()),
                rootfs,
                work: work.clone(),
                socket: sock,
                host_uid_base: base,
                disk_uid_base: None,
                args: vec!["/bin/sh".into(), "-c".into(), AGENT.into()],
                env: vec![],
                landlock_shim: None,
                memory_bytes: Some(256 << 20),
                pids: Some(64),
            };
            let bundle = dir.path().join("bundle");
            write_bundle(&bundle, &spec).unwrap();
            let state = dir.path().join("runc-state");
            let runc = Runc::new(RuncCli::new(&state));
            let (ok, err) = runc.run(&bundle, &spec.id).unwrap();
            let _ = runc.delete(&spec.id);
            assert!(ok, "the Vessel failed: {err}");

            let out = std::fs::read_to_string(work.join("out")).unwrap();
            println!("out:\n{out}");
            assert!(out.contains("work-ok"));
            assert!(
                out.contains("root-ro"),
                "the root filesystem must be read-only"
            );
            assert!(out.contains("sock-ok"), "the Field socket must be bound in");

            let net = std::fs::read_to_string(work.join("net")).unwrap();
            let ifaces: Vec<&str> = net
                .lines()
                .skip(2)
                .filter_map(|l| l.split(':').next())
                .map(str::trim)
                .collect();
            println!("interfaces: {ifaces:?}");
            assert_eq!(
                ifaces,
                vec!["lo"],
                "only loopback in the Vessel's network namespace"
            );

            let uid = std::fs::read_to_string(work.join("uid")).unwrap();
            let map: Vec<&str> = uid.split_whitespace().collect();
            assert_eq!(map, vec!["0", "200000", "65536"]);

            let status = std::fs::read_to_string(work.join("status")).unwrap();
            let field = |k: &str| {
                status
                    .lines()
                    .find(|l| l.starts_with(k))
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_string()
            };
            println!(
                "CapEff {} Seccomp {} NoNewPrivs {}",
                field("CapEff:"),
                field("Seccomp:"),
                field("NoNewPrivs:")
            );
            assert_eq!(field("CapEff:"), "0000000000000000");
            assert_eq!(field("CapBnd:"), "0000000000000000");
            assert_eq!(field("Seccomp:"), "2", "seccomp filter mode");
            assert_eq!(field("NoNewPrivs:"), "1");

            // What the agent wrote belongs to its range on the host.
            assert_eq!(std::fs::metadata(work.join("out")).unwrap().uid(), base);
        }

        /// What a killed daemon leaves behind: a running container in its
        /// runc root.  `list` reads real runc output, and `sweep` removes
        /// it; the `runc run` that started it then returns.
        #[test]
        #[ignore = "needs runc and root"]
        fn sweep_removes_a_running_container_under_runc() {
            let dir = tempfile::tempdir().unwrap();
            let rootfs = dir.path().join("rootfs");
            tiny_rootfs(&rootfs);
            let work = dir.path().join("work");
            std::fs::create_dir(&work).unwrap();
            prepare_work_dir(&work, 200_000).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            let sock = dir.path().join("field.sock");
            let _listener = UnixListener::bind(&sock).unwrap();
            let spec = VesselSpec {
                id: format!("taso-sweep-{}", std::process::id()),
                rootfs,
                work,
                socket: sock,
                host_uid_base: 200_000,
                disk_uid_base: None,
                // Never exits by itself; pid 1 ignores SIGTERM.
                args: vec!["/bin/sh".into(), "-c".into(), "while :; do :; done".into()],
                env: vec![],
                landlock_shim: None,
                memory_bytes: Some(64 << 20),
                pids: Some(16),
            };
            let bundle = dir.path().join("bundle");
            write_bundle(&bundle, &spec).unwrap();
            let state = dir.path().join("runc-state");
            let runc = Runc::new(RuncCli::new(&state));

            // An empty or not yet created root lists as empty.
            assert_eq!(runc.list().unwrap(), vec![]);

            let agent = {
                let (state, bundle, id) = (state.clone(), bundle.clone(), spec.id.clone());
                std::thread::spawn(move || Runc::new(RuncCli::new(&state)).run(&bundle, &id))
            };
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                let l = runc.list().unwrap();
                if l.iter()
                    .any(|(id, st)| id == &spec.id && *st == Status::Running)
                {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "the container never ran: {l:?}"
                );
                std::thread::sleep(std::time::Duration::from_millis(50));
            }

            let swept = runc.sweep().unwrap();
            assert_eq!(
                swept,
                Swept {
                    deleted: vec![spec.id.clone()],
                    failed: vec![]
                }
            );
            assert_eq!(runc.list().unwrap(), vec![]);
            assert_eq!(runc.state(&spec.id).unwrap(), None);
            let (ok, _) = agent.join().unwrap().unwrap();
            assert!(!ok, "a swept agent was killed, it did not exit cleanly");
        }

        /// A loop-mounted ext4, unmounted and detached on drop (also when
        /// the test fails).
        struct LoopFs {
            mnt: PathBuf,
            dev: String,
        }

        impl LoopFs {
            fn new(img: &Path, mnt: &Path) -> Self {
                let ok = |c: &mut Command| {
                    let o = c.output().unwrap();
                    assert!(
                        o.status.success(),
                        "{c:?}: {}",
                        String::from_utf8_lossy(&o.stderr)
                    );
                    String::from_utf8_lossy(&o.stdout).trim().to_string()
                };
                std::fs::File::create(img)
                    .unwrap()
                    .set_len(256 << 20)
                    .unwrap();
                ok(Command::new("mkfs.ext4").args(["-q", "-F"]).arg(img));
                let dev = ok(Command::new("losetup").args(["--find", "--show"]).arg(img));
                std::fs::create_dir_all(mnt).unwrap();
                let fs = LoopFs {
                    mnt: mnt.to_path_buf(),
                    dev,
                };
                ok(Command::new("mount").arg(&fs.dev).arg(mnt));
                fs
            }
        }

        impl Drop for LoopFs {
            fn drop(&mut self) {
                let _ = Command::new("umount").arg(&self.mnt).status();
                let _ = Command::new("losetup").args(["-d", &self.dev]).status();
            }
        }

        /// F6 step 2: a Vessel in slot B runs under real runc over files a
        /// parent in slot A left on an ext4, through `oci_config`'s idmapped
        /// `/work`.  Predictions (written before the first run, 2026-10-21):
        ///
        /// - Q1 runc 1.4 accepts the mount mapping (`ridmap`) next to the
        ///   container's own user namespace; the agent exits 0.
        /// - Q2 inside, `/work` shows as 0:0 and `home/notes` as 1000:1000.
        /// - Q3 the container's root creates `/work/new`; on disk it is A+0.
        /// - Q4 host root's file shows as 65534:65534 and is not writable.
        /// - Q5 the container's uid_map is `0 B 65536`, untouched.
        /// - Q6 the container's root (no capabilities) cannot write into
        ///   `home/` (1000's, 0755): a fork gets a birth's powers, no more.
        /// - Q7 nothing on disk was re-owned: no chown pass happened.
        #[test]
        #[ignore = "needs runc, root, mkfs.ext4 and a loop device"]
        fn fork_in_another_slot_runs_over_parents_files_under_runc() {
            const A: u32 = 200_000 + ID_RANGE; // slot 1: the parent
            const B: u32 = 200_000 + 2 * ID_RANGE; // slot 2: the child
            const OVERFLOW: u32 = 65534;

            let dir = tempfile::tempdir().unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            let rootfs = dir.path().join("rootfs");
            tiny_rootfs(&rootfs);
            add_binary(&rootfs, "/usr/bin/stat");
            let disk = LoopFs::new(&dir.path().join("disk.img"), &dir.path().join("disk"));
            let work = disk.mnt.clone();

            // The parent's files, as a Vessel in slot A leaves them.
            let own = |p: &Path, id: u32, mode: u32| {
                std::os::unix::fs::chown(p, Some(id), Some(id)).unwrap();
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
            };
            own(&work, A, 0o750);
            std::fs::create_dir(work.join("home")).unwrap();
            own(&work.join("home"), A + 1000, 0o755);
            std::fs::write(work.join("home/notes"), b"parent\n").unwrap();
            own(&work.join("home/notes"), A + 1000, 0o644);
            std::fs::write(work.join("rootfile"), b"host\n").unwrap();
            own(&work.join("rootfile"), 0, 0o644);
            let before: Vec<(PathBuf, u32, u32)> = ["", "home", "home/notes", "rootfile"]
                .iter()
                .map(|r| {
                    let m = std::fs::symlink_metadata(work.join(r)).unwrap();
                    (work.join(r), m.uid(), m.gid())
                })
                .collect();

            let sock = dir.path().join("field.sock");
            let _listener = UnixListener::bind(&sock).unwrap();
            let agent = r#"
o=/work/out
: > $o
if stat -c %u /work >/dev/null 2>/work/stat.err; then echo "stat ok" >> $o; else echo "stat broken" >> $o; fi
echo "work $(stat -c %u:%g /work)" >> $o
echo "home $(stat -c %u:%g /work/home)" >> $o
echo "notes $(stat -c %u:%g /work/home/notes)" >> $o
echo "rootfile $(stat -c %u:%g /work/rootfile)" >> $o
if (echo x >> /work/rootfile) 2>/dev/null; then echo "rootfile-write yes" >> $o; else echo "rootfile-write no" >> $o; fi
if (echo x > /work/home/by-child) 2>/dev/null; then echo "home-write yes" >> $o; else echo "home-write no" >> $o; fi
echo child > /work/new && echo "new $(stat -c %u:%g /work/new)" >> $o
while read a b c; do echo "uidmap $a $b $c" >> $o; done < /proc/self/uid_map
"#;
            let spec = VesselSpec {
                id: format!("taso-f6-{}", std::process::id()),
                rootfs,
                work: work.clone(),
                socket: sock,
                host_uid_base: B,
                disk_uid_base: Some(A),
                args: vec!["/bin/sh".into(), "-c".into(), agent.into()],
                env: vec![],
                landlock_shim: None,
                memory_bytes: Some(256 << 20),
                pids: Some(64),
            };
            let bundle = dir.path().join("bundle");
            write_bundle(&bundle, &spec).unwrap();
            let runc = Runc::new(RuncCli::new(dir.path().join("runc-state")));
            let (ok, err) = runc.run(&bundle, &spec.id).unwrap();
            let _ = runc.delete(&spec.id);
            assert!(ok, "Q1 missed: runc refused or the agent failed: {err}");

            let out = std::fs::read_to_string(work.join("out")).unwrap();
            println!("inside the Vessel:\n{out}");
            let get = |k: &str| {
                out.lines()
                    .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix(' ')))
                    .unwrap_or_else(|| panic!("no {k:?} line"))
                    .to_string()
            };
            // A broken tool inside the Vessel is the test's own failure, not
            // a missed prediction: say so, with what stat printed.
            assert_eq!(
                get("stat"),
                "ok",
                "test setup: stat does not run inside the Vessel: {}",
                std::fs::read_to_string(work.join("stat.err")).unwrap_or_default()
            );
            assert_eq!(get("work"), "0:0", "Q2: /work as the child's root");
            assert_eq!(
                get("notes"),
                "1000:1000",
                "Q2: the parent's 1000 as the child's"
            );
            assert_eq!(get("new"), "0:0", "Q3: created as the child's root");
            let disk_new = std::fs::metadata(work.join("new")).unwrap();
            assert_eq!(
                (disk_new.uid(), disk_new.gid()),
                (A, A),
                "Q3: on disk, the parent's range"
            );
            assert_eq!(
                get("rootfile"),
                format!("{OVERFLOW}:{OVERFLOW}"),
                "Q4: unmapped"
            );
            assert_eq!(
                get("rootfile-write"),
                "no",
                "Q4: host root's file not writable"
            );
            assert_eq!(
                std::fs::read(work.join("rootfile")).unwrap(),
                b"host\n",
                "Q4"
            );
            assert_eq!(get("uidmap"), format!("0 {B} {ID_RANGE}"), "Q5");
            assert_eq!(get("home-write"), "no", "Q6: no more than a birth");
            assert!(!work.join("home/by-child").exists(), "Q6");
            for (p, uid, gid) in &before {
                let m = std::fs::symlink_metadata(p).unwrap();
                assert_eq!(
                    (m.uid(), m.gid()),
                    (*uid, *gid),
                    "Q7: {} re-owned",
                    p.display()
                );
            }
            drop(disk);
        }
        /// F6 step 4: the attack on step 2's setup.  A child in slot B,
        /// running over files its parent in slot A left, tries to act as
        /// the parent or as anyone else through the idmapped `/work`.  The
        /// kernel refuses (Taso is not a sandbox: no syscall is intercepted);
        /// the test records each attempt's error and checks that it is the
        /// refusal it should be, never a missing tool.  Predictions (written
        /// before the first run, 2026-10-21):
        ///
        /// - X1 `chown` to its own 1000 (on disk the parent's A+1000):
        ///   refused, no `CAP_CHOWN` ("Operation not permitted").
        /// - X2 `chown` to an id outside its user namespace (70000):
        ///   refused ("Invalid argument": not mappable).
        /// - X3 `setpriv --reuid 1000`: refused, no `CAP_SETUID`.
        /// - X4 `setpriv --reuid 70000`: refused (not mappable, and no
        ///   capability).
        /// - X5 `mknod` a character device: refused (no `CAP_MKNOD`).
        /// - X6 a setuid program the parent left (owned A+1000 on disk,
        ///   mode 4755) runs as the child's root, not as its owner
        ///   (`nosuid`): `id -u` prints 0, `id -un`'s effective is not 1000.
        /// - X7 afterwards on disk: nothing re-owned (the child's file is
        ///   A+0, the parent's files as they were), no device node.
        #[test]
        #[ignore = "needs runc, root, mkfs.ext4 and a loop device"]
        fn a_fork_cannot_act_as_its_parent_through_the_mount() {
            const A: u32 = 200_000 + ID_RANGE; // slot 1: the parent
            const B: u32 = 200_000 + 2 * ID_RANGE; // slot 2: the child

            let dir = tempfile::tempdir().unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            let rootfs = dir.path().join("rootfs");
            tiny_rootfs(&rootfs);
            for prog in [
                "/usr/bin/stat",
                "/usr/bin/chown",
                "/usr/bin/setpriv",
                "/usr/bin/mknod",
                "/usr/bin/id",
            ] {
                add_binary(&rootfs, prog);
            }
            let disk = LoopFs::new(&dir.path().join("disk.img"), &dir.path().join("disk"));
            let work = disk.mnt.clone();

            // The parent's files, as in step 2, and a setuid program of its
            // user 1000 (a copy of `id`, its libraries are in the rootfs).
            let own = |p: &Path, id: u32, mode: u32| {
                std::os::unix::fs::chown(p, Some(id), Some(id)).unwrap();
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
            };
            own(&work, A, 0o750);
            std::fs::create_dir(work.join("home")).unwrap();
            own(&work.join("home"), A + 1000, 0o755);
            std::fs::write(work.join("home/notes"), b"parent\n").unwrap();
            own(&work.join("home/notes"), A + 1000, 0o644);
            std::fs::copy(
                std::fs::canonicalize("/usr/bin/id").unwrap(),
                work.join("home/suid-id"),
            )
            .unwrap();
            own(&work.join("home/suid-id"), A + 1000, 0o4755);
            let before: Vec<(PathBuf, u32, u32, u32)> = ["", "home", "home/notes", "home/suid-id"]
                .iter()
                .map(|r| {
                    let m = std::fs::symlink_metadata(work.join(r)).unwrap();
                    (work.join(r), m.uid(), m.gid(), m.mode())
                })
                .collect();

            let sock = dir.path().join("field.sock");
            let _listener = UnixListener::bind(&sock).unwrap();
            let agent = r#"
o=/work/attack
: > $o
for t in stat chown setpriv mknod id; do command -v $t >/dev/null || echo "missing $t" >> $o; done
attempt() {
    name=$1; shift
    if "$@" 2>/work/err; then echo "$name allowed" >> $o
    else e=; read -r e < /work/err || true; echo "$name refused: $e" >> $o; fi
}
echo child > /work/new
attempt X1 chown 1000:1000 /work/new
attempt X2 chown 70000:70000 /work/new
attempt X3 setpriv --reuid=1000 --regid=1000 --clear-groups true
attempt X4 setpriv --reuid=70000 --regid=70000 --clear-groups true
attempt X5 mknod /work/dev c 1 3
echo "X6 $(/work/home/suid-id -u) $(/work/home/suid-id -ru)" >> $o
echo "new $(stat -c %u:%g /work/new)" >> $o
"#;
            let spec = VesselSpec {
                id: format!("taso-f6x-{}", std::process::id()),
                rootfs,
                work: work.clone(),
                socket: sock,
                host_uid_base: B,
                disk_uid_base: Some(A),
                args: vec!["/bin/sh".into(), "-c".into(), agent.into()],
                env: vec![],
                landlock_shim: None,
                memory_bytes: Some(256 << 20),
                pids: Some(64),
            };
            let bundle = dir.path().join("bundle");
            write_bundle(&bundle, &spec).unwrap();
            let runc = Runc::new(RuncCli::new(dir.path().join("runc-state")));
            let (ok, err) = runc.run(&bundle, &spec.id).unwrap();
            let _ = runc.delete(&spec.id);
            assert!(ok, "the agent failed: {err}");

            let out = std::fs::read_to_string(work.join("attack")).unwrap();
            println!("inside the Vessel:\n{out}");
            assert!(
                !out.contains("missing "),
                "test setup: a tool does not run inside the Vessel:\n{out}"
            );
            let line = |k: &str| {
                out.lines()
                    .find(|l| l.starts_with(&format!("{k} ")))
                    .unwrap_or_else(|| panic!("no {k} line in:\n{out}"))
                    .to_string()
            };
            let refused = |k: &str, why: &[&str]| {
                let l = line(k);
                assert!(
                    l.starts_with(&format!("{k} refused: ")),
                    "{k} was not refused: {l}"
                );
                assert!(
                    why.iter().any(|w| l.contains(w)),
                    "{k} refused for another reason: {l}"
                );
            };
            const EPERM: &str = "Operation not permitted";
            const EINVAL: &str = "Invalid argument";
            refused("X1", &[EPERM]);
            refused("X2", &[EINVAL, EPERM]);
            refused("X3", &[EPERM]);
            refused("X4", &[EINVAL, EPERM]);
            refused("X5", &[EPERM]);
            assert_eq!(
                line("X6"),
                "X6 0 0",
                "X6: the parent's setuid bit must not apply"
            );
            assert_eq!(line("new"), "new 0:0");

            // X7: on disk, nothing re-owned, no device node.
            let new = std::fs::metadata(work.join("new")).unwrap();
            assert_eq!(
                (new.uid(), new.gid()),
                (A, A),
                "X7: the child's file is the parent's range"
            );
            assert!(!work.join("dev").exists(), "X7: no device node");
            for (p, uid, gid, mode) in &before {
                let m = std::fs::symlink_metadata(p).unwrap();
                assert_eq!(
                    (m.uid(), m.gid(), m.mode()),
                    (*uid, *gid, *mode),
                    "X7: {} changed",
                    p.display()
                );
            }
            drop(disk);
        }
    }
}
