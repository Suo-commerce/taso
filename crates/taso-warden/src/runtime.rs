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
//! [`prepare_work_dir`].
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
    "mount", "umount2", "pivot_root", "chroot", "unshare", "setns", "mount_setattr", "move_mount",
    "open_tree", "fsopen", "fsconfig", "fsmount", "fspick",
    // kernel modules, kexec, BPF, perf
    "init_module", "finit_module", "delete_module", "kexec_load", "kexec_file_load", "bpf",
    "perf_event_open",
    // other processes' memory
    "ptrace", "process_vm_readv", "process_vm_writev", "kcmp",
    // kernel keyring
    "keyctl", "add_key", "request_key",
    // host-wide state
    "reboot", "swapon", "swapoff", "settimeofday", "clock_settime", "clock_adjtime", "adjtimex",
    "acct", "quotactl", "syslog", "vhangup", "iopl", "ioperm",
    // handles that escape mounts, fault handling across processes
    "open_by_handle_at", "name_to_handle_at", "userfaultfd", "lookup_dcookie",
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
        && spec.id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
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
    if spec.host_uid_base == 0 || spec.host_uid_base.checked_add(ID_RANGE).is_none() {
        return Err(SpecError::BadUidRange(spec.host_uid_base));
    }
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
            { "destination": WORK_DIR, "type": "bind", "source": spec.work,
              "options": ["rbind", "rw", "nosuid", "nodev"] },
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
pub fn prepare_work_dir(work: &Path, host_uid_base: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::os::unix::fs::chown(work, Some(host_uid_base), Some(host_uid_base))?;
    std::fs::set_permissions(work, std::fs::Permissions::from_mode(0o750))
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
        Self { program: PathBuf::from("runc"), root: root.into() }
    }
}

impl RuncRunner for RuncCli {
    fn run(&self, args: &[String]) -> io::Result<(bool, String, String)> {
        // runc creates its root on `run`/`create`, but other subcommands
        // (`list`, at least on runc 1.x) fail on a missing one.  Create it
        // first, as runc would (0700), so an empty root is just empty.
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&self.root)?;
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
            Err(io::Error::other(format!("runc {}: {}", args.join(" "), err.trim())))
        }
    }

    /// Run the container in the foreground until it exits.  Returns whether
    /// it exited successfully and what runc and the agent printed on
    /// stderr (the reason, when it did not).  Used for one-shot Vessels.
    pub fn run(&self, bundle: &Path, id: &str) -> io::Result<(bool, String)> {
        let (ok, _, err) = self.runner.run(&s(&["run", "--bundle", &bundle.to_string_lossy(), id]))?;
        Ok((ok, err))
    }

    /// Create the container (not started).
    pub fn create(&self, bundle: &Path, id: &str) -> io::Result<()> {
        self.ok(s(&["create", "--bundle", &bundle.to_string_lossy(), id])).map(|_| ())
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
        let bad = |why: String| io::Error::new(io::ErrorKind::InvalidData, format!("runc list: {why}"));
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
                let id = e["id"].as_str().ok_or_else(|| bad(format!("entry without an id: {e}")))?;
                Ok((id.to_string(), Status::parse(e["status"].as_str().unwrap_or(""))))
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
            args: vec!["/usr/bin/hermes".into(), "--serve".into()],
            env: vec!["HERMES_MODE=agent".into()],
            landlock_shim: None,
            memory_bytes: Some(2 << 30),
            pids: Some(512),
        }
    }

    fn mount<'a>(c: &'a Value, dest: &str) -> &'a Value {
        c["mounts"].as_array().unwrap().iter().find(|m| m["destination"] == dest).unwrap()
    }

    #[test]
    fn isolation_rules_are_in_the_config() {
        let c = oci_config(&spec()).unwrap();
        // User namespace with an unprivileged range.
        let ns: Vec<&str> = c["linux"]["namespaces"].as_array().unwrap().iter().map(|n| n["type"].as_str().unwrap()).collect();
        for want in ["user", "network", "pid", "mount", "ipc", "uts", "cgroup"] {
            assert!(ns.contains(&want), "namespace {want}");
        }
        assert_eq!(c["linux"]["uidMappings"][0]["hostID"], 200_000);
        assert_eq!(c["linux"]["uidMappings"][0]["size"], ID_RANGE);
        // A new network namespace with no path: empty, not the host's.
        let net = c["linux"]["namespaces"].as_array().unwrap().iter().find(|n| n["type"] == "network").unwrap();
        assert!(net.get("path").is_none());
        // No capabilities, no new privileges.
        for set in ["bounding", "effective", "inheritable", "permitted", "ambient"] {
            assert_eq!(c["process"]["capabilities"][set], json!([]), "{set}");
        }
        assert_eq!(c["process"]["noNewPrivileges"], true);
        // Read-only root; writable only /work and /tmp; the socket bound in.
        assert_eq!(c["root"]["readonly"], true);
        assert_eq!(mount(&c, WORK_DIR)["source"], "/tasotest/vessel/v-ab12cd34");
        assert!(mount(&c, WORK_DIR)["options"].as_array().unwrap().contains(&json!("nosuid")));
        assert_eq!(mount(&c, FIELD_SOCKET)["source"], "/run/taso/v/ab12cd34.sock");
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
        for must in ["mount", "unshare", "setns", "ptrace", "bpf", "init_module", "keyctl", "open_by_handle_at"] {
            assert!(names.contains(&must), "{must}");
        }
        assert_eq!(c["linux"]["seccomp"]["syscalls"][0]["action"], "SCMP_ACT_ERRNO");
    }

    #[test]
    fn environment_is_only_what_the_spec_says() {
        // Built only from the spec: nothing from the Warden's environment.
        let c = oci_config(&spec()).unwrap();
        let env: Vec<&str> = c["process"]["env"].as_array().unwrap().iter().map(|e| e.as_str().unwrap()).collect();
        assert_eq!(env.len(), 4);
        assert!(env.contains(&"TASO_FIELD=/run/taso/field.sock"));
        assert!(env.contains(&"HOME=/work"));
        assert!(env.contains(&"HERMES_MODE=agent"));
        assert!(!env.iter().any(|e| e.starts_with("UPCLOUD_TOKEN") || e.starts_with("AWS_")));
    }

    #[test]
    fn landlock_shim_runs_first() {
        let mut sp = spec();
        sp.landlock_shim = Some("/usr/lib/taso/landlock".into());
        let c = oci_config(&sp).unwrap();
        assert_eq!(c["process"]["args"], json!(["/usr/lib/taso/landlock", "--", "/usr/bin/hermes", "--serve"]));
    }

    #[test]
    fn invalid_specs_are_refused() {
        type Case = (Box<dyn Fn(&mut VesselSpec)>, fn(&SpecError) -> bool);
        let cases: Vec<Case> = vec![
            (Box::new(|s| s.id = "../x".into()), |e| matches!(e, SpecError::BadId(_))),
            (Box::new(|s| s.id = String::new()), |e| matches!(e, SpecError::BadId(_))),
            (Box::new(|s| s.work = "relative".into()), |e| matches!(e, SpecError::NotAbsolute(_))),
            (Box::new(|s| s.args.clear()), |e| matches!(e, SpecError::NoArgs)),
            (Box::new(|s| s.host_uid_base = 0), |e| matches!(e, SpecError::BadUidRange(_))),
            (Box::new(|s| s.host_uid_base = u32::MAX - 10), |e| matches!(e, SpecError::BadUidRange(_))),
            (Box::new(|s| s.env = vec!["PATH=/evil".into()]), |e| matches!(e, SpecError::BadEnv(_))),
            (Box::new(|s| s.env = vec!["TASO_FIELD=/x".into()]), |e| matches!(e, SpecError::BadEnv(_))),
            (Box::new(|s| s.env = vec!["NOEQUALS".into()]), |e| matches!(e, SpecError::BadEnv(_))),
            (Box::new(|s| s.env = vec!["BAD-KEY=1".into()]), |e| matches!(e, SpecError::BadEnv(_))),
        ];
        for (i, (mutate, is)) in cases.into_iter().enumerate() {
            let mut sp = spec();
            mutate(&mut sp);
            let err = oci_config(&sp).unwrap_err();
            assert!(is(&err), "case {i}: {err:?}");
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
        assert_eq!(check_rootfs(dir.path()), vec!["/run/taso/field.sock".to_string()]);
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
        *f.replies.borrow_mut() = replies.iter().map(|(a, b, c)| (*a, b.to_string(), c.to_string())).collect();
        Runc::new(f)
    }

    #[test]
    fn driver_builds_exact_arguments() {
        let r = fake(&[(true, "", ""), (true, "", ""), (true, "", ""), (true, "", "")]);
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
            (true, r#"{"ociVersion":"1.2.0","id":"v1","pid":42,"status":"running"}"#, ""),
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
            (true, r#"[{"id":"a","status":"running","pid":7},{"id":"b","status":"stopped"}]"#, ""),
            (true, "null\n", ""),
            (true, "", ""),
            (true, "[]", ""),
        ]);
        assert_eq!(r.list().unwrap(), vec![("a".into(), Status::Running), ("b".into(), Status::Stopped)]);
        assert_eq!(r.list().unwrap(), vec![]);
        assert_eq!(r.list().unwrap(), vec![]);
        assert_eq!(r.list().unwrap(), vec![]);
        assert_eq!(*r.runner.calls.borrow(), vec![s(&["list", "--format", "json"]); 4]);
    }

    #[test]
    fn list_refuses_what_it_cannot_read() {
        for out in [r#"[{"status":"running"}]"#, r#"[{"id":7}]"#, r#"{"id":"a"}"#, "not json"] {
            let r = fake(&[(true, out, "")]);
            assert_eq!(r.list().unwrap_err().kind(), io::ErrorKind::InvalidData, "{out}");
        }
        let r = fake(&[(false, "", "permission denied")]);
        assert!(r.list().unwrap_err().to_string().contains("permission denied"));
    }

    #[test]
    fn sweep_deletes_every_container_and_reports_failures() {
        let r = fake(&[
            (true, r#"[{"id":"a","status":"running"},{"id":"b","status":"created"},{"id":"c","status":"stopped"}]"#, ""),
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
        let cli = RuncCli { program: "true".into(), root: root.clone() };
        let (ok, _, _) = cli.run(&s(&["list"])).unwrap();
        assert!(ok);
        assert!(root.is_dir());
        assert_eq!(std::fs::metadata(&root).unwrap().permissions().mode() & 0o777, 0o700);
        // An existing root is left as it is.
        cli.run(&s(&["list"])).unwrap();
    }

    #[test]
    fn missing_runc_says_so() {
        let cli = RuncCli { program: "/nonexistent/runc".into(), root: "/tmp".into() };
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
            assert!(out.contains("root-ro"), "the root filesystem must be read-only");
            assert!(out.contains("sock-ok"), "the Field socket must be bound in");

            let net = std::fs::read_to_string(work.join("net")).unwrap();
            let ifaces: Vec<&str> = net.lines().skip(2).filter_map(|l| l.split(':').next()).map(str::trim).collect();
            println!("interfaces: {ifaces:?}");
            assert_eq!(ifaces, vec!["lo"], "only loopback in the Vessel's network namespace");

            let uid = std::fs::read_to_string(work.join("uid")).unwrap();
            let map: Vec<&str> = uid.split_whitespace().collect();
            assert_eq!(map, vec!["0", "200000", "65536"]);

            let status = std::fs::read_to_string(work.join("status")).unwrap();
            let field = |k: &str| status.lines().find(|l| l.starts_with(k)).unwrap().split_whitespace().nth(1).unwrap().to_string();
            println!("CapEff {} Seccomp {} NoNewPrivs {}", field("CapEff:"), field("Seccomp:"), field("NoNewPrivs:"));
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
                if l.iter().any(|(id, st)| id == &spec.id && *st == Status::Running) {
                    break;
                }
                assert!(std::time::Instant::now() < deadline, "the container never ran: {l:?}");
                std::thread::sleep(std::time::Duration::from_millis(50));
            }

            let swept = runc.sweep().unwrap();
            assert_eq!(swept, Swept { deleted: vec![spec.id.clone()], failed: vec![] });
            assert_eq!(runc.list().unwrap(), vec![]);
            assert_eq!(runc.state(&spec.id).unwrap(), None);
            let (ok, _) = agent.join().unwrap().unwrap();
            assert!(!ok, "a swept agent was killed, it did not exit cleanly");
        }
    }
}
