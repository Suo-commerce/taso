//! `taso-landlock`: the Vessel's Landlock shim (v1.0 §3, Phase 1).
//!
//! runc does not apply Landlock, so the agent's command line starts with
//! this binary.  The runtime turns `args` into
//! `taso-landlock -- <agent> <args…>` (taso-warden's
//! `runtime::VesselSpec::landlock_shim`).  The shim restricts itself, then execs
//! the agent, which inherits the restriction and cannot lift it.
//!
//! # The policy
//!
//! - **Writes only beneath the write paths**: `/work` (the Vessel's
//!   dataset) and `/tmp` by default, or every `--write PATH` given.  Each
//!   must exist; a missing one is an error, never a silently looser
//!   policy.
//! - **Device files**: `/dev/null`, `/dev/zero`, `/dev/full`,
//!   `/dev/random`, `/dev/urandom`, `/dev/tty` may be read, written and
//!   ioctl'd.  Missing ones are skipped.  Nothing can be created in `/dev`.
//! - **Everything else is read and execute only**, `/proc` and `/sys`
//!   included.
//! - **Scopes** (Landlock ABI 6): no connecting to abstract Unix sockets
//!   made outside the Vessel, no signals to processes outside it.
//! - TCP is not restricted: the network namespace has only `lo` (the
//!   runtime's rule), and loopback inside a Vessel harms no one.
//!
//! # Fail closed
//!
//! Landlock ABI 1 (filesystem access control) is a hard requirement: on a
//! kernel without it the shim exits with [`EXIT_UNSUPPORTED`] and the
//! agent never runs.  Rights from later ABIs (refer, truncate, ioctl on
//! devices, scopes) are applied when the kernel has them, up to ABI 6, the
//! version this policy was written and tested against.  A partial
//! enforcement is reported on stderr, once.
//!
//! The kernel also sets `no_new_privs` (runc already has).

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use landlock::{
    path_beneath_rules, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};

/// The ABI this policy is written and tested against.
const ABI_TARGET: ABI = ABI::V6;

/// Write paths when none is given.
const DEFAULT_WRITE: [&str; 2] = ["/work", "/tmp"];

/// Device files the agent may use.
const DEVICES: [&str; 6] = [
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
];

/// Bad command line.
const EXIT_USAGE: u8 = 64;
/// The kernel has no Landlock (or it is disabled): the agent is not run.
const EXIT_UNSUPPORTED: u8 = 70;
/// The policy could not be built (a write path does not exist, …).
const EXIT_POLICY: u8 = 71;
/// The agent could not be executed.
const EXIT_EXEC: u8 = 126;

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
struct Args {
    write: Vec<PathBuf>,
    command: Vec<OsString>,
}

/// `[--write PATH]... -- COMMAND [ARGS...]`.
fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Args, String> {
    let mut it = args.into_iter();
    let mut write = Vec::new();
    loop {
        match it.next() {
            None => return Err("missing `-- COMMAND`".into()),
            Some(a) if a == "--" => break,
            Some(a) if a == "--write" => {
                let p = it.next().ok_or("--write needs a path")?;
                let p = PathBuf::from(p);
                if !p.is_absolute() {
                    return Err(format!("--write {}: not an absolute path", p.display()));
                }
                write.push(p);
            }
            Some(a) => return Err(format!("unknown argument {a:?}")),
        }
    }
    let command: Vec<OsString> = it.collect();
    if command.is_empty() {
        return Err("missing COMMAND after `--`".into());
    }
    if write.is_empty() {
        write = DEFAULT_WRITE.iter().map(PathBuf::from).collect();
    }
    Ok(Args { write, command })
}

/// Why restricting failed.
#[derive(Debug)]
enum Refused {
    /// No Landlock in this kernel.
    Unsupported(String),
    /// The policy could not be built.
    Policy(String),
}

/// Restrict this process (and what it execs) to the policy.
fn restrict(write: &[PathBuf]) -> Result<RulesetStatus, Refused> {
    let policy = |e: landlock::RulesetError| Refused::Policy(e.to_string());
    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V1))
        .map_err(|e| Refused::Unsupported(e.to_string()))?
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(ABI_TARGET))
        .map_err(policy)?
        .scope(Scope::from_all(ABI_TARGET))
        .map_err(policy)?
        .create()
        .map_err(|e| Refused::Unsupported(e.to_string()))?;

    let mut writable = Vec::with_capacity(write.len());
    for p in write {
        let fd = PathFd::new(p)
            .map_err(|e| Refused::Policy(format!("write path {}: {e}", p.display())))?;
        writable.push(Ok(PathBeneath::new(fd, AccessFs::from_all(ABI_TARGET))));
    }
    let status = ruleset
        .add_rules(path_beneath_rules(["/"], AccessFs::from_read(ABI_TARGET)))
        .map_err(policy)?
        .add_rules(writable)
        .map_err(policy)?
        .add_rules(path_beneath_rules(DEVICES, device_access()))
        .map_err(policy)?
        .restrict_self()
        .map_err(policy)?;
    match status.ruleset {
        RulesetStatus::NotEnforced => {
            Err(Refused::Unsupported("the ruleset is not enforced".into()))
        }
        s => Ok(s),
    }
}

/// What a device file may be used for.
fn device_access() -> landlock::BitFlags<AccessFs> {
    (AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::IoctlDev) & AccessFs::from_all(ABI_TARGET)
}

fn main() -> ExitCode {
    let args = match parse(std::env::args_os().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "taso-landlock: {e}\nusage: taso-landlock [--write PATH]... -- COMMAND [ARGS...]"
            );
            return ExitCode::from(EXIT_USAGE);
        }
    };
    match restrict(&args.write) {
        Ok(RulesetStatus::FullyEnforced) => {}
        Ok(_) => {
            eprintln!("taso-landlock: partially enforced (this kernel lacks some Landlock rights)")
        }
        Err(Refused::Unsupported(e)) => {
            eprintln!("taso-landlock: Landlock is not available, refusing to run the agent: {e}");
            return ExitCode::from(EXIT_UNSUPPORTED);
        }
        Err(Refused::Policy(e)) => {
            eprintln!("taso-landlock: {e}");
            return ExitCode::from(EXIT_POLICY);
        }
    }
    let err = Command::new(&args.command[0])
        .args(&args.command[1..])
        .exec();
    eprintln!("taso-landlock: cannot run {:?}: {err}", args.command[0]);
    ExitCode::from(EXIT_EXEC)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn defaults_to_work_and_tmp() {
        let a = parse(os(&["--", "/bin/agent", "-x"])).unwrap();
        assert_eq!(a.write, vec![PathBuf::from("/work"), PathBuf::from("/tmp")]);
        assert_eq!(a.command, os(&["/bin/agent", "-x"]));
    }

    #[test]
    fn explicit_write_paths_replace_the_defaults() {
        let a = parse(os(&["--write", "/a", "--write", "/b", "--", "c"])).unwrap();
        assert_eq!(a.write, vec![PathBuf::from("/a"), PathBuf::from("/b")]);
    }

    #[test]
    fn bad_command_lines() {
        for bad in [
            &[][..],
            &["/bin/agent"],
            &["--"],
            &["--write"],
            &["--write", "rel", "--", "c"],
            &["-x", "--", "c"],
        ] {
            assert!(parse(os(bad)).is_err(), "{bad:?}");
        }
        // After `--` everything is the command, flags included.
        assert_eq!(
            parse(os(&["--", "c", "--write", "/x"])).unwrap().command,
            os(&["c", "--write", "/x"])
        );
    }

    #[test]
    fn devices_get_no_directory_rights() {
        let d = device_access();
        assert!(d.contains(AccessFs::WriteFile));
        assert!(!d.contains(AccessFs::MakeReg));
        assert!(!d.contains(AccessFs::RemoveFile));
        assert!(!d.contains(AccessFs::Execute));
    }
}
