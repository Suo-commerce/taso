//! Verification attempts (P4 spec rev. 20 §3.4; D64–D70; file 7).
//!
//! This part (file 7a) is what one attempt does on a node, apart from
//! its records:
//!
//! - [`Vconf::parse`]: the verifier config (D64), whose limits can only
//!   lower the node's ([`VerifierLimits`], §11.1);
//! - [`run_capped`]: run a process with its standard output and error
//!   captured together up to a bound, killed past the bound or past its
//!   wall time (D67);
//! - [`outcome_of`]: how that run ends an attempt.
//!
//! The container's profile is [`crate::runtime::verifier_config`] (D65).
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 20, BLAKE3
//! `77cb877ff0c826ac48f8302b2f468192cfe6e7f46923f19fb6c0bcde79d4c475`.

use std::io::{self, Read};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use taso_core::contract::Outcome;

/// The node's verifier limits (`verifier.*`, §11.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierLimits {
    /// `verifier.output_bound`, in bytes.
    pub output_bound: u64,
    /// `verifier.wall_seconds`.
    pub wall_seconds: u64,
    /// `verifier.cpu_seconds`.
    pub cpu_seconds: u64,
    /// `verifier.memory_bytes`.
    pub memory_bytes: u64,
}

impl Default for VerifierLimits {
    fn default() -> Self {
        Self {
            output_bound: 64 << 10,
            wall_seconds: 600,
            cpu_seconds: 600,
            memory_bytes: 2 << 30,
        }
    }
}

/// A verifier config (D64).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vconf {
    /// The command run inside the verifier Template.
    pub entry: Vec<String>,
    /// Extra environment, `KEY=value`.
    pub env: Vec<String>,
    /// The limits it runs under: the node's, lowered by the config.
    pub limits: VerifierLimits,
}

impl Vconf {
    /// Read a vconf's bytes under the node's limits.  The error is the
    /// reason an attempt ends `LaunchFailed`.
    pub fn parse(bytes: &[u8], node: &VerifierLimits) -> Result<Self, String> {
        let text = std::str::from_utf8(bytes).map_err(|_| "the vconf is not UTF-8".to_string())?;
        let v: toml::Table = text
            .parse()
            .map_err(|e: toml::de::Error| format!("the vconf is not TOML: {}", e.message()))?;
        for k in v.keys() {
            if ![
                "version",
                "entry",
                "env",
                "wall_seconds",
                "cpu_seconds",
                "memory_bytes",
                "output_bound",
            ]
            .contains(&k.as_str())
            {
                return Err(format!("the vconf has an unknown key {k:?}"));
            }
        }
        if v.get("version").and_then(|x| x.as_integer()) != Some(1) {
            return Err("the vconf's \"version\" must be 1".into());
        }
        let strings = |key: &str| -> Result<Vec<String>, String> {
            match v.get(key) {
                None => Ok(Vec::new()),
                Some(toml::Value::Array(a)) => a
                    .iter()
                    .map(|x| {
                        x.as_str()
                            .map(str::to_string)
                            .ok_or_else(|| format!("the vconf's {key:?} must be strings"))
                    })
                    .collect(),
                Some(_) => Err(format!("the vconf's {key:?} must be an array of strings")),
            }
        };
        let entry = strings("entry")?;
        if !entry.first().is_some_and(|e| e.starts_with('/')) {
            return Err("the vconf's \"entry\" must start with an absolute path".into());
        }
        let env = strings("env")?;
        for e in &env {
            let ok = e.split_once('=').is_some_and(|(k, _)| {
                !k.is_empty()
                    && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    && !k.starts_with("TASO_")
                    && !["PATH", "HOME"].contains(&k)
            });
            if !ok {
                return Err(format!(
                    "the vconf's env entry {e:?} is not KEY=value or is reserved"
                ));
            }
        }
        let limit = |key: &str, node: u64| -> Result<u64, String> {
            match v.get(key) {
                None => Ok(node),
                Some(x) => {
                    let n =
                        x.as_integer().filter(|n| *n > 0).ok_or_else(|| {
                            format!("the vconf's {key:?} must be a positive integer")
                        })? as u64;
                    if n > node {
                        return Err(format!(
                            "the vconf's {key:?} ({n}) is above the node's ({node}): a vconf can only lower a limit"
                        ));
                    }
                    Ok(n)
                }
            }
        };
        Ok(Self {
            entry,
            env,
            limits: VerifierLimits {
                output_bound: limit("output_bound", node.output_bound)?,
                wall_seconds: limit("wall_seconds", node.wall_seconds)?,
                cpu_seconds: limit("cpu_seconds", node.cpu_seconds)?,
                memory_bytes: limit("memory_bytes", node.memory_bytes)?,
            },
        })
    }
}

/// How a capped run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// It exited: its status (a signal *n* as 128 + *n*).
    Exit(u32),
    /// Killed past its wall time.
    Timeout,
    /// Killed past its output bound.
    OutputLimit,
}

/// Run `cmd` with its standard output and error captured together, in
/// order, up to `bound` bytes; past the bound, or past `wall`, `kill` is
/// called (with the child's pid) and the run ends `OutputLimit` or
/// `Timeout`.  Returns how it ended and the captured output (at most
/// `bound` bytes).
pub fn run_capped(
    cmd: &mut Command,
    wall: Duration,
    bound: u64,
    kill: &dyn Fn(u32),
) -> io::Result<(Ended, Vec<u8>)> {
    let (reader, writer) = io::pipe()?;
    let writer2 = writer.try_clone()?;
    let mut child: Child = cmd
        .stdin(Stdio::null())
        .stdout(writer)
        .stderr(writer2)
        .spawn()?;
    // Our copies of the write end are gone with `cmd`'s; the read end sees
    // EOF once the child and everything it started have closed theirs.
    let pid = child.id();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let reading = std::thread::spawn(move || -> io::Result<(Vec<u8>, bool)> {
        let mut out = Vec::new();
        let mut r = reader;
        let mut buf = [0u8; 8192];
        let mut over = false;
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let room = bound.saturating_sub(out.len() as u64) as usize;
            out.extend_from_slice(&buf[..n.min(room)]);
            if n > room && !over {
                over = true;
                let _ = tx.send(());
            }
        }
        Ok((out, over))
    });
    let start = Instant::now();
    let mut ended = None;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if ended.is_none() {
            if rx.try_recv().is_ok() {
                ended = Some(Ended::OutputLimit);
                kill(pid);
            } else if start.elapsed() >= wall {
                ended = Some(Ended::Timeout);
                kill(pid);
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    drop(cmd_stdio_guard(cmd));
    let (out, over) = reading
        .join()
        .map_err(|_| io::Error::other("the output reader panicked"))??;
    let code = {
        use std::os::unix::process::ExitStatusExt;
        match (status.code(), status.signal()) {
            (Some(c), _) => c as u32,
            (None, Some(s)) => 128 + s as u32,
            (None, None) => 255,
        }
    };
    let ended = match ended {
        Some(e) => e,
        // The bound was passed just as it exited.
        None if over => Ended::OutputLimit,
        None => Ended::Exit(code),
    };
    Ok((ended, out))
}

/// Drop the `Command`'s own handles to the pipe (it keeps the `Stdio`s it
/// was given until it is dropped or reconfigured).
fn cmd_stdio_guard(cmd: &mut Command) -> &mut Command {
    cmd.stdout(Stdio::null()).stderr(Stdio::null())
}

/// The exit status of a process killed by `SIGXCPU` (`RLIMIT_CPU`).
pub const SIGXCPU_STATUS: u32 = 128 + 24;

/// How a run ends an attempt (D67): a process killed by `SIGXCPU` is out
/// of CPU time, `Timeout`.
pub fn outcome_of(ended: Ended) -> Outcome {
    match ended {
        Ended::Timeout | Ended::Exit(SIGXCPU_STATUS) => Outcome::Timeout,
        Ended::OutputLimit => Outcome::OutputLimit,
        Ended::Exit(code) => Outcome::Exit { code },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut c = Command::new("sh");
        c.arg("-c").arg(script);
        c
    }

    fn kill(pid: u32) {
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(pid.to_string())
            .status();
    }

    #[test]
    fn output_is_captured_in_order_and_the_exit_status_kept() {
        let (e, out) = run_capped(
            &mut sh("echo one; echo two >&2; echo three; exit 3"),
            Duration::from_secs(10),
            1 << 10,
            &kill,
        )
        .unwrap();
        assert_eq!(e, Ended::Exit(3));
        assert_eq!(out, b"one\ntwo\nthree\n");
        assert_eq!(outcome_of(e), Outcome::Exit { code: 3 });
    }

    #[test]
    fn past_the_bound_it_is_killed_with_the_first_bytes_kept() {
        let (e, out) =
            run_capped(&mut sh("exec yes"), Duration::from_secs(10), 1000, &kill).unwrap();
        assert_eq!(e, Ended::OutputLimit);
        assert_eq!(out.len(), 1000);
        assert!(out.starts_with(b"y\ny\n"));
        assert_eq!(outcome_of(e), Outcome::OutputLimit);
    }

    #[test]
    fn past_its_wall_time_it_is_killed() {
        let t = Instant::now();
        let (e, _) = run_capped(
            &mut sh("echo started; exec sleep 30"),
            Duration::from_millis(300),
            1 << 10,
            &kill,
        )
        .unwrap();
        assert_eq!(e, Ended::Timeout);
        assert!(t.elapsed() < Duration::from_secs(10));
        assert_eq!(outcome_of(e), Outcome::Timeout);
    }

    #[test]
    fn out_of_cpu_is_a_timeout_and_other_signals_an_exit() {
        let (e, _) =
            run_capped(&mut sh("kill -XCPU $$"), Duration::from_secs(10), 64, &kill).unwrap();
        assert_eq!(e, Ended::Exit(SIGXCPU_STATUS));
        assert_eq!(outcome_of(e), Outcome::Timeout);
        let (e, _) =
            run_capped(&mut sh("kill -TERM $$"), Duration::from_secs(10), 64, &kill).unwrap();
        assert_eq!(outcome_of(e), Outcome::Exit { code: 128 + 15 });
    }

    #[test]
    fn a_vconf_can_only_lower_the_nodes_limits() {
        let node = VerifierLimits::default();
        let v = Vconf::parse(
            b"version = 1\nentry = [\"/bin/check\", \"--all\"]\nenv = [\"MODE=strict\"]\nwall_seconds = 60\n",
            &node,
        )
        .unwrap();
        assert_eq!(v.entry, ["/bin/check", "--all"]);
        assert_eq!(v.env, ["MODE=strict"]);
        assert_eq!(v.limits.wall_seconds, 60);
        assert_eq!(v.limits.cpu_seconds, node.cpu_seconds);
        assert_eq!(v.limits.output_bound, 64 << 10);
        for (bad, says) in [
            (&b"entry = [\"/bin/x\"]\n"[..], "version"),
            (b"version = 2\nentry = [\"/bin/x\"]\n", "version"),
            (b"version = 1\n", "absolute"),
            (b"version = 1\nentry = [\"check\"]\n", "absolute"),
            (
                b"version = 1\nentry = [\"/bin/x\"]\nwall_seconds = 601\n",
                "only lower",
            ),
            (
                b"version = 1\nentry = [\"/bin/x\"]\nwall_seconds = 0\n",
                "positive",
            ),
            (
                b"version = 1\nentry = [\"/bin/x\"]\nenv = [\"TASO_FIELD=x\"]\n",
                "reserved",
            ),
            (
                b"version = 1\nentry = [\"/bin/x\"]\nnetwork = true\n",
                "unknown key",
            ),
            (b"version = 1\nentry = \"/bin/x\"\n", "array"),
            (b"\xff", "UTF-8"),
            (b"version = = 1", "TOML"),
        ] {
            let e = Vconf::parse(bad, &node).unwrap_err();
            assert!(e.contains(says), "{says}: {e}");
        }
    }
}
