//! A client for `taso-blkd`'s control socket (adoption step 3 of the plan
//! `Taso_plan_blk_adoption_2026-10-18`).
//!
//! The Warden's block-log `Pool` and `Layers` talk to the daemon through
//! this; it needs no ublk and builds anywhere.  One [`Client`] is one
//! connection; commands on it are answered in order.
//!
//! The protocol is one line per command, words separated by spaces, one
//! answer line starting `ok` or `err`.  So every argument is checked
//! before it is sent: an argument with a space, a newline or any other
//! control character is refused here ([`ClientError::BadArgument`]), never
//! sent, because it could turn one command into two.
//!
//! ```no_run
//! use taso_blk::client::Client;
//! let mut c = Client::connect("/run/taso-blk.sock".as_ref())?;
//! let root = c.root()?;
//! let b = c.branch(root, Some("tank/taso/vessel-a"))?;
//! let dev = c.attach(b)?;            // mkfs and mount dev, write, ...
//! let seal = c.seal(b, b"lsn+hash")?;
//! assert_eq!(c.seals(b)?, vec![(seal, b"lsn+hash".to_vec())]);
//! # let _ = dev;
//! # Ok::<(), taso_blk::client::ClientError>(())
//! ```

use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::map::LayerId;

/// How long a command may take before the client gives up.  Detaching
/// many devices, or `quit` with many attached, takes seconds.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Why a client call failed.
#[derive(Debug)]
pub enum ClientError {
    /// The socket failed (including a timeout).  The connection should not
    /// be used again: an answer may still be on its way.
    Io(io::Error),
    /// The daemon answered `err …`: the operation was refused.
    Daemon(String),
    /// The daemon's answer does not fit the command.
    Protocol(String),
    /// An argument that cannot be sent safely (empty, or has a space or a
    /// control character).  Nothing was sent.
    BadArgument(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "taso-blkd socket: {e}"),
            Self::Daemon(e) => write!(f, "taso-blkd: {e}"),
            Self::Protocol(e) => write!(f, "taso-blkd answered something unexpected: {e}"),
            Self::BadArgument(a) => write!(f, "argument {a:?} cannot be sent (empty, space or control character)"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Result of a client call.
pub type Result<T> = std::result::Result<T, ClientError>;

/// What a layer is, as `info` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    /// A branch (writable) or a Seal (frozen).
    pub kind: LayerKind,
    /// The layer it stands on; `None` for a root Seal.
    pub parent: Option<LayerId>,
    /// The branch's name, if it has one.
    pub name: Option<String>,
    /// The Seal's tag (empty if it has none); `None` for a branch.
    pub tag: Option<Vec<u8>>,
    /// The branch a Seal was made from; `None` for a branch or a root Seal.
    pub origin: Option<LayerId>,
    /// The block device of an attached branch.
    pub dev: Option<PathBuf>,
}

/// A layer's kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayerKind {
    /// Writable.
    Branch,
    /// Frozen.
    Seal,
}

/// One connection to `taso-blkd`.
pub struct Client {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Client {
    /// Connect to the daemon's socket, with [`DEFAULT_TIMEOUT`].
    pub fn connect(socket: &Path) -> Result<Self> {
        let s = UnixStream::connect(socket)?;
        let mut c = Self { reader: BufReader::new(s.try_clone()?), writer: s };
        c.set_timeout(DEFAULT_TIMEOUT)?;
        Ok(c)
    }

    /// How long each command may take.
    pub fn set_timeout(&mut self, t: Duration) -> Result<()> {
        self.writer.set_read_timeout(Some(t))?;
        self.writer.set_write_timeout(Some(t))?;
        Ok(())
    }

    /// A Template's first Seal (empty, zeros).  Durable when it returns.
    pub fn root(&mut self) -> Result<LayerId> {
        layer(&self.call(&["root"])?)
    }

    /// A branch on `seal`, without a device, named `name` if given.  A bad
    /// or taken name makes nothing.  Durable at the next [`Client::flush`].
    pub fn branch(&mut self, seal: LayerId, name: Option<&str>) -> Result<LayerId> {
        let seal = seal.to_string();
        let mut w = vec!["branch", seal.as_str()];
        w.extend(name);
        layer(&self.call(&w)?)
    }

    /// [`Client::branch`], then [`Client::attach`]: the branch and its device.
    pub fn fork(&mut self, seal: LayerId, name: Option<&str>) -> Result<(LayerId, PathBuf)> {
        let seal = seal.to_string();
        let mut w = vec!["fork", seal.as_str()];
        w.extend(name);
        let a = self.call(&w)?;
        match a.split_once(' ') {
            Some((b, dev)) if !dev.contains(' ') => Ok((layer(b)?, PathBuf::from(dev))),
            _ => Err(ClientError::Protocol(format!("fork answered {a:?}"))),
        }
    }

    /// A block device for `branch`, to mount.
    pub fn attach(&mut self, branch: LayerId) -> Result<PathBuf> {
        let a = self.call(&["attach", &branch.to_string()])?;
        if a.is_empty() || a.contains(' ') {
            return Err(ClientError::Protocol(format!("attach answered {a:?}")));
        }
        Ok(PathBuf::from(a))
    }

    /// Stop `branch`'s device (unmount it first).
    pub fn detach(&mut self, branch: LayerId) -> Result<()> {
        self.call_empty(&["detach", &branch.to_string()])
    }

    /// Freeze `branch` as a Seal carrying `tag` (at most 64 bytes).  A
    /// mounted ext4 must be made consistent first (frozen or unmounted).
    /// Durable when it returns.
    pub fn seal(&mut self, branch: LayerId, tag: &[u8]) -> Result<LayerId> {
        let (b, t) = (branch.to_string(), hex(tag));
        let mut w = vec!["seal", b.as_str()];
        if !t.is_empty() {
            w.push(t.as_str());
        }
        layer(&self.call(&w)?)
    }

    /// Name `branch`, or take its name away (`None`).
    pub fn name(&mut self, branch: LayerId, name: Option<&str>) -> Result<()> {
        let b = branch.to_string();
        let mut w = vec!["name", b.as_str()];
        w.extend(name);
        self.call_empty(&w)
    }

    /// The live branch named `name`, if any.
    pub fn find(&mut self, name: &str) -> Result<Option<LayerId>> {
        match self.call(&["find", name]) {
            Ok(a) => Ok(Some(layer(&a)?)),
            Err(ClientError::Daemon(e)) if e.starts_with("no branch named ") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The live Seals made from `branch`, oldest first, with their tags.
    pub fn seals(&mut self, branch: LayerId) -> Result<Vec<(LayerId, Vec<u8>)>> {
        let a = self.call(&["seals", &branch.to_string()])?;
        a.split_whitespace()
            .map(|item| {
                let (l, t) = item.split_once(':').ok_or_else(|| ClientError::Protocol(format!("seals answered {a:?}")))?;
                Ok((layer(l)?, unhex(t)?))
            })
            .collect()
    }

    /// What `layer` is.
    pub fn info(&mut self, layer_id: LayerId) -> Result<Info> {
        let a = self.call(&["info", &layer_id.to_string()])?;
        let mut kv = BTreeMap::new();
        for item in a.split_whitespace() {
            let (k, v) = item.split_once('=').ok_or_else(|| ClientError::Protocol(format!("info answered {a:?}")))?;
            kv.insert(k, (v != "-").then_some(v));
        }
        let field = |k: &str| kv.get(k).copied().ok_or_else(|| ClientError::Protocol(format!("info has no {k}: {a:?}")));
        let kind = match field("kind")? {
            Some("branch") => LayerKind::Branch,
            Some("seal") => LayerKind::Seal,
            other => return Err(ClientError::Protocol(format!("info kind {other:?}"))),
        };
        Ok(Info {
            kind,
            parent: field("parent")?.map(layer).transpose()?,
            name: field("name")?.map(str::to_string),
            // A Seal without a tag reports an empty one; the daemon writes
            // an empty tag as "", which arrives here as `Some("")`.
            tag: match (kind, field("tag")?) {
                (LayerKind::Seal, t) => Some(unhex(t.unwrap_or(""))?),
                (LayerKind::Branch, _) => None,
            },
            origin: field("origin")?.map(layer).transpose()?,
            dev: field("dev")?.map(PathBuf::from),
        })
    }

    /// Drop a layer: a branch (its device is stopped first) or a Seal
    /// nothing stands on.
    pub fn drop_layer(&mut self, layer_id: LayerId) -> Result<()> {
        self.call_empty(&["drop", &layer_id.to_string()])
    }

    /// End a group: everything before is durable.  Returns the Flush
    /// record's sequence number.
    pub fn flush(&mut self) -> Result<u64> {
        let a = self.call(&["flush"])?;
        a.parse().map_err(|_| ClientError::Protocol(format!("flush answered {a:?}")))
    }

    /// The daemon's counters, as `key → value`.
    pub fn stats(&mut self) -> Result<BTreeMap<String, String>> {
        let a = self.call(&["stats"])?;
        a.split_whitespace()
            .map(|kv| {
                kv.split_once('=')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .ok_or_else(|| ClientError::Protocol(format!("stats answered {a:?}")))
            })
            .collect()
    }

    /// Stop every device, flush, and end the daemon.
    pub fn quit(mut self) -> Result<()> {
        self.call_empty(&["quit"])
    }

    /// Send one command; the answer after `ok` (maybe empty).
    fn call(&mut self, words: &[&str]) -> Result<String> {
        for w in words {
            if w.is_empty() || w.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(ClientError::BadArgument(w.to_string()));
            }
        }
        let mut line = words.join(" ");
        line.push('\n');
        self.writer.write_all(line.as_bytes())?;
        let mut answer = String::new();
        if self.reader.read_line(&mut answer)? == 0 {
            return Err(ClientError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "taso-blkd closed the connection")));
        }
        let answer = answer.trim_end_matches('\n');
        if answer == "ok" {
            Ok(String::new())
        } else if let Some(rest) = answer.strip_prefix("ok ") {
            Ok(rest.to_string())
        } else if let Some(e) = answer.strip_prefix("err ") {
            Err(ClientError::Daemon(e.to_string()))
        } else {
            Err(ClientError::Protocol(answer.to_string()))
        }
    }

    /// A command whose answer is a bare `ok`.
    fn call_empty(&mut self, words: &[&str]) -> Result<()> {
        let a = self.call(words)?;
        if a.is_empty() {
            Ok(())
        } else {
            Err(ClientError::Protocol(format!("{} answered {a:?}", words[0])))
        }
    }
}

/// `L<n>` as a layer id.
fn layer(s: &str) -> Result<LayerId> {
    s.strip_prefix('L')
        .and_then(|n| n.parse().ok())
        .map(LayerId::from_raw)
        .ok_or_else(|| ClientError::Protocol(format!("{s:?} is not a layer id")))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    let bad = || ClientError::Protocol(format!("bad hex {s:?}"));
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return Err(bad());
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| bad())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread::JoinHandle;

    /// A scripted daemon: answers each line with the next answer, and
    /// returns the lines it received.
    fn fake(answers: &[&str]) -> (tempfile::TempDir, PathBuf, JoinHandle<Vec<String>>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sock");
        let listener = UnixListener::bind(&path).unwrap();
        let answers: Vec<String> = answers.iter().map(|a| a.to_string()).collect();
        let h = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut w = s;
            let mut got = Vec::new();
            for a in answers {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                got.push(line.trim_end().to_string());
                writeln!(w, "{a}").unwrap();
            }
            got
        });
        (dir, path, h)
    }

    #[test]
    fn commands_are_sent_and_answers_parsed() {
        let tag = [7u8, 0, 0xab];
        let (_d, path, h) = fake(&[
            "ok L0",
            "ok L1",
            "ok L2 /dev/ublkb3",
            "ok /dev/ublkb4",
            "ok L5",
            "ok L5:0700ab L7:",
            "ok kind=seal parent=L0 name=- tag=0700ab origin=L1 dev=-",
            "ok kind=branch parent=L5 name=tank/a tag=- origin=- dev=/dev/ublkb4",
            "ok",
            "ok 42",
            "ok log_bytes=10 layers=3",
        ]);
        let mut c = Client::connect(&path).unwrap();
        let l = |n| LayerId::from_raw(n);
        assert_eq!(c.root().unwrap(), l(0));
        assert_eq!(c.branch(l(0), Some("tank/a")).unwrap(), l(1));
        assert_eq!(c.fork(l(0), None).unwrap(), (l(2), PathBuf::from("/dev/ublkb3")));
        assert_eq!(c.attach(l(1)).unwrap(), PathBuf::from("/dev/ublkb4"));
        assert_eq!(c.seal(l(1), &tag).unwrap(), l(5));
        assert_eq!(c.seals(l(1)).unwrap(), vec![(l(5), tag.to_vec()), (l(7), vec![])]);
        let i = c.info(l(5)).unwrap();
        assert_eq!(
            i,
            Info { kind: LayerKind::Seal, parent: Some(l(0)), name: None, tag: Some(tag.to_vec()), origin: Some(l(1)), dev: None }
        );
        let i = c.info(l(1)).unwrap();
        assert_eq!((i.kind, i.name.as_deref(), i.tag, i.dev), (LayerKind::Branch, Some("tank/a"), None, Some("/dev/ublkb4".into())));
        c.name(l(1), None).unwrap();
        assert_eq!(c.flush().unwrap(), 42);
        assert_eq!(c.stats().unwrap().get("layers").map(String::as_str), Some("3"));
        drop(c);
        assert_eq!(
            h.join().unwrap(),
            [
                "root", "branch L0 tank/a", "fork L0", "attach L1", "seal L1 0700ab", "seals L1", "info L5", "info L1",
                "name L1", "flush", "stats"
            ]
        );
    }

    #[test]
    fn an_untagged_seal_reports_an_empty_tag() {
        let (_d, path, h) = fake(&["ok L3", "ok kind=seal parent=L2 name=- tag= origin=L1 dev=-"]);
        let mut c = Client::connect(&path).unwrap();
        assert_eq!(c.seal(LayerId::from_raw(1), b"").unwrap(), LayerId::from_raw(3));
        assert_eq!(c.info(LayerId::from_raw(3)).unwrap().tag, Some(vec![]));
        drop(c);
        assert_eq!(h.join().unwrap(), ["seal L1", "info L3"], "no tag word for an empty tag");
    }

    #[test]
    fn refusals_and_missing_names() {
        let (_d, path, _h) = fake(&["err no branch named x", "err branch name \"a\" is taken", "err no layer L9"]);
        let mut c = Client::connect(&path).unwrap();
        assert_eq!(c.find("x").unwrap(), None);
        assert!(matches!(c.branch(LayerId::from_raw(0), Some("a")), Err(ClientError::Daemon(e)) if e.contains("taken")));
        assert!(matches!(c.drop_layer(LayerId::from_raw(9)), Err(ClientError::Daemon(_))));
    }

    #[test]
    fn arguments_that_could_split_a_command_are_never_sent() {
        let (_d, path, h) = fake(&["ok L1"]);
        let mut c = Client::connect(&path).unwrap();
        for bad in ["a b", "a\nquit", "a\tb", "a\rb", "", "a\u{7f}"] {
            assert!(matches!(c.find(bad), Err(ClientError::BadArgument(_))), "{bad:?}");
            assert!(matches!(c.branch(LayerId::from_raw(0), Some(bad)), Err(ClientError::BadArgument(_))), "{bad:?}");
        }
        assert_eq!(c.find("ok").unwrap(), Some(LayerId::from_raw(1)));
        drop(c);
        assert_eq!(h.join().unwrap(), ["find ok"], "only the good command reached the daemon");
    }

    #[test]
    fn answers_that_do_not_fit_are_protocol_errors() {
        let (_d, path, _h) = fake(&["ok banana", "ok", "hello", "ok L1 /dev/a b", "ok L1:zz", "ok kind=thing", "ok 1"]);
        let mut c = Client::connect(&path).unwrap();
        let l0 = LayerId::from_raw(0);
        assert!(matches!(c.root(), Err(ClientError::Protocol(_))));
        assert!(matches!(c.attach(l0), Err(ClientError::Protocol(_))), "empty device path");
        assert!(matches!(c.flush(), Err(ClientError::Protocol(_))), "neither ok nor err");
        assert!(matches!(c.fork(l0, None), Err(ClientError::Protocol(_))));
        assert!(matches!(c.seals(l0), Err(ClientError::Protocol(_))));
        assert!(matches!(c.info(l0), Err(ClientError::Protocol(_))));
        assert!(matches!(c.detach(l0), Err(ClientError::Protocol(_))), "detach answers a bare ok");
    }

    #[test]
    fn a_closed_connection_is_an_io_error() {
        let (_d, path, h) = fake(&[]);
        let mut c = Client::connect(&path).unwrap();
        h.join().unwrap(); // the fake accepted and closed without answering
        assert!(matches!(c.root(), Err(ClientError::Io(_))));
    }

    #[test]
    fn hex_round_trips() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(unhex(&hex(&all)).unwrap(), all);
        assert_eq!(unhex("0A").unwrap(), [10]);
        for bad in ["0", "zz", "é0"] {
            assert!(unhex(bad).is_err(), "{bad:?}");
        }
    }
}
