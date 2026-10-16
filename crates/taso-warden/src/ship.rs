//! Where shipped bytes go, and where `fs` streams come from
//! (v1.0 §1 P1–P2, §3).
//!
//! An [`ObjectStore`] keeps objects by key: [`LocalStore`] in a local
//! directory (atomic: temp file, fsync, rename, fsync the directory), and
//! Garage (S3) later behind the same trait.  A [`Sender`] produces the ZFS
//! send stream of a Seal snapshot, full or incremental; [`ZfsSend`] runs
//! `zfs send`.
//!
//! What is shipped, and how it is laid out in the store, is
//! [`crate::pack`]: one pack object per shipment, carrying the log and,
//! for a Seal, its `fs` stream.
//!
//! Normative references: v1.0 §1 (P1, P2), §3.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use taso_core::envelope::Lsn;

use crate::zfs::Dataset;

// ── Object store ────────────────────────────────────────────────────

/// A byte stream being read: a send stream, or an object from a store.
pub type ByteStream = Box<dyn Read + Send>;

/// Where streams are kept.
pub trait ObjectStore {
    /// Store `data` under `key`, atomically: the key holds either nothing
    /// (or its previous object) or all of `data`.  Returns bytes written.
    fn put(&self, key: &str, data: &mut dyn Read) -> io::Result<u64>;
    /// The object under `key`, if any.
    fn get(&self, key: &str) -> io::Result<Option<ByteStream>>;
    /// Whether `key` exists.
    fn exists(&self, key: &str) -> io::Result<bool>;
    /// Every key under `prefix` (a valid key, read as a directory: the
    /// keys that start with `prefix/`), at any depth, in byte order.
    /// Objects still being written are not listed.
    fn list(&self, prefix: &str) -> io::Result<Vec<String>>;
}

/// Keys are `/`-separated components of `[A-Za-z0-9._-]`, none of them
/// `.` or `..`, no leading or trailing `/`.
pub fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.split('/').all(|c| {
            !c.is_empty()
                && c != "."
                && c != ".."
                && c.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

fn bad_key(key: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("invalid object key {key:?}"))
}

/// An [`ObjectStore`] in a local directory.
#[derive(Debug)]
pub struct LocalStore {
    root: PathBuf,
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Name prefix of [`LocalStore`]'s temp files (never a listed key).
const TMP_PREFIX: &str = ".tmp-";

impl LocalStore {
    /// A store rooted at `root`, which must exist.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path(&self, key: &str) -> io::Result<PathBuf> {
        if !valid_key(key) {
            return Err(bad_key(key));
        }
        Ok(self.root.join(key))
    }
}

impl ObjectStore for LocalStore {
    fn put(&self, key: &str, data: &mut dyn Read) -> io::Result<u64> {
        let path = self.path(key)?;
        let dir = path.parent().expect("a key has a file name").to_path_buf();
        fs::create_dir_all(&dir)?;
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!("{TMP_PREFIX}{}-{n}", std::process::id()));
        let result = (|| {
            let mut f = File::create(&tmp)?;
            let written = io::copy(data, &mut f)?;
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp, &path)?;
            File::open(&dir)?.sync_all()?;
            Ok(written)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    fn get(&self, key: &str) -> io::Result<Option<ByteStream>> {
        match File::open(self.path(key)?) {
            Ok(f) => Ok(Some(Box::new(f))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn exists(&self, key: &str) -> io::Result<bool> {
        Ok(self.path(key)?.is_file())
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        let root = self.path(prefix)?;
        let mut keys = Vec::new();
        // (directory, its key)
        let mut todo = vec![(root, prefix.to_string())];
        while let Some((dir, key)) = todo.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            for entry in entries {
                let entry = entry?;
                let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
                if name.starts_with(TMP_PREFIX) {
                    continue;
                }
                let child = format!("{key}/{name}");
                if !valid_key(&child) {
                    continue; // not something put() could have made
                }
                let ty = entry.file_type()?;
                if ty.is_dir() {
                    todo.push((entry.path(), child));
                } else if ty.is_file() {
                    keys.push(child);
                }
            }
        }
        keys.sort();
        Ok(keys)
    }
}

// ── Sending ─────────────────────────────────────────────────────────

/// Produces send streams.
pub trait Sender {
    /// The stream of `dataset@<to>`, incremental from the snapshot `from`
    /// (a full snapshot name: an earlier Seal of `dataset`, or the parent
    /// Seal snapshot `dataset` is a clone of) if given, else full.  The
    /// reader fails, rather than ends, if the stream is incomplete.
    fn send(&self, dataset: &Dataset, from: Option<&str>, to: Lsn) -> io::Result<ByteStream>;
}

/// [`Sender`] running `zfs send`.
#[derive(Clone, Debug)]
pub struct ZfsSend {
    program: PathBuf,
}

impl Default for ZfsSend {
    fn default() -> Self {
        Self { program: PathBuf::from("zfs") }
    }
}

impl Sender for ZfsSend {
    fn send(&self, dataset: &Dataset, from: Option<&str>, to: Lsn) -> io::Result<ByteStream> {
        let mut cmd = Command::new(&self.program);
        cmd.arg("send");
        if let Some(f) = from {
            cmd.arg("-i").arg(f);
        }
        cmd.arg(dataset.seal_snapshot(to));
        let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
        let stdout = child.stdout.take().expect("piped");
        Ok(Box::new(ChildReader { child: Some(child), stdout }))
    }
}

/// A child's stdout that turns a non-zero exit into a read error at the
/// end, so a failed `zfs send` is never mistaken for a short stream.
struct ChildReader {
    child: Option<Child>,
    stdout: ChildStdout,
}

impl Read for ChildReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.stdout.read(buf)?;
        if n == 0 {
            if let Some(mut child) = self.child.take() {
                let mut err = String::new();
                if let Some(mut e) = child.stderr.take() {
                    let _ = e.read_to_string(&mut err);
                }
                let status = child.wait()?;
                if !status.success() {
                    return Err(io::Error::other(format!("zfs send failed ({status}): {}", err.trim())));
                }
            }
        }
        Ok(n)
    }
}

impl Drop for ChildReader {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_validated() {
        for ok in ["a", "a/b.c", "vessels/ab12/pack/00000000000000000001-00000000000000000000-00000000000000000000"] {
            assert!(valid_key(ok), "{ok}");
        }
        for bad in ["", "/a", "a/", "a//b", "a/../b", "./a", "a b", "a\\b"] {
            assert!(!valid_key(bad), "{bad:?}");
        }
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        assert!(store.put("../escape", &mut &b"x"[..]).is_err());
    }

    #[test]
    fn put_get_exists_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        assert!(store.get("a/b").unwrap().is_none());
        assert!(!store.exists("a/b").unwrap());
        assert_eq!(store.put("a/b", &mut &b"hello"[..]).unwrap(), 5);
        let mut v = Vec::new();
        store.get("a/b").unwrap().unwrap().read_to_end(&mut v).unwrap();
        assert_eq!(v, b"hello");
        assert!(store.exists("a/b").unwrap());
        // A second put replaces the object whole.
        store.put("a/b", &mut &b"bye"[..]).unwrap();
        let mut v = Vec::new();
        store.get("a/b").unwrap().unwrap().read_to_end(&mut v).unwrap();
        assert_eq!(v, b"bye");
    }

    #[test]
    fn list_returns_every_key_under_a_prefix_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        for k in ["v/ab/pack/00000000000000000010", "v/ab/pack/00000000000000000002", "v/ab/fs/x.meta", "v/abc/pack/1", "w/1"] {
            store.put(k, &mut &b"x"[..]).unwrap();
        }
        assert_eq!(
            store.list("v/ab").unwrap(),
            vec!["v/ab/fs/x.meta", "v/ab/pack/00000000000000000002", "v/ab/pack/00000000000000000010"],
        );
        // `v/ab` is a directory boundary: `v/abc` is not under it.
        assert_eq!(store.list("v/ab/pack").unwrap().len(), 2);
        assert_eq!(store.list("v").unwrap().len(), 4);
        assert_eq!(store.list("nothing/here").unwrap(), Vec::<String>::new());
        assert!(store.list("../up").is_err());
        assert!(store.list("").is_err());
    }

    #[test]
    fn list_skips_objects_being_written() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        store.put("v/a/1", &mut &b"x"[..]).unwrap();
        // A put in progress (or one a crash left behind).
        fs::write(dir.path().join("v/a").join(format!("{TMP_PREFIX}9-9")), b"partial").unwrap();
        // A file put() could never have made.
        fs::write(dir.path().join("v/a/has space"), b"?").unwrap();
        assert_eq!(store.list("v/a").unwrap(), vec!["v/a/1"]);
        // A failed put leaves nothing listed.
        struct Dies;
        impl Read for Dies {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("died"))
            }
        }
        assert!(store.put("v/a/2", &mut Dies).is_err());
        assert_eq!(store.list("v/a").unwrap(), vec!["v/a/1"]);
    }
}
