//! Where shipped bytes go, and where `fs` streams come from
//! (v1.0 §1 P1–P2, §3).
//!
//! An [`ObjectStore`] keeps objects by key: [`LocalStore`] in a local
//! directory (atomic: temp file, fsync, rename, fsync the directory), and
//! Garage (S3) ([`crate::s3`]) behind the same trait.  A [`Sender`]
//! produces the `fs` stream of a Seal, full or incremental; the block
//! log's is [`crate::blk::BlkSend`].
//!
//! What is shipped, and how it is laid out in the store, is
//! [`crate::pack`]: one pack object per shipment, carrying the log and,
//! for a Seal, its `fs` stream.
//!
//! Normative references: v1.0 §1 (P1, P2), §3.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use taso_core::envelope::Lsn;

use crate::storage::Dataset;

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
    /// As [`ObjectStore::list`], with when each object was last written:
    /// its age, for the reclaimer's grace period (`store.orphan_grace`).
    /// A put again makes it new.  Every store says, none by default: a
    /// reclaimer that cannot tell an object's age must not guess it.
    fn list_times(&self, prefix: &str) -> io::Result<Vec<(String, std::time::SystemTime)>>;
    /// Remove the object under `key`.  `Ok(true)` if it was there and is
    /// gone, `Ok(false)` if there was nothing to remove: a retry after a
    /// crash is a no-op (P4 spec §6.4).  Durable when it returns.
    ///
    /// The store does not log or check who deletes: a caller deletes only
    /// a key it holds the coordinator's claim on, and the claim and its
    /// resolution are the record of what was deleted (P4 spec §2.4).
    ///
    /// A store that cannot delete answers [`io::ErrorKind::Unsupported`].
    fn delete(&self, key: &str) -> io::Result<bool> {
        let _ = key;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this object store cannot delete",
        ))
    }
}

/// A store shared by a node's Vessels (any [`ObjectStore`]).
pub type SharedStore = std::sync::Arc<dyn ObjectStore + Send + Sync>;

impl<T: ObjectStore + ?Sized> ObjectStore for std::sync::Arc<T> {
    fn put(&self, key: &str, data: &mut dyn Read) -> io::Result<u64> {
        (**self).put(key, data)
    }
    fn get(&self, key: &str) -> io::Result<Option<ByteStream>> {
        (**self).get(key)
    }
    fn exists(&self, key: &str) -> io::Result<bool> {
        (**self).exists(key)
    }
    fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        (**self).list(prefix)
    }
    fn list_times(&self, prefix: &str) -> io::Result<Vec<(String, std::time::SystemTime)>> {
        (**self).list_times(prefix)
    }
    fn delete(&self, key: &str) -> io::Result<bool> {
        (**self).delete(key)
    }
}

/// Keys are `/`-separated components of `[A-Za-z0-9._-]`, none of them
/// `.` or `..`, no leading or trailing `/`.
pub fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.split('/').all(|c| {
            !c.is_empty()
                && c != "."
                && c != ".."
                && c.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

fn bad_key(key: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid object key {key:?}"),
    )
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

    /// Every object under `prefix` as (key, its file), in key order.
    fn walk(&self, prefix: &str) -> io::Result<Vec<(String, PathBuf)>> {
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
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
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
                    keys.push((child, entry.path()));
                }
            }
        }
        keys.sort();
        Ok(keys)
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

    /// False only if nothing is there (NotFound, as `get` reads it); any
    /// other error is said, and something there that is not a file is an
    /// error: an unreadable object is never "absent" (audit 2026-11-06,
    /// finding 4: `is_file()` turned every error into false).
    fn exists(&self, key: &str) -> io::Result<bool> {
        let path = self.path(key)?;
        match fs::metadata(&path) {
            Ok(m) if m.is_file() => Ok(true),
            Ok(_) => Err(io::Error::other(format!(
                "{}: there, but not an object file",
                path.display()
            ))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        Ok(self.walk(prefix)?.into_iter().map(|(k, _)| k).collect())
    }

    /// The file's modification time: a put writes a new file and renames
    /// it into place, so a put again makes it new.
    fn list_times(&self, prefix: &str) -> io::Result<Vec<(String, std::time::SystemTime)>> {
        let mut out = Vec::new();
        for (key, path) in self.walk(prefix)? {
            match fs::metadata(&path) {
                Ok(m) => out.push((key, m.modified()?)),
                // Deleted since the walk saw it: not listed.
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Unlink the file, then fsync its directory so the removal survives a
    /// crash.  Empty directories are left: [`LocalStore::list`] does not
    /// list them, and a later put reuses them.
    fn delete(&self, key: &str) -> io::Result<bool> {
        let path = self.path(key)?;
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        }
        let dir = path.parent().expect("a key has a file name");
        File::open(dir)?.sync_all()?;
        Ok(true)
    }
}

// ── Sending ─────────────────────────────────────────────────────────

/// Produces send streams.
pub trait Sender {
    /// The stream of `dataset`'s Seal at `to`, incremental from the Seal
    /// named `from` (a full Seal name, `<dataset>@taso-seal-<lsn>`: an
    /// earlier Seal of `dataset`, or the parent's Seal `dataset` is a
    /// clone of) if given, else full.  The
    /// reader fails, rather than ends, if the stream is incomplete.
    fn send(&self, dataset: &Dataset, from: Option<&str>, to: Lsn) -> io::Result<ByteStream>;
}

/// [`Sender`] of a Chronicle that ships records only and never an `fs`
/// stream -- a Template's log, a genesis Chronicle, the Warden's own
/// Chronicle, and the coordinator's read-only view of a pack directory.
/// The sibling of [`crate::chronicle::NoLayers`].
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NoSend;

impl Sender for NoSend {
    fn send(&self, _: &Dataset, _: Option<&str>, _: Lsn) -> io::Result<ByteStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a records-only Chronicle ships no fs stream",
        ))
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_validated() {
        for ok in [
            "a",
            "a/b.c",
            "vessels/ab12/pack/00000000000000000001-00000000000000000000-00000000000000000000",
        ] {
            assert!(valid_key(ok), "{ok}");
        }
        for bad in ["", "/a", "a/", "a//b", "a/../b", "./a", "a b", "a\\b"] {
            assert!(!valid_key(bad), "{bad:?}");
        }
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        assert!(store.put("../escape", &mut &b"x"[..]).is_err());
    }

    /// Review fix 2a: the local store lists every object with when it was
    /// last written; a put again makes it new.
    #[test]
    fn list_times_gives_each_object_its_last_write() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        store.put("p/obj/a", &mut &b"1"[..]).unwrap();
        store.put("p/obj/b/c", &mut &b"2"[..]).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400);
        let f = std::fs::File::options()
            .write(true)
            .open(dir.path().join("p/obj/a"))
            .unwrap();
        f.set_modified(old).unwrap();
        drop(f);
        let got = store.list_times("p/obj").unwrap();
        let keys: Vec<&str> = got.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["p/obj/a", "p/obj/b/c"], "the keys list() gives");
        assert_eq!(got[0].1, old);
        assert!(got[1].1 > old);
        store.put("p/obj/a", &mut &b"1"[..]).unwrap();
        assert!(
            store.list_times("p/obj").unwrap()[0].1 > old,
            "put again: new"
        );
        assert!(store.list_times("p/none").unwrap().is_empty());
    }

    #[test]
    fn put_get_exists_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        assert!(store.get("a/b").unwrap().is_none());
        assert!(!store.exists("a/b").unwrap());
        assert_eq!(store.put("a/b", &mut &b"hello"[..]).unwrap(), 5);
        let mut v = Vec::new();
        store
            .get("a/b")
            .unwrap()
            .unwrap()
            .read_to_end(&mut v)
            .unwrap();
        assert_eq!(v, b"hello");
        assert!(store.exists("a/b").unwrap());
        // A second put replaces the object whole.
        store.put("a/b", &mut &b"bye"[..]).unwrap();
        let mut v = Vec::new();
        store
            .get("a/b")
            .unwrap()
            .unwrap()
            .read_to_end(&mut v)
            .unwrap();
        assert_eq!(v, b"bye");
    }

    #[test]
    fn list_returns_every_key_under_a_prefix_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        for k in [
            "v/ab/pack/00000000000000000010",
            "v/ab/pack/00000000000000000002",
            "v/ab/fs/x.meta",
            "v/abc/pack/1",
            "w/1",
        ] {
            store.put(k, &mut &b"x"[..]).unwrap();
        }
        assert_eq!(
            store.list("v/ab").unwrap(),
            vec![
                "v/ab/fs/x.meta",
                "v/ab/pack/00000000000000000002",
                "v/ab/pack/00000000000000000010"
            ],
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
        fs::write(
            dir.path().join("v/a").join(format!("{TMP_PREFIX}9-9")),
            b"partial",
        )
        .unwrap();
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

    #[test]
    fn delete_removes_once_and_is_then_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        store.put("v/a/1", &mut &b"x"[..]).unwrap();
        store.put("v/a/2", &mut &b"y"[..]).unwrap();
        assert!(store.delete("v/a/1").unwrap(), "it was there");
        assert!(!store.exists("v/a/1").unwrap());
        assert!(store.get("v/a/1").unwrap().is_none());
        assert_eq!(store.list("v/a").unwrap(), vec!["v/a/2"], "the other stays");
        assert!(!store.delete("v/a/1").unwrap(), "a retry is a no-op");
        assert!(!store.delete("v/never").unwrap());
        // A deleted key can be put again (a replacement, or a re-put).
        store.put("v/a/1", &mut &b"z"[..]).unwrap();
        assert!(store.exists("v/a/1").unwrap());
    }

    #[test]
    fn delete_refuses_invalid_keys_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        store.put("v/a/1", &mut &b"x"[..]).unwrap();
        for bad in ["", "../v/a/1", "v/../v/a/1", "/v/a/1"] {
            assert_eq!(
                store.delete(bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{bad:?}"
            );
        }
        // A prefix is not an object: deleting it removes nothing.
        assert!(store.delete("v/a").is_err());
        assert_eq!(store.list("v").unwrap(), vec!["v/a/1"]);
    }

    #[test]
    fn delete_works_on_pack_names() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        let pack =
            "vessels/ab12/pack/00000000000000000014-00000000000000000009-00000000000000000012";
        let log =
            "vessels/ab12/pack/00000000000000000014-00000000000000000009-00000000000000000000";
        store.put(pack, &mut &b"fs pack"[..]).unwrap();
        store.put(log, &mut &b"log pack"[..]).unwrap();
        assert!(store.delete(pack).unwrap());
        assert_eq!(store.list("vessels/ab12/pack").unwrap(), vec![log]);
    }

    #[test]
    fn a_store_without_delete_says_so() {
        struct NoDelete;
        impl ObjectStore for NoDelete {
            fn put(&self, _: &str, _: &mut dyn Read) -> io::Result<u64> {
                Ok(0)
            }
            fn get(&self, _: &str) -> io::Result<Option<ByteStream>> {
                Ok(None)
            }
            fn exists(&self, _: &str) -> io::Result<bool> {
                Ok(false)
            }
            fn list(&self, _: &str) -> io::Result<Vec<String>> {
                Ok(vec![])
            }
            fn list_times(&self, _: &str) -> io::Result<Vec<(String, std::time::SystemTime)>> {
                Ok(vec![])
            }
        }
        let shared: SharedStore = std::sync::Arc::new(NoDelete);
        assert_eq!(
            shared.delete("a").unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    /// Audit 2026-11-06, finding 4: `exists` says false only for an
    /// object that is not there.  Any other answer of the file system
    /// (ELOOP here; EIO, EACCES alike) is an error, as `get` says it, and
    /// something there that is not a file is an error too, never "absent".
    #[test]
    fn exists_is_false_only_for_not_found() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("loop", dir.path().join("loop")).unwrap();
        std::fs::create_dir_all(dir.path().join("a/dir")).unwrap();
        std::fs::write(dir.path().join("a/file"), b"x").unwrap();
        let store = LocalStore::new(dir.path());
        assert!(store.get("loop/object").is_err());
        assert!(
            store.exists("loop/object").is_err(),
            "ELOOP is not an absent object"
        );
        assert!(store.exists("a/dir").is_err(), "a directory is not an object");
        assert!(store.exists("a/file").unwrap());
        assert!(!store.exists("a/none").unwrap());
        assert!(!store.exists("b/none").unwrap(), "its directory missing too");
    }
}
