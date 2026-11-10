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

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::path::PathBuf;

use rustix::fs::{
    fstat, fsync, mkdirat, openat2, renameat, statat, unlinkat, AtFlags, Dir, FileType, Mode,
    OFlags, ResolveFlags, CWD,
};
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

    /// The root, opened.  The root itself is the operator's path and may
    /// be a symlink; everything under it is resolved beneath it and never
    /// through a symlink (round 2, R2-08, Kimi; D&D a).
    fn root(&self) -> io::Result<OwnedFd> {
        Ok(openat2(
            CWD,
            &self.root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::empty(),
        )?)
    }

    /// The directory `rel` under the root, opened beneath it with no
    /// symlink anywhere on the way (a symlink is an error, `ELOOP`, never
    /// absent); with `create`, missing directories are made, one by one.
    fn dir(&self, rel: &str, create: bool) -> io::Result<OwnedFd> {
        if create {
            // The root is the operator's path: made as a put always made it.
            std::fs::create_dir_all(&self.root)?;
        }
        let mut fd = self.root()?;
        for c in rel.split('/').filter(|c| !c.is_empty()) {
            let open = |at: &OwnedFd| {
                openat2(
                    at,
                    c,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    BENEATH,
                )
            };
            fd = match open(&fd) {
                Ok(next) => next,
                Err(rustix::io::Errno::NOENT) if create => {
                    match mkdirat(&fd, c, Mode::from_raw_mode(0o755)) {
                        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                        Err(e) => return Err(e.into()),
                    }
                    open(&fd)?
                }
                Err(e) => return Err(e.into()),
            };
        }
        Ok(fd)
    }

    /// `key`'s directory and file name; `None` if the directory is not
    /// there.
    fn parent(&self, key: &str, create: bool) -> io::Result<Option<(OwnedFd, String)>> {
        if !valid_key(key) {
            return Err(bad_key(key));
        }
        let (dir, name) = key.rsplit_once('/').unwrap_or(("", key));
        match self.dir(dir, create) {
            Ok(fd) => Ok(Some((fd, name.to_string()))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// What `name` in `dir` is, without following it: `None` if nothing.
    fn kind(dir: &OwnedFd, name: &str) -> io::Result<Option<rustix::fs::Stat>> {
        match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => Ok(Some(st)),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn not_an_object(key: &str) -> io::Error {
        io::Error::other(format!("{key}: there, but not an object file"))
    }

    /// Every object under `prefix` as (key, last written), in key order.
    /// Anything there that is not a directory or a file (a symlink) is an
    /// error: the store never makes one.
    fn walk(&self, prefix: &str) -> io::Result<Vec<(String, std::time::SystemTime)>> {
        if !valid_key(prefix) {
            return Err(bad_key(prefix));
        }
        let mut keys = Vec::new();
        let mut todo = vec![prefix.to_string()];
        while let Some(key) = todo.pop() {
            let fd = match self.dir(&key, false) {
                Ok(fd) => fd,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            for entry in Dir::read_from(&fd)? {
                let entry = entry?;
                let Ok(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                if name == "." || name == ".." || name.starts_with(TMP_PREFIX) {
                    continue;
                }
                let child = format!("{key}/{name}");
                if !valid_key(&child) {
                    continue; // not something put() could have made
                }
                let Some(st) = Self::kind(&fd, &name)? else {
                    continue; // deleted since the read saw it
                };
                match FileType::from_raw_mode(st.st_mode as _) {
                    FileType::Directory => todo.push(child),
                    FileType::RegularFile => {
                        let t = std::time::UNIX_EPOCH
                            + std::time::Duration::new(st.st_mtime as u64, st.st_mtime_nsec as u32);
                        keys.push((child, t));
                    }
                    _ => return Err(Self::not_an_object(&child)),
                }
            }
        }
        keys.sort();
        Ok(keys)
    }
}

/// Resolution under the store's root: beneath it, through no symlink.
const BENEATH: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

impl ObjectStore for LocalStore {
    fn put(&self, key: &str, data: &mut dyn Read) -> io::Result<u64> {
        let (dir, name) = self
            .parent(key, true)?
            .ok_or_else(|| io::Error::other(format!("{key}: its directory was not made")))?;
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = format!("{TMP_PREFIX}{}-{n}", std::process::id());
        let result = (|| {
            let f = openat2(
                &dir,
                tmp.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::from_raw_mode(0o644),
                BENEATH,
            )?;
            let mut f = File::from(f);
            let written = io::copy(data, &mut f)?;
            f.sync_all()?;
            drop(f);
            // Never over something that is not an object file.
            if let Some(st) = Self::kind(&dir, &name)? {
                if FileType::from_raw_mode(st.st_mode as _) != FileType::RegularFile {
                    return Err(Self::not_an_object(key));
                }
            }
            renameat(&dir, tmp.as_str(), &dir, name.as_str())?;
            fsync(&dir)?;
            Ok(written)
        })();
        if result.is_err() {
            let _ = unlinkat(&dir, tmp.as_str(), AtFlags::empty());
        }
        result
    }

    fn get(&self, key: &str) -> io::Result<Option<ByteStream>> {
        let Some((dir, name)) = self.parent(key, false)? else {
            return Ok(None);
        };
        let f = match openat2(
            &dir,
            name.as_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            BENEATH,
        ) {
            Ok(f) => f,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if FileType::from_raw_mode(fstat(&f)?.st_mode as _) != FileType::RegularFile {
            return Err(Self::not_an_object(key));
        }
        Ok(Some(Box::new(File::from(f))))
    }

    /// False only if nothing is there (NotFound, as `get` reads it); any
    /// other error is said, and something there that is not a file (a
    /// symlink too) is an error: an unreadable object is never "absent"
    /// (audit 2026-11-06, finding 4; R2-08).
    fn exists(&self, key: &str) -> io::Result<bool> {
        let Some((dir, name)) = self.parent(key, false)? else {
            return Ok(false);
        };
        match Self::kind(&dir, &name)? {
            None => Ok(false),
            Some(st) if FileType::from_raw_mode(st.st_mode as _) == FileType::RegularFile => {
                Ok(true)
            }
            Some(_) => Err(Self::not_an_object(key)),
        }
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        Ok(self.walk(prefix)?.into_iter().map(|(k, _)| k).collect())
    }

    /// The file's modification time: a put writes a new file and renames
    /// it into place, so a put again makes it new.
    fn list_times(&self, prefix: &str) -> io::Result<Vec<(String, std::time::SystemTime)>> {
        self.walk(prefix)
    }

    /// Unlink the file, then fsync its directory so the removal survives a
    /// crash.  Empty directories are left: [`LocalStore::list`] does not
    /// list them, and a later put reuses them.  Only an object file is
    /// removed: anything else there is an error.
    fn delete(&self, key: &str) -> io::Result<bool> {
        let Some((dir, name)) = self.parent(key, false)? else {
            return Ok(false);
        };
        match Self::kind(&dir, &name)? {
            None => return Ok(false),
            Some(st) if FileType::from_raw_mode(st.st_mode as _) == FileType::RegularFile => {}
            Some(_) => return Err(Self::not_an_object(key)),
        }
        match unlinkat(&dir, name.as_str(), AtFlags::empty()) {
            Ok(()) => {}
            Err(rustix::io::Errno::NOENT) => return Ok(false),
            Err(e) => return Err(e.into()),
        }
        fsync(&dir)?;
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
        std::fs::write(
            dir.path().join("v/a").join(format!("{TMP_PREFIX}9-9")),
            b"partial",
        )
        .unwrap();
        // A file put() could never have made.
        std::fs::write(dir.path().join("v/a/has space"), b"?").unwrap();
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

    /// Round 2, R2-08 (Kimi; D&D a): nothing under the store's root is
    /// reached through a symlink.  A directory symlink to the outside: put
    /// is refused and writes nothing outside; get, exists, delete and the
    /// listing are errors, never "absent", and touch nothing outside.  A
    /// symlink as the object itself: the same.  The root itself may be a
    /// symlink (the operator's path).
    #[test]
    fn nothing_is_reached_through_a_symlink_under_the_root() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let (root, outside) = (dir.path().join("root"), dir.path().join("outside"));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("object"), b"theirs").unwrap();
        symlink("../outside", root.join("escape")).unwrap();
        std::fs::create_dir_all(root.join("d")).unwrap();
        symlink(outside.join("object"), root.join("d/link")).unwrap();
        let store = LocalStore::new(&root);

        assert!(store.put("escape/new", &mut &b"x"[..]).is_err());
        assert!(!outside.join("new").exists(), "nothing written outside");
        assert!(store.put("escape/object", &mut &b"x"[..]).is_err());
        assert!(store.get("escape/object").is_err());
        assert!(store.exists("escape/object").is_err());
        assert!(store.delete("escape/object").is_err());
        assert!(store.list("escape").is_err());
        // The object itself a symlink.
        assert!(store.get("d/link").is_err());
        assert!(store.exists("d/link").is_err());
        assert!(store.delete("d/link").is_err());
        assert!(store.put("d/link", &mut &b"x"[..]).is_err());
        assert!(store.list("d").is_err());
        assert_eq!(
            std::fs::read(outside.join("object")).unwrap(),
            b"theirs",
            "the outside file is untouched"
        );
        // A root that is a symlink works as before.
        symlink(&root, dir.path().join("root-link")).unwrap();
        let via = LocalStore::new(dir.path().join("root-link"));
        via.put("ok/k", &mut &b"v"[..]).unwrap();
        assert!(via.exists("ok/k").unwrap());
        assert_eq!(via.list("ok").unwrap(), vec!["ok/k".to_string()]);
        assert!(via.delete("ok/k").unwrap());
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
        assert!(
            store.exists("a/dir").is_err(),
            "a directory is not an object"
        );
        assert!(store.exists("a/file").unwrap());
        assert!(!store.exists("a/none").unwrap());
        assert!(
            !store.exists("b/none").unwrap(),
            "its directory missing too"
        );
    }
    // ── audit confirmation round, group g1 (tests only) ─────────────

    /// G1-9: a put's temp file is `.tmp-<pid>-<n>`, n counted from 0 in
    /// each process.  A Warden killed in a put leaves its temp file; a
    /// later process with the same pid (a container's pid 1, a pid file
    /// reused after a reboot) meets the name.  The put must still store
    /// the object, and the leftover must not stay for good.
    #[test]
    fn confirm_g1_9_a_temp_file_left_by_a_dead_process_fails_no_put() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        store.put("p/obj/first", &mut &b"1"[..]).unwrap();
        // The leftovers of an earlier process of this pid: the names this
        // process's next puts take (other tests move the counter too).
        let next = TMP_COUNTER.load(Ordering::Relaxed);
        let stale: Vec<std::path::PathBuf> = (next..next + 64)
            .map(|n| {
                dir.path()
                    .join("p/obj")
                    .join(format!("{TMP_PREFIX}{}-{n}", std::process::id()))
            })
            .collect();
        for f in &stale {
            std::fs::write(f, b"half a pack").unwrap();
        }
        let r = store.put("p/obj/second", &mut &b"2"[..]);
        assert!(r.is_ok(), "the put failed: {}", r.unwrap_err());
    }

    /// G1-9: a temp file of another (dead) process is never removed.
    #[test]
    fn confirm_g1_9_temp_files_of_dead_processes_are_swept() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        store.put("p/obj/first", &mut &b"1"[..]).unwrap();
        // pid 4194305 is above the kernel's pid_max: no live process.
        let stale = dir.path().join("p/obj/.tmp-4194305-0");
        std::fs::write(&stale, vec![0u8; 1 << 16]).unwrap();
        store.put("p/obj/second", &mut &b"2"[..]).unwrap();
        store.put("p/obj/first", &mut &b"3"[..]).unwrap();
        assert_eq!(store.list("p").unwrap(), ["p/obj/first", "p/obj/second"]);
        assert!(!stale.exists(), "{} is left for good", stale.display());
    }

}
