//! Artifacts: format-neutral file archives (P4 spec rev. 12 §4.3, D38,
//! D39; file 4a).
//!
//! An artifact is what a Template's layer, a Candidate's output and a
//! genesis source are: the files of a tree, not a storage image, so any
//! node restores it whatever its storage (ZFS or the block log).
//!
//! ```text
//! magic "TASOART\0" (8) · version u32 = 1 · manifest (u64 length · its canonical bytes, §8)
//! · for each File entry of the manifest, in its order: exactly `size` bytes of content
//! ```
//!
//! Integers little-endian; nothing follows the last file.  The archive is
//! a function of the manifest and the files' bytes, so the same tree gives
//! the same bytes and the same content key (`taso.artifact.v1`).
//!
//! **Writing** ([`write`]) reads each file once, relative to the tree's
//! root with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, and checks its size
//! and BLAKE3 against the manifest while copying it: a file that changed
//! since the walk fails the write ([`ArtifactError::Changed`]) rather than
//! leave an archive whose bytes are not what its manifest says.  The
//! archive's key is computed as it is written.
//!
//! **Restoring** ([`restore`]) writes the manifest's entries into an empty
//! directory (a fresh dataset's root, which may hold its reserved entries,
//! `lost+found`) under §4.2's rules: every create relative to a directory
//! fd opened with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, nothing
//! followed; each file's bytes checked against its BLAKE3 while written;
//! owners `base + slot`; the mode after the owner (a `chown` clears
//! set-id bits); each entry's `mtime` (and `atime`, the same) last, a
//! directory's after its children.  Only an archive whose manifest is
//! complete and lists no unsupported entry is restored; a short archive,
//! trailing bytes, a mismatch or a key other than the expected one refuses
//! it, and the caller discards the half-written dataset (§4.2: the next
//! attempt uses a fresh one).
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 12, BLAKE3
//! `37c75f30580bf3edd79674be38702d7893af413813bbfe6d4585231e9477144a`.

use std::ffi::CString;
use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use rustix::fs::{
    chownat, fchmod, fchown, futimens, mkdirat, openat2, symlinkat, utimensat, AtFlags, Gid, Mode,
    OFlags, ResolveFlags, Timespec, Timestamps, Uid, CWD,
};
use taso_core::contract::ObjectKind;
use taso_core::envelope::HashVal;

use crate::classify::{Content, Kind, Manifest, Mtime, Owner, Reserved};

/// An artifact's magic bytes.
pub const MAGIC: [u8; 8] = *b"TASOART\0";
/// The format version this code writes and reads.
pub const VERSION: u32 = 1;
/// The largest manifest an archive may carry (`manifest.max_manifest_bytes`
/// plus the one byte a stopped walk adds).
pub const MAX_MANIFEST: u64 = (256 << 20) + 1;

/// Why an archive could not be written or restored.
#[derive(Debug)]
pub enum ArtifactError {
    /// Reading or writing failed.
    Io(io::Error),
    /// The archive is not well formed.
    Malformed(String),
    /// A file is not what the manifest says (writing: it changed since the
    /// walk; restoring: the archive's bytes do not hash to it).
    Mismatch {
        /// The entry's path.
        path: String,
    },
    /// The manifest is incomplete or lists unsupported entries: the archive
    /// records a walk, it cannot be restored.
    NotRestorable(&'static str),
    /// The archive's key is not the one expected.
    KeyMismatch {
        /// Its key.
        got: HashVal,
    },
    /// The target directory holds something other than reserved entries.
    TargetNotEmpty(String),
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "artifact: {e}"),
            Self::Malformed(why) => write!(f, "artifact: malformed: {why}"),
            Self::Mismatch { path } => {
                write!(f, "artifact: {path:?} is not what the manifest says")
            }
            Self::NotRestorable(why) => write!(f, "artifact: not restorable: {why}"),
            Self::KeyMismatch { got } => write!(f, "artifact: unexpected key {got:?}"),
            Self::TargetNotEmpty(name) => write!(f, "artifact: target holds {name:?}"),
        }
    }
}

impl std::error::Error for ArtifactError {}

impl From<io::Error> for ArtifactError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<rustix::io::Errno> for ArtifactError {
    fn from(e: rustix::io::Errno) -> Self {
        Self::Io(e.into())
    }
}

fn shown(path: &[u8]) -> String {
    String::from_utf8_lossy(path).into_owned()
}

/// Everything written, hashed under the artifact's domain.
struct Keyed<'a> {
    out: &'a mut dyn Write,
    hasher: blake3::Hasher,
    written: u64,
}

impl Write for Keyed<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self.out.write(b)?;
        self.hasher.update(&b[..n]);
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

fn open_root(root: &Path) -> io::Result<OwnedFd> {
    Ok(openat2(
        CWD,
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::empty(),
    )?)
}

/// Open `path` (relative) under `root`, nothing followed.
fn beneath(root: &OwnedFd, path: &[u8], flags: OFlags, mode: Mode) -> io::Result<OwnedFd> {
    let c = CString::new(path).map_err(|_| io::Error::other("NUL in a path"))?;
    Ok(openat2(
        root.as_fd(),
        c.as_c_str(),
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        mode,
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )?)
}

/// Write the archive of the tree at `root`, which `manifest` describes, to
/// `out`.  Returns its content key and length.
pub fn write(
    root: &Path,
    manifest: &Manifest,
    out: &mut dyn Write,
) -> Result<(HashVal, u64), ArtifactError> {
    let mut k = Keyed {
        out,
        hasher: blake3::Hasher::new_derive_key(ObjectKind::Artifact.prefix()),
        written: 0,
    };
    let m = manifest.bytes();
    k.write_all(&MAGIC)?;
    k.write_all(&VERSION.to_le_bytes())?;
    k.write_all(&(m.len() as u64).to_le_bytes())?;
    k.write_all(&m)?;
    let rootfd = open_root(root)?;
    let mut buf = vec![0u8; 1 << 16];
    for e in &manifest.entries {
        let Content::Blake3(want) = &e.content else {
            continue;
        };
        let changed = || ArtifactError::Mismatch {
            path: shown(&e.path),
        };
        let f = beneath(&rootfd, &e.path, OFlags::RDONLY, Mode::empty()).map_err(|_| changed())?;
        let mut file = std::fs::File::from(f);
        let mut h = blake3::Hasher::new();
        let mut left = e.size;
        while left > 0 {
            let want_n = buf.len().min(left as usize);
            let n = file.read(&mut buf[..want_n])?;
            if n == 0 {
                return Err(changed());
            }
            h.update(&buf[..n]);
            k.write_all(&buf[..n])?;
            left -= n as u64;
        }
        if file.read(&mut buf[..1])? != 0 || h.finalize().as_bytes() != want.as_bytes() {
            return Err(changed());
        }
    }
    k.flush()?;
    Ok((
        HashVal::from_bytes(*k.hasher.finalize().as_bytes()),
        k.written,
    ))
}

/// What the reader has read so far, hashed under the artifact's domain.
struct Hashed<'a> {
    r: &'a mut dyn Read,
    hasher: blake3::Hasher,
}

impl Hashed<'_> {
    fn exact(&mut self, buf: &mut [u8]) -> Result<(), ArtifactError> {
        self.r.read_exact(buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                ArtifactError::Malformed("short".into())
            } else {
                ArtifactError::Io(e)
            }
        })?;
        self.hasher.update(buf);
        Ok(())
    }
}

/// Read the header and manifest.
fn read_head(h: &mut Hashed<'_>) -> Result<Manifest, ArtifactError> {
    let mut b = [0u8; 8 + 4 + 8];
    h.exact(&mut b)?;
    if b[..8] != MAGIC {
        return Err(ArtifactError::Malformed("not an artifact".into()));
    }
    if u32::from_le_bytes(b[8..12].try_into().expect("4")) != VERSION {
        return Err(ArtifactError::Malformed("unknown version".into()));
    }
    let len = u64::from_le_bytes(b[12..20].try_into().expect("8"));
    if len > MAX_MANIFEST {
        return Err(ArtifactError::Malformed("manifest too large".into()));
    }
    let mut m = vec![0u8; len as usize];
    h.exact(&mut m)?;
    Manifest::decode(&m).map_err(|e| ArtifactError::Malformed(e.to_string()))
}

/// The manifest of the archive `r` (its header and manifest only).
pub fn read_manifest(r: &mut dyn Read) -> Result<Manifest, ArtifactError> {
    let mut h = Hashed {
        r,
        hasher: blake3::Hasher::new(),
    };
    read_head(&mut h)
}

fn ts(m: Mtime) -> Timestamps {
    let t = Timespec {
        tv_sec: m.secs,
        tv_nsec: m.nsec as _,
    };
    Timestamps {
        last_access: t,
        last_modification: t,
    }
}

/// The parent directory of `path` (`""` for the root) and its last name.
fn split(path: &[u8]) -> (&[u8], &[u8]) {
    match path.iter().rposition(|&b| b == b'/') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => (&[], path),
    }
}

/// Restore the archive `r` into the empty directory `target`, owners
/// relative to `owner`; refuse it unless its key is `expect` (if given).
/// Returns its manifest and key.
pub fn restore(
    r: &mut dyn Read,
    target: &Path,
    owner: Owner,
    reserved: &[Reserved],
    expect: Option<HashVal>,
) -> Result<(Manifest, HashVal), ArtifactError> {
    let mut h = Hashed {
        r,
        hasher: blake3::Hasher::new_derive_key(ObjectKind::Artifact.prefix()),
    };
    let manifest = read_head(&mut h)?;
    if !manifest.complete() {
        return Err(ArtifactError::NotRestorable("the walk was incomplete"));
    }
    if !manifest.unsupported.is_empty() {
        return Err(ArtifactError::NotRestorable("it lists unsupported entries"));
    }
    let root = open_root(target)?;
    for e in rustix::fs::Dir::read_from(&root)? {
        let e = e?;
        let n = e.file_name().to_bytes();
        if n != b"." && n != b".." && !reserved.iter().any(|r| r.name == n) {
            return Err(ArtifactError::TargetNotEmpty(shown(n)));
        }
    }
    let uid = |slot: u32| Uid::from_raw(owner.uid_base + slot);
    let gid = |slot: u32| Gid::from_raw(owner.gid_base + slot);
    let mut dirs = Vec::new();
    let mut buf = vec![0u8; 1 << 16];
    for e in &manifest.entries {
        let (parent, name) = split(&e.path);
        let pfd = if parent.is_empty() {
            root.try_clone()?
        } else {
            beneath(
                &root,
                parent,
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )?
        };
        let cname = CString::new(name).map_err(|_| ArtifactError::Malformed("NUL".into()))?;
        let mode = Mode::from_raw_mode(e.mode as _);
        match (&e.kind, &e.content) {
            (Kind::Dir, Content::None) => {
                mkdirat(&pfd, cname.as_c_str(), Mode::from_raw_mode(0o700))?;
                let d = beneath(
                    &root,
                    &e.path,
                    OFlags::RDONLY | OFlags::DIRECTORY,
                    Mode::empty(),
                )?;
                fchown(&d, Some(uid(e.uid_slot)), Some(gid(e.gid_slot)))?;
                fchmod(&d, mode)?;
                // Its times are set once its children exist.
                dirs.push(e);
            }
            (Kind::File, Content::Blake3(want)) => {
                let f = openat2(
                    pfd.as_fd(),
                    cname.as_c_str(),
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
                )?;
                let mut file = std::fs::File::from(f);
                let mut fh = blake3::Hasher::new();
                let mut left = e.size;
                while left > 0 {
                    let n = buf.len().min(left as usize);
                    h.exact(&mut buf[..n])?;
                    fh.update(&buf[..n]);
                    file.write_all(&buf[..n])?;
                    left -= n as u64;
                }
                if fh.finalize().as_bytes() != want.as_bytes() {
                    return Err(ArtifactError::Mismatch {
                        path: shown(&e.path),
                    });
                }
                file.sync_all()?;
                let fd = OwnedFd::from(file);
                fchown(&fd, Some(uid(e.uid_slot)), Some(gid(e.gid_slot)))?;
                fchmod(&fd, mode)?;
                futimens(&fd, &ts(e.mtime))?;
            }
            (Kind::Symlink, Content::Target(t)) => {
                let ct = CString::new(t.as_slice())
                    .map_err(|_| ArtifactError::Malformed("NUL".into()))?;
                symlinkat(ct.as_c_str(), &pfd, cname.as_c_str())?;
                chownat(
                    &pfd,
                    cname.as_c_str(),
                    Some(uid(e.uid_slot)),
                    Some(gid(e.gid_slot)),
                    AtFlags::SYMLINK_NOFOLLOW,
                )?;
                utimensat(
                    &pfd,
                    cname.as_c_str(),
                    &ts(e.mtime),
                    AtFlags::SYMLINK_NOFOLLOW,
                )?;
            }
            _ => {
                return Err(ArtifactError::Malformed(format!(
                    "entry {:?}: kind and content disagree",
                    shown(&e.path)
                )))
            }
        }
    }
    // Nothing may follow the last file.
    let mut one = [0u8; 1];
    if h.r.read(&mut one)? != 0 {
        return Err(ArtifactError::Malformed("trailing bytes".into()));
    }
    // Directory times last, deepest first, so creating children does not
    // move them.
    for e in dirs.iter().rev() {
        let (parent, name) = split(&e.path);
        let pfd = if parent.is_empty() {
            root.try_clone()?
        } else {
            beneath(
                &root,
                parent,
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )?
        };
        let cname = CString::new(name).map_err(|_| ArtifactError::Malformed("NUL".into()))?;
        utimensat(
            &pfd,
            cname.as_c_str(),
            &ts(e.mtime),
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
    }
    rustix::fs::syncfs(&root)?;
    let key = HashVal::from_bytes(*h.hasher.finalize().as_bytes());
    if expect.is_some_and(|k| k != key) {
        return Err(ArtifactError::KeyMismatch { got: key });
    }
    Ok((manifest, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{walk, Classmap, Limits, Unsupported};
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::time::{Duration, UNIX_EPOCH};
    use taso_core::contract::object_key;

    const MAP: &str = "version = 1\n[[rule]]\nglob = \"**\"\nclass = \"Source\"\n";

    fn map() -> Classmap {
        Classmap::parse(MAP.as_bytes()).unwrap()
    }

    fn me() -> Owner {
        Owner {
            uid_base: rustix::process::getuid().as_raw(),
            gid_base: rustix::process::getgid().as_raw(),
        }
    }

    /// A tree with directories, files of several sizes, a set-uid mode, an
    /// empty file, a symlink, and dates before 1970 and past 2262.
    fn tree() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let p = d.path();
        fs::create_dir_all(p.join("src/deep/er")).unwrap();
        fs::write(p.join("src/main.rs"), b"fn main() {}").unwrap();
        fs::write(
            p.join("src/deep/er/big.bin"),
            (0..200_000u32).map(|i| i as u8).collect::<Vec<_>>(),
        )
        .unwrap();
        fs::write(p.join("empty"), b"").unwrap();
        fs::write(p.join("tool"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(p.join("tool"), fs::Permissions::from_mode(0o4755)).unwrap();
        fs::set_permissions(p.join("src/deep"), fs::Permissions::from_mode(0o750)).unwrap();
        symlink("src/main.rs", p.join("link")).unwrap();
        let set = |name: &str, t| {
            fs::File::options()
                .write(true)
                .open(p.join(name))
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(t))
                .unwrap();
        };
        set("empty", UNIX_EPOCH - Duration::from_secs(315_619_200));
        set("src/main.rs", UNIX_EPOCH + Duration::new(10_413_792_000, 7));
        d
    }

    fn manifest_of(root: &Path) -> Manifest {
        walk(
            root,
            &map(),
            me(),
            &Limits::default(),
            &Reserved::defaults(),
        )
        .unwrap()
    }

    fn archive(root: &Path) -> (Manifest, Vec<u8>, HashVal) {
        let m = manifest_of(root);
        let mut out = Vec::new();
        let (key, len) = write(root, &m, &mut out).unwrap();
        assert_eq!(len, out.len() as u64);
        (m, out, key)
    }

    #[test]
    fn an_archive_restores_to_the_same_tree_and_the_same_bytes() {
        let src = tree();
        let (m, bytes, key) = archive(src.path());
        assert!(m.complete() && m.unsupported.is_empty());
        assert_eq!(
            key,
            object_key(ObjectKind::Artifact, &bytes),
            "its content key"
        );
        assert_eq!(&bytes[..8], b"TASOART\0");
        let files: u64 = m
            .entries
            .iter()
            .filter(|e| e.kind == Kind::File)
            .map(|e| e.size)
            .sum();
        let mlen = m.bytes().len() as u64;
        assert_eq!(
            bytes.len() as u64,
            8 + 4 + 8 + mlen + files,
            "header, manifest, contents; nothing else"
        );
        assert_eq!(read_manifest(&mut &bytes[..]).unwrap(), m);

        let dst = tempfile::tempdir().unwrap();
        let (got, k) = restore(
            &mut &bytes[..],
            dst.path(),
            me(),
            &Reserved::defaults(),
            Some(key),
        )
        .unwrap();
        assert_eq!((got, k), (m.clone(), key));
        // The restored tree walks to the same manifest: contents, modes
        // (set-uid kept), owners, every date (directories' too), symlink.
        assert_eq!(manifest_of(dst.path()), m);
        assert_eq!(
            fs::metadata(dst.path().join("tool")).unwrap().mode() & 0o7777,
            0o4755
        );
        // And archives to the same bytes: deterministic.
        let (_, again, k2) = archive(dst.path());
        assert_eq!((again, k2), (bytes, key));
    }

    #[test]
    fn owners_are_written_by_slot_from_the_targets_base() {
        if !rustix::process::getuid().is_root() {
            eprintln!("skipped: needs root to chown");
            return;
        }
        let src = tree();
        let (m, bytes, _) = archive(src.path());
        let dst = tempfile::tempdir().unwrap();
        let base = Owner {
            uid_base: 200_000,
            gid_base: 200_000,
        };
        restore(&mut &bytes[..], dst.path(), base, &[], None).unwrap();
        for e in &m.entries {
            let md =
                fs::symlink_metadata(dst.path().join(String::from_utf8_lossy(&e.path).as_ref()))
                    .unwrap();
            assert_eq!(
                (md.uid(), md.gid()),
                (200_000 + e.uid_slot, 200_000 + e.gid_slot)
            );
        }
        // Read back with that base, the slots are the same.
        let back = walk(dst.path(), &map(), base, &Limits::default(), &[]).unwrap();
        assert_eq!(back.entries, m.entries);
    }

    #[test]
    fn a_file_that_changed_since_the_walk_fails_the_write() {
        let src = tree();
        let m = manifest_of(src.path());
        fs::write(src.path().join("src/main.rs"), b"fn main() { changed() }").unwrap();
        assert!(matches!(
            write(src.path(), &m, &mut Vec::new()),
            Err(ArtifactError::Mismatch { path }) if path == "src/main.rs"
        ));
        // Same length, other bytes.
        let src = tree();
        let m = manifest_of(src.path());
        fs::write(src.path().join("src/main.rs"), b"fn mainX) {}").unwrap();
        assert!(matches!(
            write(src.path(), &m, &mut Vec::new()),
            Err(ArtifactError::Mismatch { .. })
        ));
        // Gone.
        let src = tree();
        let m = manifest_of(src.path());
        fs::remove_file(src.path().join("empty")).unwrap();
        assert!(matches!(
            write(src.path(), &m, &mut Vec::new()),
            Err(ArtifactError::Mismatch { .. })
        ));
    }

    #[test]
    fn a_damaged_archive_is_refused() {
        let src = tree();
        let (_, bytes, key) = archive(src.path());
        let try_restore = |b: &[u8], expect| {
            let dst = tempfile::tempdir().unwrap();
            restore(&mut &b[..], dst.path(), me(), &[], expect).map(|_| ())
        };
        // A content byte: the file's BLAKE3 refuses it.
        let mut flipped = bytes.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert!(matches!(
            try_restore(&flipped, None),
            Err(ArtifactError::Mismatch { .. })
        ));
        // Short, trailing, not an artifact, another version.
        assert!(matches!(
            try_restore(&bytes[..bytes.len() - 1], None),
            Err(ArtifactError::Malformed(_))
        ));
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(
            matches!(try_restore(&longer, None), Err(ArtifactError::Malformed(w)) if w == "trailing bytes")
        );
        let mut magic = bytes.clone();
        magic[0] = b'X';
        assert!(matches!(
            try_restore(&magic, None),
            Err(ArtifactError::Malformed(_))
        ));
        let mut version = bytes.clone();
        version[8] = 2;
        assert!(matches!(
            try_restore(&version, None),
            Err(ArtifactError::Malformed(_))
        ));
        // Whole and right, but not the artifact asked for.
        assert!(matches!(
            try_restore(&bytes, Some(HashVal::from_bytes([1; 32]))),
            Err(ArtifactError::KeyMismatch { got }) if got == key
        ));
        assert!(try_restore(&bytes, Some(key)).is_ok());
    }

    #[test]
    fn an_archive_of_an_unsupported_walk_records_it_but_does_not_restore() {
        let src = tree();
        rustix::fs::mknodat(
            CWD,
            src.path().join("fifo").as_path(),
            rustix::fs::FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let (m, bytes, _) = archive(src.path());
        assert_eq!(m.unsupported, vec![(b"fifo".to_vec(), Unsupported::Fifo)]);
        assert_eq!(
            read_manifest(&mut &bytes[..]).unwrap(),
            m,
            "the walk is recorded"
        );
        let dst = tempfile::tempdir().unwrap();
        assert!(matches!(
            restore(&mut &bytes[..], dst.path(), me(), &[], None),
            Err(ArtifactError::NotRestorable(_))
        ));
        // An incomplete walk neither.
        let small = Limits {
            max_entries: 2,
            ..Default::default()
        };
        let m = walk(src.path(), &map(), me(), &small, &[]).unwrap();
        let mut out = Vec::new();
        write(src.path(), &m, &mut out).unwrap();
        assert!(matches!(
            restore(
                &mut &out[..],
                tempfile::tempdir().unwrap().path(),
                me(),
                &[],
                None
            ),
            Err(ArtifactError::NotRestorable(_))
        ));
    }

    #[test]
    fn the_target_holds_only_its_reserved_entries() {
        let src = tree();
        let (_, bytes, _) = archive(src.path());
        let dst = tempfile::tempdir().unwrap();
        let lf = dst.path().join("lost+found");
        fs::create_dir(&lf).unwrap();
        fs::set_permissions(&lf, fs::Permissions::from_mode(0o700)).unwrap();
        restore(
            &mut &bytes[..],
            dst.path(),
            me(),
            &Reserved::defaults(),
            None,
        )
        .unwrap();
        let dst = tempfile::tempdir().unwrap();
        fs::write(dst.path().join("stray"), b"").unwrap();
        assert!(matches!(
            restore(&mut &bytes[..], dst.path(), me(), &Reserved::defaults(), None),
            Err(ArtifactError::TargetNotEmpty(n)) if n == "stray"
        ));
    }
}
