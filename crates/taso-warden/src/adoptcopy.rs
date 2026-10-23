//! Adoption on ZFS by copying (P3 close-out C7, decided 2026-10-23).
//!
//! A promoted fork's files become its parent's: on the block log the
//! fork's increment is imported as the parent's next layer, but ZFS will
//! not do that — a stream sent from a clone's origin is a clone stream,
//! and `zfs receive` makes a new clone of it, never a layer of the origin
//! ("destination has snapshots", taso-test 2026-10-23).  So on ZFS the
//! parent, rolled back to its Seal `S`, is made equal to the fork's Seal
//! snapshot `T` by copying exactly what `zfs diff <parent>@S <fork>@T`
//! lists (it works across the clone: taso-test 2026-10-23), and the
//! parent's next Seal snapshot is then taken as usual.  The cost is what
//! the fork changed, not what the Vessel holds.
//!
//! What is copied: regular files (contents, mode, owner, times),
//! directories (mode, owner, times), symlinks (target, owner).  Sockets
//! are skipped: they mean nothing to a new run.  Fifos and device nodes
//! are refused.  Not carried: extended attributes and ACLs; hard links
//! become separate files.

use std::ffi::OsString;
use std::fs::{self, File, FileTimes, Metadata};
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{lchown, symlink, FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// One line of `zfs diff -H`, its paths made relative to the fork's
/// mountpoint.  The root itself is the empty path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// `-`: gone in the fork.
    Removed(PathBuf),
    /// `+`: new in the fork.
    Added(PathBuf),
    /// `M`: contents or metadata changed (a directory: its entries).
    Modified(PathBuf),
    /// `R`: renamed, from the first path to the second.
    Renamed(PathBuf, PathBuf),
}

/// Why a diff could not be read or applied.
#[derive(Debug)]
pub enum CopyError {
    /// A line `zfs diff` printed that is not understood.
    Parse {
        /// The line.
        line: String,
        /// What is wrong with it.
        why: &'static str,
    },
    /// A file the fork has that cannot be carried over.
    Unsupported(PathBuf),
    /// The filesystem refused.
    Io(PathBuf, io::Error),
}

impl std::fmt::Display for CopyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse { line, why } => write!(f, "zfs diff line {line:?}: {why}"),
            Self::Unsupported(p) => {
                write!(
                    f,
                    "{}: a fifo or device node cannot be adopted",
                    p.display()
                )
            }
            Self::Io(p, e) => write!(f, "{}: {e}", p.display()),
        }
    }
}

impl std::error::Error for CopyError {}

/// Undo `zfs diff`'s escaping: every byte that is not printable ASCII,
/// a space or a backslash is printed as `\` and four octal digits.
fn unescape(s: &str) -> Option<PathBuf> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            let digits = b.get(i + 1..i + 5)?;
            let mut v: u32 = 0;
            for d in digits {
                if !(b'0'..=b'7').contains(d) {
                    return None;
                }
                v = v * 8 + u32::from(d - b'0');
            }
            out.push(u8::try_from(v).ok()?);
            i += 5;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(PathBuf::from(OsString::from_vec(out)))
}

/// `path` under `root`, relative, with nothing but plain names in it.
fn relative(root: &Path, path: &Path) -> Option<PathBuf> {
    let rel = path.strip_prefix(root).ok()?;
    rel.components()
        .all(|c| matches!(c, Component::Normal(_)))
        .then(|| rel.to_path_buf())
}

/// Parse `zfs diff -H -F` output (`<change>\t<type>\t<path>[\t<new>]`),
/// its paths under `root`, the fork's mountpoint.
pub fn parse_diff(root: &Path, out: &str) -> Result<Vec<Change>, CopyError> {
    let mut changes = Vec::new();
    for line in out.lines().filter(|l| !l.is_empty()) {
        let bad = |why| CopyError::Parse {
            line: line.to_string(),
            why,
        };
        let f: Vec<&str> = line.split('\t').collect();
        let path = |s: &str| {
            let p = unescape(s).ok_or_else(|| bad("bad escape"))?;
            relative(root, &p).ok_or_else(|| bad("a path outside the fork's mountpoint"))
        };
        let change = match f[..] {
            ["-", _, p] => Change::Removed(path(p)?),
            ["+", _, p] => Change::Added(path(p)?),
            ["M", _, p] => Change::Modified(path(p)?),
            ["R", _, from, to] => Change::Renamed(path(from)?, path(to)?),
            _ => return Err(bad("expected <change> <type> <path> [<new path>]")),
        };
        changes.push(change);
    }
    Ok(changes)
}

fn io_at(p: &Path) -> impl FnOnce(io::Error) -> CopyError + '_ {
    move |e| CopyError::Io(p.to_path_buf(), e)
}

/// Remove whatever is at `p`; nothing there is fine.
fn remove_any(p: &Path) -> Result<(), CopyError> {
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(CopyError::Io(p.to_path_buf(), e)),
        Ok(m) if m.is_dir() => fs::remove_dir_all(p).map_err(io_at(p)),
        Ok(_) => fs::remove_file(p).map_err(io_at(p)),
    }
}

fn time(secs: i64, nsecs: i64) -> SystemTime {
    let d = Duration::new(secs.unsigned_abs(), nsecs.clamp(0, 999_999_999) as u32);
    if secs >= 0 {
        UNIX_EPOCH + d
    } else {
        UNIX_EPOCH - d
    }
}

/// Owner, then mode (a chown clears set-id bits), then times.  A symlink
/// gets only its owner.
fn set_meta(dest: &Path, m: &Metadata) -> Result<(), CopyError> {
    lchown(dest, Some(m.uid()), Some(m.gid())).map_err(io_at(dest))?;
    if m.file_type().is_symlink() {
        return Ok(());
    }
    fs::set_permissions(dest, m.permissions()).map_err(io_at(dest))?;
    let times = FileTimes::new()
        .set_accessed(time(m.atime(), m.atime_nsec()))
        .set_modified(time(m.mtime(), m.mtime_nsec()));
    File::open(dest)
        .and_then(|f| f.set_times(times))
        .map_err(io_at(dest))
}

/// Make `dest` what `src` is, alone (a directory's entries are not
/// touched, nor its metadata: see [`apply`]).  Returns `src`'s metadata
/// if it is a directory.
fn copy_one(src: &Path, dest: &Path) -> Result<Option<Metadata>, CopyError> {
    let m = fs::symlink_metadata(src).map_err(io_at(src))?;
    let t = m.file_type();
    if t.is_dir() {
        match fs::symlink_metadata(dest) {
            Ok(d) if d.is_dir() => {}
            Ok(_) => {
                remove_any(dest)?;
                fs::create_dir(dest).map_err(io_at(dest))?;
            }
            Err(_) => fs::create_dir(dest).map_err(io_at(dest))?,
        }
        return Ok(Some(m));
    }
    if t.is_socket() {
        remove_any(dest)?;
        return Ok(None);
    }
    if t.is_fifo() || t.is_block_device() || t.is_char_device() {
        return Err(CopyError::Unsupported(src.to_path_buf()));
    }
    remove_any(dest)?;
    if t.is_symlink() {
        let target = fs::read_link(src).map_err(io_at(src))?;
        symlink(&target, dest).map_err(io_at(dest))?;
    } else {
        fs::copy(src, dest).map_err(io_at(dest))?;
    }
    set_meta(dest, &m)?;
    Ok(None)
}

/// Copy the tree at `src` to `dest`, replacing whatever is there.
fn copy_tree(src: &Path, dest: &Path) -> Result<(), CopyError> {
    remove_any(dest)?;
    if let Some(m) = copy_one(src, dest)? {
        for e in fs::read_dir(src).map_err(io_at(src))? {
            let e = e.map_err(io_at(src))?;
            copy_tree(&e.path(), &dest.join(e.file_name()))?;
        }
        set_meta(dest, &m)?;
    }
    Ok(())
}

fn depth(p: &Path) -> usize {
    p.components().count()
}

/// Make the tree at `dest` (the parent, at the Seal the diff starts from)
/// equal to the tree at `src` (the fork's Seal snapshot), given the diff
/// between them.  Removals first, deepest first; then what is new or
/// changed, shallowest first (a renamed path is copied whole); then the
/// metadata of the changed directories, deepest first, so the copying
/// does not leave its own times on them.  Returns how many changes were
/// applied.
pub fn apply(changes: &[Change], src: &Path, dest: &Path) -> Result<usize, CopyError> {
    let mut gone: Vec<&Path> = Vec::new();
    let mut put: Vec<(&Path, bool)> = Vec::new(); // (path, whole tree)
    for c in changes {
        match c {
            Change::Removed(p) => gone.push(p),
            Change::Added(p) | Change::Modified(p) => put.push((p, false)),
            Change::Renamed(from, to) => {
                gone.push(from);
                put.push((to, true));
            }
        }
    }
    gone.sort_by_key(|p| std::cmp::Reverse(depth(p)));
    for p in &gone {
        if !p.as_os_str().is_empty() {
            remove_any(&dest.join(p))?;
        }
    }
    put.sort_by_key(|(p, _)| depth(p));
    let mut dirs: Vec<(PathBuf, Metadata)> = Vec::new();
    for (p, tree) in &put {
        let (s, d) = (src.join(p), dest.join(p));
        if *tree {
            copy_tree(&s, &d)?;
        } else if let Some(m) = copy_one(&s, &d)? {
            dirs.push((d, m));
        }
    }
    dirs.sort_by_key(|(p, _)| std::cmp::Reverse(depth(p)));
    for (d, m) in &dirs {
        set_meta(d, m)?;
    }
    Ok(changes.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn diff_lines_are_parsed_and_unescaped() {
        let root = Path::new("/tasotest/vessel/zd-c");
        let out = "-\tF\t/tasotest/vessel/zd-c/a\n\
                   +\tF\t/tasotest/vessel/zd-c/b\\0040c\n\
                   M\t/\t/tasotest/vessel/zd-c/\n\
                   R\tF\t/tasotest/vessel/zd-c/x\t/tasotest/vessel/zd-c/d/\\0303\\0244\n";
        assert_eq!(
            parse_diff(root, out).unwrap(),
            vec![
                Change::Removed("a".into()),
                Change::Added("b c".into()),
                Change::Modified("".into()),
                Change::Renamed("x".into(), "d/ä".into()),
            ]
        );
        for bad in [
            "?\tF\t/tasotest/vessel/zd-c/a",
            "-\tF\t/elsewhere/a",
            "-\tF\t/tasotest/vessel/zd-c/../a",
            "-\tF\t/tasotest/vessel/zd-c/a\\09",
            "-\t/tasotest/vessel/zd-c/a",
        ] {
            assert!(parse_diff(root, bad).is_err(), "{bad}");
        }
    }

    fn write(p: &Path, s: &str) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, s).unwrap();
    }

    fn tree(root: &Path) -> Vec<(String, String)> {
        let mut v = Vec::new();
        fn walk(root: &Path, p: &Path, v: &mut Vec<(String, String)>) {
            let mut es: Vec<_> = fs::read_dir(p)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            es.sort();
            for e in es {
                let rel = e.strip_prefix(root).unwrap().display().to_string();
                let m = fs::symlink_metadata(&e).unwrap();
                if m.file_type().is_symlink() {
                    v.push((rel, format!("-> {}", fs::read_link(&e).unwrap().display())));
                } else if m.is_dir() {
                    v.push((rel, format!("dir {:o}", m.permissions().mode() & 0o7777)));
                    walk(root, &e, v);
                } else {
                    v.push((
                        rel,
                        format!(
                            "{:o} {} {}",
                            m.permissions().mode() & 0o7777,
                            m.mtime(),
                            fs::read_to_string(&e).unwrap()
                        ),
                    ));
                }
            }
        }
        walk(root, root, &mut v);
        v
    }

    /// The parent at `S`, the fork at `T`, and the diff between them:
    /// after applying it the parent's tree is the fork's.
    #[test]
    fn applying_the_diff_makes_the_parent_the_fork() {
        let t = tempfile::tempdir().unwrap();
        let (parent, fork) = (t.path().join("parent"), t.path().join("fork"));
        for root in [&parent, &fork] {
            write(&root.join("keep"), "same");
            write(&root.join("edit"), "old");
            write(&root.join("gone/deep/f"), "x");
            write(&root.join("old/inner"), "moved");
        }
        // The fork's changes.
        write(&fork.join("edit"), "new");
        fs::set_permissions(fork.join("edit"), fs::Permissions::from_mode(0o640)).unwrap();
        fs::remove_dir_all(fork.join("gone")).unwrap();
        fs::rename(fork.join("old"), fork.join("new")).unwrap();
        write(&fork.join("added/dir/file"), "hello");
        symlink("added/dir/file", fork.join("link")).unwrap();
        fs::set_permissions(fork.join("added"), fs::Permissions::from_mode(0o700)).unwrap();
        let old = File::open(fork.join("keep")).unwrap();
        old.set_modified(UNIX_EPOCH + Duration::from_secs(1_000_000))
            .unwrap();
        write(&fork.join("edit"), "new"); // keep a changed file's own mtime too
        File::open(fork.join("edit"))
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(2_000_000))
            .unwrap();
        // A "keep" change in the fork shows as M.
        let changes = vec![
            Change::Modified("".into()),
            Change::Modified("keep".into()),
            Change::Modified("edit".into()),
            Change::Removed("gone/deep/f".into()),
            Change::Removed("gone/deep".into()),
            Change::Removed("gone".into()),
            Change::Renamed("old".into(), "new".into()),
            Change::Added("added".into()),
            Change::Added("added/dir".into()),
            Change::Added("added/dir/file".into()),
            Change::Added("link".into()),
        ];
        apply(&changes, &fork, &parent).unwrap();
        assert_eq!(tree(&parent), tree(&fork));
        // Applying again changes nothing (a crash mid-copy is redone after
        // a rollback, but a second pass must not break either).
        apply(&changes, &fork, &parent).unwrap();
        assert_eq!(tree(&parent), tree(&fork));
    }

    #[test]
    fn a_fifo_is_refused_and_a_socket_skipped() {
        let t = tempfile::tempdir().unwrap();
        let (parent, fork) = (t.path().join("p"), t.path().join("f"));
        fs::create_dir_all(&parent).unwrap();
        fs::create_dir_all(&fork).unwrap();
        let _sock = std::os::unix::net::UnixListener::bind(fork.join("s")).unwrap();
        apply(&[Change::Added("s".into())], &fork, &parent).unwrap();
        assert!(!parent.join("s").exists());
        let st = std::process::Command::new("mkfifo")
            .arg(fork.join("q"))
            .status()
            .unwrap();
        assert!(st.success());
        assert!(matches!(
            apply(&[Change::Added("q".into())], &fork, &parent),
            Err(CopyError::Unsupported(_))
        ));
    }
}
