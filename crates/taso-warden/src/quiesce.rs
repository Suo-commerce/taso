//! Quiescence: Phase 1's one SQLite rule (v1.0 §3).
//!
//! In Phase 1, SQLite is a normal file on the Vessel's dataset.  A Seal is
//! taken only at a turn boundary where the harness reports no open
//! transaction, and the Warden checks the claim: no `-wal` changed since
//! the harness's quiescence signal, and no rollback journal is hot.
//!
//! # Metadata only
//!
//! The spec forbids the Warden a file handle to Vessel data (v1.0 §7,
//! negative space 2), so this module never opens a database file.  It
//! `lstat`s `<db>-wal` and `<db>-journal` — size, mtime, inode, file type
//! — and nothing else.  The final path component is never followed: the
//! agent controls everything in its dataset, so a symlink, FIFO, device
//! or directory where a WAL or journal should be is reported as not
//! quiescent rather than looked through.  (Intermediate directories are
//! resolved normally; the information an `lstat` can leak is size and
//! time, and the database paths are configured by the operator, not the
//! agent.)
//!
//! # Use
//!
//! [`Watch::sample`] at the quiescence signal; [`Watch::sample`] again
//! after the layer is frozen and before the Seal record is appended;
//! [`verify`] the two.  If anything changed, the frozen layer may hold a
//! write that happened after the harness said it was done, and the Seal
//! must not be taken.  Phase 2 removes all of this (v1.0 §5).

use std::fmt;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// Which companion file of a database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Companion {
    /// `<db>-wal`.
    Wal,
    /// `<db>-journal`.
    Journal,
}

impl Companion {
    fn suffix(self) -> &'static str {
        match self {
            Self::Wal => "-wal",
            Self::Journal => "-journal",
        }
    }
}

/// What `lstat` saw for one companion file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seen {
    /// No such file.
    Absent,
    /// A regular file.
    File {
        /// Inode (a replaced file has a new one).
        ino: u64,
        /// Size in bytes.
        size: u64,
        /// Modification time, nanoseconds since the epoch.
        mtime_ns: i128,
    },
    /// Something that is not a regular file: symlink, FIFO, socket,
    /// device or directory.
    NotAFile,
}

/// One database's companions at one moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DbSample {
    /// The database path, relative to the dataset mount.
    pub db: PathBuf,
    /// Its `-wal`.
    pub wal: Seen,
    /// Its `-journal`.
    pub journal: Seen,
}

/// Every watched database at one moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sample(pub Vec<DbSample>);

/// Why a turn is not quiescent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotQuiescent {
    /// A rollback journal is present and not empty: a transaction is open
    /// (or was interrupted and is hot).
    HotJournal(PathBuf),
    /// The WAL changed between the two samples.
    WalChanged(PathBuf),
    /// The journal changed between the two samples.
    JournalChanged(PathBuf),
    /// A companion is not a regular file.
    NotAFile(PathBuf, Companion),
    /// The two samples do not cover the same databases.
    Mismatched,
}

impl fmt::Display for NotQuiescent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HotJournal(db) => write!(f, "{}: rollback journal is hot", db.display()),
            Self::WalChanged(db) => write!(
                f,
                "{}: WAL changed since the quiescence signal",
                db.display()
            ),
            Self::JournalChanged(db) => {
                write!(
                    f,
                    "{}: journal changed since the quiescence signal",
                    db.display()
                )
            }
            Self::NotAFile(db, c) => {
                write!(f, "{}{} is not a regular file", db.display(), c.suffix())
            }
            Self::Mismatched => write!(f, "samples cover different databases"),
        }
    }
}

impl std::error::Error for NotQuiescent {}

/// The databases of one Vessel to watch.
#[derive(Clone, Debug)]
pub struct Watch {
    mount: PathBuf,
    dbs: Vec<PathBuf>,
}

impl Watch {
    /// Watch `dbs` (paths relative to `mount`).  Refuses absolute paths,
    /// `..`, and empty paths: a watched database must be inside the
    /// dataset.
    pub fn new(mount: impl Into<PathBuf>, dbs: &[&str]) -> io::Result<Self> {
        let mut out = Vec::with_capacity(dbs.len());
        for db in dbs {
            let p = Path::new(db);
            let inside = !db.is_empty()
                && p.components()
                    .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
            if !inside {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{db:?} is not a relative path inside the dataset"),
                ));
            }
            out.push(p.to_path_buf());
        }
        Ok(Self {
            mount: mount.into(),
            dbs: out,
        })
    }

    /// `lstat` every companion of every watched database.
    pub fn sample(&self) -> io::Result<Sample> {
        let mut out = Vec::with_capacity(self.dbs.len());
        for db in &self.dbs {
            out.push(DbSample {
                db: db.clone(),
                wal: self.seen(db, Companion::Wal)?,
                journal: self.seen(db, Companion::Journal)?,
            });
        }
        Ok(Sample(out))
    }

    fn seen(&self, db: &Path, c: Companion) -> io::Result<Seen> {
        let mut name = self.mount.join(db).into_os_string();
        name.push(c.suffix());
        match std::fs::symlink_metadata(&name) {
            Ok(m) if m.file_type().is_file() => Ok(Seen::File {
                ino: m.ino(),
                size: m.size(),
                mtime_ns: m.mtime() as i128 * 1_000_000_000 + m.mtime_nsec() as i128,
            }),
            Ok(_) => Ok(Seen::NotAFile),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Seen::Absent),
            Err(e) => Err(e),
        }
    }
}

/// Is the turn quiescent, given a sample at the signal (`before`) and one
/// after the layer was frozen (`after`)?  Reports the first problem.
pub fn verify(before: &Sample, after: &Sample) -> Result<(), NotQuiescent> {
    if before.0.len() != after.0.len() {
        return Err(NotQuiescent::Mismatched);
    }
    for (b, a) in before.0.iter().zip(&after.0) {
        if b.db != a.db {
            return Err(NotQuiescent::Mismatched);
        }
        for (seen, c) in [
            (&b.wal, Companion::Wal),
            (&a.wal, Companion::Wal),
            (&b.journal, Companion::Journal),
            (&a.journal, Companion::Journal),
        ] {
            if *seen == Seen::NotAFile {
                return Err(NotQuiescent::NotAFile(b.db.clone(), c));
            }
        }
        for j in [&b.journal, &a.journal] {
            if matches!(j, Seen::File { size, .. } if *size > 0) {
                return Err(NotQuiescent::HotJournal(b.db.clone()));
            }
        }
        if b.journal != a.journal {
            return Err(NotQuiescent::JournalChanged(b.db.clone()));
        }
        if b.wal != a.wal {
            return Err(NotQuiescent::WalChanged(b.db.clone()));
        }
    }
    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn setup() -> (tempfile::TempDir, Watch) {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("state.db"), b"db").unwrap();
        let w = Watch::new(dir.path(), &["state.db"]).unwrap();
        (dir, w)
    }

    fn append(path: &Path, bytes: &[u8]) {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    #[test]
    fn nothing_written_is_quiescent() {
        let (dir, w) = setup();
        append(&dir.path().join("state.db-wal"), &[0; 4096]);
        let a = w.sample().unwrap();
        let b = w.sample().unwrap();
        assert_eq!(verify(&a, &b), Ok(()));
        // No companions at all is quiescent too.
        fs::remove_file(dir.path().join("state.db-wal")).unwrap();
        let a = w.sample().unwrap();
        assert_eq!(verify(&a, &w.sample().unwrap()), Ok(()));
    }

    #[test]
    fn wal_growth_after_the_signal_is_caught() {
        let (dir, w) = setup();
        let wal = dir.path().join("state.db-wal");
        append(&wal, &[0; 4096]);
        let before = w.sample().unwrap();
        append(&wal, &[1; 4120]);
        assert_eq!(
            verify(&before, &w.sample().unwrap()),
            Err(NotQuiescent::WalChanged("state.db".into()))
        );
    }

    #[test]
    fn wal_created_or_removed_or_replaced_is_caught() {
        let (dir, w) = setup();
        let wal = dir.path().join("state.db-wal");
        let before = w.sample().unwrap();
        append(&wal, &[0; 32]);
        assert!(matches!(
            verify(&before, &w.sample().unwrap()),
            Err(NotQuiescent::WalChanged(_))
        ));

        let before = w.sample().unwrap();
        fs::remove_file(&wal).unwrap();
        assert!(matches!(
            verify(&before, &w.sample().unwrap()),
            Err(NotQuiescent::WalChanged(_))
        ));

        // Same size, new inode (checkpoint + reset that recreates it).
        append(&wal, &[0; 32]);
        let before = w.sample().unwrap();
        let tmp = dir.path().join("tmp");
        fs::write(&tmp, [0; 32]).unwrap();
        fs::rename(&tmp, &wal).unwrap();
        assert!(matches!(
            verify(&before, &w.sample().unwrap()),
            Err(NotQuiescent::WalChanged(_))
        ));
    }

    #[test]
    fn hot_rollback_journal_is_not_quiescent() {
        let (dir, w) = setup();
        let journal = dir.path().join("state.db-journal");
        append(&journal, &[0; 512]);
        let a = w.sample().unwrap();
        assert_eq!(
            verify(&a, &w.sample().unwrap()),
            Err(NotQuiescent::HotJournal("state.db".into()))
        );
        // An empty journal (journal_mode=TRUNCATE after commit) is fine.
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&journal)
            .unwrap();
        let a = w.sample().unwrap();
        assert_eq!(verify(&a, &w.sample().unwrap()), Ok(()));
    }

    #[test]
    fn symlinks_and_fifos_are_not_looked_through() {
        let (dir, w) = setup();
        let target = dir.path().join("elsewhere");
        fs::write(&target, b"host file").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("state.db-wal")).unwrap();
        let a = w.sample().unwrap();
        assert_eq!(a.0[0].wal, Seen::NotAFile);
        assert_eq!(
            verify(&a, &w.sample().unwrap()),
            Err(NotQuiescent::NotAFile("state.db".into(), Companion::Wal))
        );

        fs::remove_file(dir.path().join("state.db-wal")).unwrap();
        fs::create_dir(dir.path().join("state.db-journal")).unwrap();
        let a = w.sample().unwrap();
        assert_eq!(
            verify(&a, &w.sample().unwrap()),
            Err(NotQuiescent::NotAFile(
                "state.db".into(),
                Companion::Journal
            ))
        );
    }

    #[test]
    fn several_databases_report_the_one_that_moved() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        let w = Watch::new(dir.path(), &["a.db", "sub/b.db"]).unwrap();
        append(&dir.path().join("a.db-wal"), &[0; 8]);
        append(&dir.path().join("sub/b.db-wal"), &[0; 8]);
        let before = w.sample().unwrap();
        append(&dir.path().join("sub/b.db-wal"), &[1; 8]);
        assert_eq!(
            verify(&before, &w.sample().unwrap()),
            Err(NotQuiescent::WalChanged("sub/b.db".into()))
        );
    }

    #[test]
    fn watched_paths_must_be_inside_the_dataset() {
        for bad in ["", "/etc/state.db", "../state.db", "a/../../state.db"] {
            assert!(Watch::new("/m", &[bad]).is_err(), "{bad:?}");
        }
        assert!(Watch::new("/m", &["state.db", "./data/state.db"]).is_ok());
    }

    #[test]
    fn samples_of_different_watches_do_not_compare() {
        let (_d, w) = setup();
        let other = Watch::new("/nonexistent", &["x.db"]).unwrap();
        assert_eq!(
            verify(&w.sample().unwrap(), &other.sample().unwrap()),
            Err(NotQuiescent::Mismatched)
        );
        assert_eq!(
            verify(&w.sample().unwrap(), &Sample(vec![])),
            Err(NotQuiescent::Mismatched)
        );
    }
}
