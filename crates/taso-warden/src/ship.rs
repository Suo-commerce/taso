//! The `fs` stream: Seals shipped as ZFS send streams to an object store
//! (v1.0 §1 P1, §3: "`zfs send -i` → Garage = `fs` stream").
//!
//! # Layout
//!
//! For a Vessel with Chronicle id `<id>` (hex), every accepted Seal `S`
//! gets exactly one stream, keyed by `S`'s lsn:
//!
//! ```text
//! <prefix>/<id>/fs/<S lsn, 20 digits>.zfs    the stream (full for the first
//!                                             Seal, incremental from the
//!                                             previous Seal otherwise)
//! <prefix>/<id>/fs/<S lsn, 20 digits>.meta   what it is: from, to, bytes, blake3
//! ```
//!
//! **A stream is shipped only once its `.meta` exists.**  The data object
//! goes first, the metadata last — the same rule as a Seal (layer first,
//! record last).  A crash in between leaves a data object without
//! metadata, which the next [`Shipper::ship`] simply sends again.
//!
//! The metadata binds the stream to the Chronicle: `from` and `to` are
//! (lsn, Seal record hash) pairs, so a stream can never be applied on top
//! of the wrong base, and a bucket holding another history is refused
//! rather than extended.
//!
//! # Streaming
//!
//! A send stream can be gigabytes.  It goes from the `zfs send` process to
//! the store without being held in memory, hashed (BLAKE3) and counted on
//! the way.  Reading it back ([`Shipper::open_stream`]) verifies length and
//! hash as it goes and fails at the end on any mismatch, so a corrupted
//! object can never be received silently.
//!
//! A plain `zfs send` does not carry the `taso:seal` property; the binding
//! travels in the `.meta` (`to`), and the receiving side re-applies it.
//!
//! [`LocalStore`] writes atomically to a directory (temp file, fsync,
//! rename, fsync the directory).  Garage (S3) is a second [`ObjectStore`]
//! behind the same trait.
//!
//! Normative references: v1.0 §1 (P1, P2), §3.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use taso_core::envelope::{ChronicleId, HashVal, Lsn};

use crate::segment::Position;
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
    /// The stream of `dataset@<to>`, incremental from `@<from>` if given.
    /// The reader fails, rather than ends, if the stream is incomplete.
    fn send(&self, dataset: &Dataset, from: Option<Lsn>, to: Lsn) -> io::Result<ByteStream>;
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
    fn send(&self, dataset: &Dataset, from: Option<Lsn>, to: Lsn) -> io::Result<ByteStream> {
        let mut cmd = Command::new(&self.program);
        cmd.arg("send");
        if let Some(f) = from {
            cmd.arg("-i").arg(format!("@{}", crate::zfs::snap_name(f)));
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

// ── Hashing ─────────────────────────────────────────────────────────

const STREAM_DOMAIN: &str = "taso.fs.stream.v1";

/// Counts and hashes (BLAKE3, derive-key mode) what passes through.
pub(crate) struct Hashing<R> {
    inner: R,
    hasher: blake3::Hasher,
    bytes: u64,
}

impl<R: Read> Hashing<R> {
    /// Hash under the `fs` stream domain.
    fn new(inner: R) -> Self {
        Self::with_domain(inner, STREAM_DOMAIN)
    }
    /// Hash under `domain`.
    pub(crate) fn with_domain(inner: R, domain: &str) -> Self {
        Self { inner, hasher: blake3::Hasher::new_derive_key(domain), bytes: 0 }
    }
    /// Bytes read so far and their hash.
    pub(crate) fn finish(&self) -> (u64, HashVal) {
        (self.bytes, HashVal::from_bytes(*self.hasher.finalize().as_bytes()))
    }
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
}

/// Fails at the end if the stream is not exactly what the metadata says.
struct Verifying {
    inner: Hashing<ByteStream>,
    expect: (u64, HashVal),
}

impl Read for Verifying {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if self.inner.bytes > self.expect.0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "stream is longer than its metadata says"));
        }
        if n == 0 && self.inner.finish() != self.expect {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "stream does not match its metadata"));
        }
        Ok(n)
    }
}

// ── Metadata ────────────────────────────────────────────────────────

/// What a shipped stream is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamMeta {
    /// The Seal it is incremental from; `None` for a full stream.
    pub from: Option<Position>,
    /// The Seal it brings the dataset to.
    pub to: Position,
    /// Its length.
    pub bytes: u64,
    /// Its BLAKE3 hash (derive-key domain `taso.fs.stream.v1`).
    pub blake3: HashVal,
}

const META_HEADER: &str = "taso-fs-stream v1";

impl StreamMeta {
    fn encode(&self) -> String {
        let from = match self.from {
            Some(p) => format!("from {} {}", p.lsn.get(), p.hash),
            None => "from none".to_string(),
        };
        format!(
            "{META_HEADER}\n{from}\nto {} {}\nbytes {}\nblake3 {}\n",
            self.to.lsn.get(),
            self.to.hash,
            self.bytes,
            self.blake3
        )
    }

    fn decode(s: &str) -> Option<Self> {
        let mut lines = s.strip_suffix('\n')?.split('\n');
        if lines.next()? != META_HEADER {
            return None;
        }
        let pos = |l: &str, tag: &str| -> Option<Position> {
            let mut w = l.strip_prefix(tag)?.split(' ');
            let lsn = w.next()?.parse().ok()?;
            let hash = hex32(w.next()?)?;
            w.next().is_none().then_some(Position { lsn: Lsn::new(lsn), hash })
        };
        let from_line = lines.next()?;
        let from = if from_line == "from none" { None } else { Some(pos(from_line, "from ")?) };
        let to = pos(lines.next()?, "to ")?;
        let bytes = lines.next()?.strip_prefix("bytes ")?.parse().ok()?;
        let blake3 = hex32(lines.next()?.strip_prefix("blake3 ")?)?;
        lines.next().is_none().then_some(Self { from, to, bytes, blake3 })
    }
}

fn hex32(s: &str) -> Option<HashVal> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(HashVal::from_bytes(out))
}

// ── Shipper ─────────────────────────────────────────────────────────

/// Why shipping or reading back failed.
#[derive(Debug)]
pub enum ShipError {
    /// The store or the sender failed.
    Io(io::Error),
    /// The store already holds a different history for this Seal.
    Mismatch {
        /// The Seal's lsn.
        lsn: Lsn,
        /// What the store has.
        found: Box<StreamMeta>,
    },
    /// A metadata object cannot be read.
    BadMeta(String),
    /// Seals must be given in increasing lsn order.
    Unordered,
}

impl fmt::Display for ShipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Mismatch { lsn, .. } => {
                write!(f, "the store holds another history for the Seal at lsn {}", lsn.get())
            }
            Self::BadMeta(k) => write!(f, "unreadable stream metadata {k}"),
            Self::Unordered => write!(f, "seals are not in increasing lsn order"),
        }
    }
}

impl std::error::Error for ShipError {}

impl From<io::Error> for ShipError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// What one [`Shipper::ship`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shipped {
    /// Seals whose streams were sent now.
    pub sent: Vec<Lsn>,
    /// Seals already shipped.
    pub present: Vec<Lsn>,
}

/// Ships one Vessel's Seals.
pub struct Shipper<S: ObjectStore, X: Sender> {
    store: S,
    sender: X,
    base: String,
}

impl<S: ObjectStore, X: Sender> Shipper<S, X> {
    /// A shipper for the Chronicle `id`, under `prefix` in `store`.
    pub fn new(store: S, sender: X, prefix: &str, id: ChronicleId) -> io::Result<Self> {
        let hex: String = id.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let base = format!("{prefix}/{hex}/fs");
        if !valid_key(&base) {
            return Err(bad_key(&base));
        }
        Ok(Self { store, sender, base })
    }

    fn keys(&self, lsn: Lsn) -> (String, String) {
        let stem = format!("{}/{:020}", self.base, lsn.get());
        (format!("{stem}.zfs"), format!("{stem}.meta"))
    }

    /// The metadata of the stream into the Seal at `lsn`, if shipped.
    pub fn meta(&self, lsn: Lsn) -> Result<Option<StreamMeta>, ShipError> {
        let (_, mk) = self.keys(lsn);
        let Some(r) = self.store.get(&mk)? else { return Ok(None) };
        let mut s = String::new();
        r.take(4096).read_to_string(&mut s).map_err(|_| ShipError::BadMeta(mk.clone()))?;
        StreamMeta::decode(&s).map(Some).ok_or(ShipError::BadMeta(mk))
    }

    /// Ship every Seal in `seals` (accepted Seals of `dataset`, in lsn
    /// order) that is not shipped yet.  Each stream is incremental from
    /// the Seal before it in `seals`; the first is full.
    pub fn ship(&self, dataset: &Dataset, seals: &[Position]) -> Result<Shipped, ShipError> {
        if seals.windows(2).any(|w| w[0].lsn >= w[1].lsn) {
            return Err(ShipError::Unordered);
        }
        let mut out = Shipped::default();
        let mut prev: Option<Position> = None;
        for &seal in seals {
            match self.meta(seal.lsn)? {
                Some(m) if m.from == prev && m.to == seal => out.present.push(seal.lsn),
                Some(m) => return Err(ShipError::Mismatch { lsn: seal.lsn, found: Box::new(m) }),
                None => {
                    self.ship_one(dataset, prev, seal)?;
                    out.sent.push(seal.lsn);
                }
            }
            prev = Some(seal);
        }
        Ok(out)
    }

    fn ship_one(&self, dataset: &Dataset, from: Option<Position>, to: Position) -> Result<(), ShipError> {
        let (dk, mk) = self.keys(to.lsn);
        let stream = self.sender.send(dataset, from.map(|p| p.lsn), to.lsn)?;
        let mut hashing = Hashing::new(stream);
        self.store.put(&dk, &mut hashing)?;
        let (bytes, blake3) = hashing.finish();
        let meta = StreamMeta { from, to, bytes, blake3 };
        self.store.put(&mk, &mut meta.encode().as_bytes())?;
        Ok(())
    }

    /// The shipped stream into the Seal at `lsn`, verified as it is read:
    /// the reader fails at the end unless length and hash match the
    /// metadata.  `None` if not shipped.
    pub fn open_stream(&self, lsn: Lsn) -> Result<Option<(StreamMeta, ByteStream)>, ShipError> {
        let Some(meta) = self.meta(lsn)? else { return Ok(None) };
        let (dk, _) = self.keys(lsn);
        let data = self.store.get(&dk)?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{dk} is missing but its metadata exists"))
        })?;
        let r = Verifying { inner: Hashing::new(data), expect: (meta.bytes, meta.blake3) };
        Ok(Some((meta, Box::new(r))))
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    type Calls = Vec<(Option<Lsn>, Lsn)>;

    /// Streams are their own description; can fail after some bytes.
    #[derive(Clone, Default)]
    struct FakeSend {
        calls: Rc<RefCell<Calls>>,
        fail_after: Rc<RefCell<Option<usize>>>,
    }

    struct Failing {
        data: io::Cursor<Vec<u8>>,
        left: usize,
    }

    impl Read for Failing {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.left == 0 {
                return Err(io::Error::other("zfs send died"));
            }
            let n = buf.len().min(self.left);
            let got = self.data.read(&mut buf[..n])?;
            self.left -= got;
            Ok(got)
        }
    }

    impl Sender for FakeSend {
        fn send(&self, _d: &Dataset, from: Option<Lsn>, to: Lsn) -> io::Result<ByteStream> {
            self.calls.borrow_mut().push((from, to));
            let body = match from {
                Some(f) => format!("incremental {}..{}", f.get(), to.get()),
                None => format!("full {}", to.get()),
            }
            .repeat(1000)
            .into_bytes();
            Ok(match self.fail_after.borrow_mut().take() {
                Some(left) => Box::new(Failing { data: io::Cursor::new(body), left }),
                None => Box::new(io::Cursor::new(body)),
            })
        }
    }

    fn seal(n: u64) -> Position {
        Position { lsn: Lsn::new(n), hash: HashVal::from_bytes([n as u8; 32]) }
    }

    fn setup() -> (tempfile::TempDir, Shipper<LocalStore, FakeSend>, FakeSend) {
        let dir = tempfile::tempdir().unwrap();
        let send = FakeSend::default();
        let s = Shipper::new(LocalStore::new(dir.path()), send.clone(), "vessels", ChronicleId::from_bytes([0xAB; 16]))
            .unwrap();
        (dir, s, send)
    }

    fn ds() -> Dataset {
        Dataset::new("tank/v").unwrap()
    }

    fn read_all(s: &Shipper<LocalStore, FakeSend>, lsn: u64) -> io::Result<Vec<u8>> {
        let (_, mut r) = s.open_stream(Lsn::new(lsn)).unwrap().unwrap();
        let mut v = Vec::new();
        r.read_to_end(&mut v)?;
        Ok(v)
    }

    #[test]
    fn first_full_then_incremental_and_idempotent() {
        let (_d, s, send) = setup();
        let seals = [seal(3), seal(7), seal(12)];
        let r = s.ship(&ds(), &seals).unwrap();
        assert_eq!(r.sent, vec![Lsn::new(3), Lsn::new(7), Lsn::new(12)]);
        assert_eq!(
            *send.calls.borrow(),
            vec![(None, Lsn::new(3)), (Some(Lsn::new(3)), Lsn::new(7)), (Some(Lsn::new(7)), Lsn::new(12))]
        );
        let m = s.meta(Lsn::new(7)).unwrap().unwrap();
        assert_eq!((m.from, m.to), (Some(seal(3)), seal(7)));
        assert_eq!(read_all(&s, 7).unwrap(), "incremental 3..7".repeat(1000).into_bytes());

        // Again: nothing sent.
        let r = s.ship(&ds(), &seals).unwrap();
        assert!(r.sent.is_empty());
        assert_eq!(r.present.len(), 3);
        assert_eq!(send.calls.borrow().len(), 3);
        // A new Seal: only it is sent, incremental from the last.
        let r = s.ship(&ds(), &[seal(3), seal(7), seal(12), seal(20)]).unwrap();
        assert_eq!(r.sent, vec![Lsn::new(20)]);
        assert_eq!(send.calls.borrow().last(), Some(&(Some(Lsn::new(12)), Lsn::new(20))));
    }

    #[test]
    fn crash_between_data_and_meta_is_resent() {
        let (dir, s, send) = setup();
        s.ship(&ds(), &[seal(1), seal(2)]).unwrap();
        let (_, mk) = s.keys(Lsn::new(2));
        fs::remove_file(dir.path().join(&mk)).unwrap();
        let r = s.ship(&ds(), &[seal(1), seal(2)]).unwrap();
        assert_eq!(r.sent, vec![Lsn::new(2)]);
        assert_eq!(send.calls.borrow().len(), 3);
        assert!(read_all(&s, 2).is_ok());
    }

    #[test]
    fn a_failed_send_leaves_no_object_and_no_meta() {
        let (dir, s, send) = setup();
        *send.fail_after.borrow_mut() = Some(500);
        assert!(matches!(s.ship(&ds(), &[seal(1)]), Err(ShipError::Io(_))));
        assert_eq!(s.meta(Lsn::new(1)).unwrap(), None);
        let (dk, _) = s.keys(Lsn::new(1));
        assert!(!dir.path().join(&dk).exists());
        let fs_dir = dir.path().join(dk).parent().unwrap().to_path_buf();
        assert_eq!(fs::read_dir(fs_dir).unwrap().count(), 0, "no temp file left");
        // And the next attempt ships it.
        assert_eq!(s.ship(&ds(), &[seal(1)]).unwrap().sent, vec![Lsn::new(1)]);
    }

    #[test]
    fn corrupted_or_truncated_streams_fail_when_read() {
        let (dir, s, _) = setup();
        s.ship(&ds(), &[seal(1)]).unwrap();
        let (dk, _) = s.keys(Lsn::new(1));
        let path = dir.path().join(&dk);
        let mut bytes = fs::read(&path).unwrap();
        bytes[100] ^= 1;
        fs::write(&path, &bytes).unwrap();
        assert_eq!(read_all(&s, 1).unwrap_err().kind(), io::ErrorKind::InvalidData);
        bytes[100] ^= 1;
        bytes.truncate(bytes.len() - 1);
        fs::write(&path, &bytes).unwrap();
        assert_eq!(read_all(&s, 1).unwrap_err().kind(), io::ErrorKind::InvalidData);
        bytes.extend_from_slice(b"ss");
        fs::write(&path, &bytes).unwrap();
        assert_eq!(read_all(&s, 1).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn another_history_in_the_store_is_refused() {
        let (_d, s, _) = setup();
        s.ship(&ds(), &[seal(1), seal(2)]).unwrap();
        // Same lsns, different Seal hash at 2.
        let other = Position { lsn: Lsn::new(2), hash: HashVal::from_bytes([9; 32]) };
        assert!(matches!(s.ship(&ds(), &[seal(1), other]), Err(ShipError::Mismatch { .. })));
        // Same Seal 2, but now claimed incremental from nothing.
        assert!(matches!(s.ship(&ds(), &[seal(2)]), Err(ShipError::Mismatch { .. })));
        assert!(matches!(s.ship(&ds(), &[seal(2), seal(1)]), Err(ShipError::Unordered)));
    }

    #[test]
    fn meta_round_trips_and_rejects_junk() {
        let m = StreamMeta { from: Some(seal(4)), to: seal(9), bytes: 123, blake3: HashVal::from_bytes([7; 32]) };
        assert_eq!(StreamMeta::decode(&m.encode()), Some(m));
        let full = StreamMeta { from: None, ..m };
        assert_eq!(StreamMeta::decode(&full.encode()), Some(full));
        for junk in ["", "taso-fs-stream v2\n", &m.encode().replace("bytes 123", "bytes x"), &format!("{}extra\n", m.encode())] {
            assert_eq!(StreamMeta::decode(junk), None, "{junk:?}");
        }
    }

    #[test]
    fn keys_are_validated() {
        for ok in ["a", "a/b.c", "vessels/ab12/fs/00000000000000000001.zfs"] {
            assert!(valid_key(ok), "{ok}");
        }
        for bad in ["", "/a", "a/", "a//b", "a/../b", "./a", "a b", "a\\b"] {
            assert!(!valid_key(bad), "{bad:?}");
        }
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        assert!(store.put("../escape", &mut &b"x"[..]).is_err());
        assert!(Shipper::new(store, FakeSend::default(), "../x", ChronicleId::from_bytes([0; 16])).is_err());
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

    #[test]
    fn hashing_domains_differ() {
        let mut a = Hashing::with_domain(&b"same bytes"[..], "taso.one");
        let mut b = Hashing::with_domain(&b"same bytes"[..], "taso.two");
        io::copy(&mut a, &mut io::sink()).unwrap();
        io::copy(&mut b, &mut io::sink()).unwrap();
        assert_eq!(a.finish().0, 10);
        assert_ne!(a.finish().1, b.finish().1);
    }

    // ── on a real pool ──────────────────────────────────────────────

    mod node {
        use super::*;
        use crate::zfs::Zfs;

        fn zfs(args: &[&str]) -> String {
            let out = Command::new("zfs").args(args).output().expect("run zfs");
            assert!(out.status.success(), "zfs {:?}: {}", args, String::from_utf8_lossy(&out.stderr));
            String::from_utf8_lossy(&out.stdout).into_owned()
        }

        /// Ship two Seals, then receive both streams into a fresh dataset:
        /// it ends up with both Seals' contents.
        #[test]
        #[ignore = "needs a ZFS pool: set TASO_ZFS_DATASET"]
        fn ship_then_receive_elsewhere() {
            let base = std::env::var("TASO_ZFS_DATASET").expect("set TASO_ZFS_DATASET");
            let root = format!("{base}/sh-{}", std::process::id());
            zfs(&["create", &root]);
            struct Cleanup(String);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = Command::new("zfs").args(["destroy", "-R", &self.0]).status();
                }
            }
            let _c = Cleanup(root.clone());

            let src = Dataset::new(&format!("{root}/src")).unwrap();
            let z = Zfs::cli();
            let mount = z.create(&src).unwrap().mountpoint.unwrap();
            fs::write(mount.join("f"), b"one").unwrap();
            z.snapshot(&src, Lsn::new(1), HashVal::from_bytes([1; 32])).unwrap();
            fs::write(mount.join("f"), b"two").unwrap();
            z.snapshot(&src, Lsn::new(2), HashVal::from_bytes([2; 32])).unwrap();

            let store_dir = tempfile::tempdir().unwrap();
            let id = ChronicleId::from_bytes([0x5A; 16]);
            let s = Shipper::new(LocalStore::new(store_dir.path()), ZfsSend::default(), "vessels", id).unwrap();
            let seals = [
                Position { lsn: Lsn::new(1), hash: HashVal::from_bytes([1; 32]) },
                Position { lsn: Lsn::new(2), hash: HashVal::from_bytes([2; 32]) },
            ];
            let r = s.ship(&src, &seals).unwrap();
            assert_eq!(r.sent.len(), 2);
            println!(
                "full {} bytes, incremental {} bytes",
                s.meta(Lsn::new(1)).unwrap().unwrap().bytes,
                s.meta(Lsn::new(2)).unwrap().unwrap().bytes
            );

            let dst = format!("{root}/dst");
            for lsn in [1u64, 2] {
                let (_, mut stream) = s.open_stream(Lsn::new(lsn)).unwrap().unwrap();
                let mut child = Command::new("zfs")
                    .args(["receive", &dst])
                    .stdin(Stdio::piped())
                    .spawn()
                    .unwrap();
                io::copy(&mut stream, child.stdin.as_mut().unwrap()).unwrap();
                drop(child.stdin.take());
                assert!(child.wait().unwrap().success(), "receive {lsn}");
            }
            let dmount = PathBuf::from(zfs(&["get", "-H", "-o", "value", "mountpoint", &dst]).trim());
            assert_eq!(fs::read(dmount.join("f")).unwrap(), b"two");
            let first = dmount.join(".zfs/snapshot").join(crate::zfs::snap_name(Lsn::new(1))).join("f");
            assert_eq!(fs::read(first).unwrap(), b"one");
            // The snapshots arrived under their Seal names.  A plain send
            // does not carry user properties, so the taso:seal binding is
            // not on them; rebirth re-binds from the .meta (P2).
            let dst_ds = Dataset::new(&dst).unwrap();
            let got: Vec<_> = z.list(&dst_ds).unwrap().into_iter().map(|s| s.seal).collect();
            assert_eq!(got, vec![Lsn::new(1), Lsn::new(2)]);
        }
    }
}
