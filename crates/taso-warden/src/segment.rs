//! The Warden's local Chronicle log: one append-only segment file
//! (v1.0 §1 P1, v0.4 §8.3).
//!
//! The append path is: write the record here and fsync, *then*
//! [`Coord::append`](crate::coordinator::Coord::append).
//! Because of that order, the coordinator can never have accepted a record
//! that is not on local disk, and anything on local disk past the
//! coordinator's anchored head was never accepted and must not be
//! replayed.  [`Segment::open`] enforces both on recovery.
//!
//! # Format
//!
//! ```text
//! header  magic "TASOSEG\0" (8) · version (1) · chronicle (16)
//!         · base lsn (8) · base hash (32)                      = 65 bytes
//! frame   payload length u32 (4) · envelope (137) · payload bytes
//! envelope chronicle (16) · branch (8) · epoch (8) · stream (1)
//!         · lsn (8) · prev (32) · payload_hash (32) · hash (32)
//! ```
//!
//! All integers are big-endian.  The first frame chains from the header's
//! base `(lsn, hash)`: `(0, GENESIS)` for a new Chronicle, the previous
//! segment's tail after a roll.
//!
//! There is no separate checksum.  A frame is valid only if its envelope
//! verifies and `payload_hash(bytes) == envelope.payload_hash`; the BLAKE3
//! chain covers every byte, so a torn or garbled frame fails to verify.
//! The first invalid frame ends the valid prefix.
//!
//! The payload is stored as opaque canonical bytes and never decoded here
//! (v0.4 §2.1: envelope always, payload never).
//!
//! Normative references: v0.4 §2.1, §4, §8.3–8.5; v1.0 §1 (P1), §3.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use taso_core::envelope::{
    payload_hash, BranchId, ChronicleHead, ChronicleId, Envelope, Epoch, HashVal, Lsn, Stream,
};

// ── Layout ──────────────────────────────────────────────────────────

const MAGIC: [u8; 8] = *b"TASOSEG\0";
const VERSION: u8 = 1;
pub(crate) const HEADER_LEN: u64 = 8 + 1 + 16 + 8 + 32;
pub(crate) const ENVELOPE_LEN: usize = 16 + 8 + 8 + 1 + 8 + 32 + 32 + 32;
const FRAME_PREFIX: usize = 4 + ENVELOPE_LEN;

/// Largest payload a frame may carry.  A torn length field larger than
/// this is treated as the end of the valid prefix, not as an allocation.
pub const MAX_PAYLOAD: u32 = 64 * 1024 * 1024;

// ── Types ───────────────────────────────────────────────────────────

/// A position in the chain: an lsn and the hash of the record at it
/// (or the base the first frame chains from).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    /// The lsn.
    pub lsn: Lsn,
    /// The record hash at that lsn.
    pub hash: HashVal,
}

impl Position {
    /// The position before the first record of a Chronicle.
    pub const GENESIS: Self = Self {
        lsn: Lsn::new(0),
        hash: HashVal::GENESIS,
    };
}

impl From<ChronicleHead> for Position {
    fn from(h: ChronicleHead) -> Self {
        Self {
            lsn: h.lsn,
            hash: h.hash,
        }
    }
}

/// One record read back from a segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// The verified envelope.
    pub envelope: Envelope,
    /// The payload's canonical bytes, opaque.
    pub payload: Vec<u8>,
}

/// What [`Segment::open`] dropped to land on the anchored head.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Recovery {
    /// Valid frames past the anchored head: written locally, never
    /// accepted by the coordinator.
    pub unaccepted_frames: u64,
    /// Bytes after the valid prefix (a torn or garbled tail).
    pub invalid_bytes: u64,
}

// ── Errors ──────────────────────────────────────────────────────────

/// Why a segment operation failed.
#[derive(Debug)]
pub enum SegmentError {
    /// The file system failed.
    Io(io::Error),
    /// The header is missing or malformed.
    BadHeader(&'static str),
    /// The envelope belongs to another Chronicle.
    ChronicleMismatch {
        /// The segment's Chronicle.
        expected: ChronicleId,
        /// The envelope's.
        got: ChronicleId,
    },
    /// The envelope's lsn is not the tail's lsn + 1.
    NotNext {
        /// What the envelope carried.
        lsn: Lsn,
        /// What the segment expected.
        expected: Lsn,
    },
    /// The envelope's `prev` is not the tail's hash.
    PrevMismatch {
        /// The envelope's lsn.
        lsn: Lsn,
    },
    /// The envelope's hash does not verify over its own fields.
    BadHash {
        /// The envelope's lsn.
        lsn: Lsn,
    },
    /// The payload bytes do not hash to the envelope's `payload_hash`.
    PayloadHashMismatch {
        /// The envelope's lsn.
        lsn: Lsn,
    },
    /// The payload is larger than [`MAX_PAYLOAD`].
    PayloadTooLarge {
        /// Its length.
        len: usize,
    },
    /// The local record at the anchored lsn is not the anchored record.
    Diverged {
        /// The anchored lsn.
        lsn: Lsn,
    },
    /// The coordinator accepted records this segment does not have.
    MissingAccepted {
        /// The anchored lsn.
        anchored: Lsn,
        /// The end of the local valid prefix.
        local_tail: Lsn,
    },
    /// The anchor is before this segment's base.
    AnchorBeforeBase {
        /// The anchored lsn.
        anchored: Lsn,
        /// The segment's base lsn.
        base: Lsn,
    },
    /// A closed segment (not the newest) has bytes after its valid prefix.
    /// A closed segment is complete by definition: nothing is cut from it.
    ClosedTorn {
        /// Bytes after the valid prefix.
        invalid_bytes: u64,
    },
    /// `truncate_to` an lsn outside `[base, tail]`.
    OutOfRange {
        /// The requested lsn.
        lsn: Lsn,
    },
    /// An earlier write failed and could not be rolled back; reopen.
    Poisoned,
}

impl fmt::Display for SegmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::BadHeader(r) => write!(f, "bad segment header: {r}"),
            Self::ChronicleMismatch { expected, got } => {
                write!(f, "chronicle {got:?} is not this segment's {expected:?}")
            }
            Self::NotNext { lsn, expected } => {
                write!(
                    f,
                    "lsn {} is not the next lsn {}",
                    lsn.get(),
                    expected.get()
                )
            }
            Self::PrevMismatch { lsn } => write!(f, "lsn {}: prev is not the tail", lsn.get()),
            Self::BadHash { lsn } => write!(f, "lsn {}: envelope does not verify", lsn.get()),
            Self::PayloadHashMismatch { lsn } => {
                write!(f, "lsn {}: payload does not match its hash", lsn.get())
            }
            Self::PayloadTooLarge { len } => write!(f, "payload of {len} bytes is too large"),
            Self::Diverged { lsn } => {
                write!(
                    f,
                    "local record at lsn {} is not the anchored record",
                    lsn.get()
                )
            }
            Self::MissingAccepted {
                anchored,
                local_tail,
            } => write!(
                f,
                "coordinator accepted up to lsn {} but the segment ends at {}",
                anchored.get(),
                local_tail.get()
            ),
            Self::AnchorBeforeBase { anchored, base } => write!(
                f,
                "anchor lsn {} is before the segment base {}",
                anchored.get(),
                base.get()
            ),
            Self::ClosedTorn { invalid_bytes } => {
                write!(
                    f,
                    "a closed segment has {invalid_bytes} bytes after its valid frames"
                )
            }
            Self::OutOfRange { lsn } => write!(f, "lsn {} is outside the segment", lsn.get()),
            Self::Poisoned => write!(f, "segment is poisoned by an earlier failed write"),
        }
    }
}

impl std::error::Error for SegmentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for SegmentError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

// ── Segment ─────────────────────────────────────────────────────────

/// One append-only segment file.
///
/// Holds a small in-memory index (the hash and end offset of each frame)
/// so that `truncate_to` and `frames` never re-scan.
#[derive(Debug)]
pub struct Segment {
    path: PathBuf,
    file: File,
    chronicle: ChronicleId,
    base: Position,
    /// `hashes[i]` is the hash of the frame at lsn `base + 1 + i`.
    hashes: Vec<HashVal>,
    /// `ends[i]` is the byte offset just past that frame.
    ends: Vec<u64>,
    poisoned: bool,
}

impl Segment {
    /// Create a new, empty segment at `path`.  Refuses if the file exists.
    ///
    /// The header is fsynced, and so is the parent directory, so the file
    /// itself survives a crash.
    pub fn create(
        path: impl AsRef<Path>,
        chronicle: ChronicleId,
        base: Position,
    ) -> Result<Self, SegmentError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        let mut header = Vec::with_capacity(HEADER_LEN as usize);
        header.extend_from_slice(&MAGIC);
        header.push(VERSION);
        header.extend_from_slice(chronicle.as_bytes());
        header.extend_from_slice(&base.lsn.get().to_be_bytes());
        header.extend_from_slice(base.hash.as_bytes());
        file.write_all_at(&header, 0)?;
        file.sync_all()?;
        sync_parent(&path)?;
        Ok(Self {
            path,
            file,
            chronicle,
            base,
            hashes: Vec::new(),
            ends: Vec::new(),
            poisoned: false,
        })
    }

    /// Open an existing segment and recover it against the coordinator's
    /// anchored head.
    ///
    /// Scans the valid prefix, then:
    /// - the record at the anchored lsn must be the anchored record, else
    ///   [`SegmentError::Diverged`];
    /// - the valid prefix must reach the anchored lsn, else
    ///   [`SegmentError::MissingAccepted`] — nothing is truncated;
    /// - everything after the anchored head is truncated and fsynced away.
    pub fn open(
        path: impl AsRef<Path>,
        anchored: ChronicleHead,
    ) -> Result<(Self, Recovery), SegmentError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().read(true).write(true).open(&path)?;
        let file_len = file.metadata()?.len();
        let (chronicle, base) = read_header(&file)?;
        let mut seg = Self {
            path,
            file,
            chronicle,
            base,
            hashes: Vec::new(),
            ends: Vec::new(),
            poisoned: false,
        };
        seg.scan(file_len)?;

        let anchor = Position::from(anchored);
        if anchor.lsn < base.lsn {
            return Err(SegmentError::AnchorBeforeBase {
                anchored: anchor.lsn,
                base: base.lsn,
            });
        }
        let local_tail = seg.tail();
        if anchor.lsn > local_tail.lsn {
            return Err(SegmentError::MissingAccepted {
                anchored: anchor.lsn,
                local_tail: local_tail.lsn,
            });
        }
        if seg.hash_at(anchor.lsn) != Some(anchor.hash) {
            return Err(SegmentError::Diverged { lsn: anchor.lsn });
        }

        let keep = (anchor.lsn.get() - base.lsn.get()) as usize;
        let valid_end = seg.end_of_index(seg.hashes.len());
        let recovery = Recovery {
            unaccepted_frames: (seg.hashes.len() - keep) as u64,
            invalid_bytes: file_len - valid_end,
        };
        if recovery != Recovery::default() {
            seg.cut(keep)?;
        }
        Ok((seg, recovery))
    }

    /// Open a closed segment: one that a newer segment follows.  It is read
    /// and verified in full and never written: every byte must belong to a
    /// valid frame ([`SegmentError::ClosedTorn`] otherwise), because only the
    /// newest segment can have been cut off by a crash.  The returned
    /// segment refuses appends.
    pub fn open_closed(path: impl AsRef<Path>) -> Result<Self, SegmentError> {
        let (seg, file_len) = Self::read_only(path.as_ref())?;
        let valid_end = seg.end_of_index(seg.hashes.len());
        if valid_end != file_len {
            return Err(SegmentError::ClosedTorn {
                invalid_bytes: file_len - valid_end,
            });
        }
        Ok(seg)
    }

    /// Open the segment at `path` for reading only: the valid prefix is
    /// indexed, a torn tail is ignored (not cut), and appends are refused.
    /// For inspecting a log another process owns.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, SegmentError> {
        Ok(Self::read_only(path.as_ref())?.0)
    }

    /// The position of the last valid frame in the segment at `path`, read
    /// without writing anything (a torn tail is ignored, not cut).
    pub fn peek_tail(path: impl AsRef<Path>) -> Result<Position, SegmentError> {
        Ok(Self::read_only(path.as_ref())?.0.tail())
    }

    /// Open read-only and index the valid prefix; also return the file length.
    fn read_only(path: &Path) -> Result<(Self, u64), SegmentError> {
        let file = OpenOptions::new().read(true).open(path)?;
        let file_len = file.metadata()?.len();
        let (chronicle, base) = read_header(&file)?;
        let mut seg = Self {
            path: path.to_path_buf(),
            file,
            chronicle,
            base,
            hashes: Vec::new(),
            ends: Vec::new(),
            // Read-only: refuse writes the same way a failed write does.
            poisoned: true,
        };
        seg.scan(file_len)?;
        Ok((seg, file_len))
    }

    /// Append one record and fsync it.
    ///
    /// Checks the local chain first: same Chronicle, `lsn == tail + 1`,
    /// `prev == tail.hash`, the envelope verifies, and the payload matches
    /// its hash.  Only after this returns `Ok` may the Warden submit the
    /// envelope to the coordinator.
    ///
    /// If the write or fsync fails, the frame is cut off again; if even
    /// that fails, the segment is poisoned and refuses further writes.
    pub fn append(
        &mut self,
        envelope: &Envelope,
        payload: &[u8],
    ) -> Result<Position, SegmentError> {
        self.append_batch(&[(envelope, payload)])
    }

    /// Append consecutive frames in one write and one fsync: each must
    /// follow the one before it as [`Segment::append`] requires.  Nothing
    /// is written unless all of them pass.  A crash during the write
    /// leaves a prefix of them, the last possibly torn; recovery treats
    /// them like any unaccepted tail.
    pub fn append_batch(
        &mut self,
        frames: &[(&Envelope, &[u8])],
    ) -> Result<Position, SegmentError> {
        if self.poisoned {
            return Err(SegmentError::Poisoned);
        }
        let mut tail = self.tail();
        let mut buf = Vec::new();
        let mut ends = Vec::with_capacity(frames.len());
        let start = self.end_of_index(self.hashes.len());
        for (envelope, payload) in frames {
            check_frame(self.chronicle, tail, envelope, payload)?;
            buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            encode_envelope(envelope, &mut buf);
            buf.extend_from_slice(payload);
            ends.push(start + buf.len() as u64);
            tail = Position {
                lsn: envelope.lsn,
                hash: envelope.hash,
            };
        }
        if frames.is_empty() {
            return Ok(tail);
        }

        let _t = crate::timing::span("append.fsync");
        let written = self
            .file
            .write_all_at(&buf, start)
            .and_then(|()| self.file.sync_data());
        if let Err(e) = written {
            if self
                .file
                .set_len(start)
                .and_then(|()| self.file.sync_all())
                .is_err()
            {
                self.poisoned = true;
            }
            return Err(SegmentError::Io(e));
        }
        self.hashes.extend(frames.iter().map(|(e, _)| e.hash));
        self.ends.extend(ends);
        Ok(self.tail())
    }

    /// Drop every frame after `lsn` and fsync.  Used when the coordinator
    /// refuses an append: the refused frame was never accepted and must
    /// not stay on disk.
    pub fn truncate_to(&mut self, lsn: Lsn) -> Result<(), SegmentError> {
        if self.poisoned {
            return Err(SegmentError::Poisoned);
        }
        if lsn < self.base.lsn || lsn > self.tail().lsn {
            return Err(SegmentError::OutOfRange { lsn });
        }
        self.cut((lsn.get() - self.base.lsn.get()) as usize)
    }

    /// The last record in the segment, or the base if it is empty.
    pub fn tail(&self) -> Position {
        match self.hashes.last() {
            Some(&hash) => Position {
                lsn: Lsn::new(self.base.lsn.get() + self.hashes.len() as u64),
                hash,
            },
            None => self.base,
        }
    }

    /// The position the first frame chains from.
    pub fn base(&self) -> Position {
        self.base
    }

    /// The segment's Chronicle.
    pub fn chronicle(&self) -> ChronicleId {
        self.chronicle
    }

    /// The segment's file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Bytes in the file: the header and every frame.
    pub fn bytes(&self) -> u64 {
        self.ends.last().copied().unwrap_or(HEADER_LEN)
    }

    /// Number of frames.
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// True if the segment holds no frames.
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Read every frame back, in order.
    pub fn frames(&self) -> Result<Vec<Frame>, SegmentError> {
        self.read_from(0)
    }

    /// The frames after `lsn`, in order, read from their offset in one
    /// read: none of the file before them is touched.
    pub fn frames_after(&self, lsn: Lsn) -> Result<Vec<Frame>, SegmentError> {
        let first = lsn.get().saturating_sub(self.base.lsn.get()) as usize;
        self.read_from(first.min(self.hashes.len()))
    }

    /// The frame at `lsn`, read from its offset; `None` if this segment
    /// does not hold it.
    pub fn frame(&self, lsn: Lsn) -> Result<Option<Frame>, SegmentError> {
        let Some(i) = self.index_of(lsn) else {
            return Ok(None);
        };
        Ok(self.read_range(i, i + 1)?.pop())
    }

    /// The hash at `lsn`, from the in-memory index (no read): a frame's,
    /// or the base's at the base lsn.  `None` if this segment knows neither.
    pub fn hash_at(&self, lsn: Lsn) -> Option<HashVal> {
        if lsn == self.base.lsn {
            return Some(self.base.hash);
        }
        self.index_of(lsn).map(|i| self.hashes[i])
    }

    // ── internals ───────────────────────────────────────────────────

    /// Byte offset where frame `i` starts (= where frame `i - 1` ends).
    fn end_of_index(&self, i: usize) -> u64 {
        if i == 0 {
            HEADER_LEN
        } else {
            self.ends[i - 1]
        }
    }

    /// The index of the frame at `lsn`, if this segment holds it.
    fn index_of(&self, lsn: Lsn) -> Option<usize> {
        let i = lsn.get().checked_sub(self.base.lsn.get() + 1)? as usize;
        (i < self.hashes.len()).then_some(i)
    }

    /// Frames `first ..` to the end, in one read.
    fn read_from(&self, first: usize) -> Result<Vec<Frame>, SegmentError> {
        self.read_range(first, self.hashes.len())
    }

    /// Frames `first .. last` (indexes), in one read of their bytes.
    fn read_range(&self, first: usize, last: usize) -> Result<Vec<Frame>, SegmentError> {
        if first >= last {
            return Ok(Vec::new());
        }
        let start = self.end_of_index(first);
        let mut buf = vec![0u8; (self.ends[last - 1] - start) as usize];
        self.file.read_exact_at(&mut buf, start)?;
        let mut out = Vec::with_capacity(last - first);
        let mut at = start;
        for i in first..last {
            let frame = &buf[(at - start) as usize..(self.ends[i] - start) as usize];
            let envelope = decode_envelope(&frame[4..FRAME_PREFIX]);
            out.push(Frame {
                envelope,
                payload: frame[FRAME_PREFIX..].to_vec(),
            });
            at = self.ends[i];
        }
        Ok(out)
    }

    /// Keep the first `keep` frames; truncate the file after them; fsync.
    fn cut(&mut self, keep: usize) -> Result<(), SegmentError> {
        let end = self.end_of_index(keep);
        if let Err(e) = self.file.set_len(end).and_then(|()| self.file.sync_all()) {
            self.poisoned = true;
            return Err(SegmentError::Io(e));
        }
        self.hashes.truncate(keep);
        self.ends.truncate(keep);
        Ok(())
    }

    /// Build the index from the valid prefix of the file.
    fn scan(&mut self, file_len: u64) -> Result<(), SegmentError> {
        self.hashes.clear();
        self.ends.clear();
        let mut reader = BufReader::new(&self.file);
        let mut skip = [0u8; HEADER_LEN as usize];
        reader.read_exact(&mut skip)?;
        let mut pos = HEADER_LEN;
        let mut prefix = [0u8; FRAME_PREFIX];
        loop {
            if file_len - pos < FRAME_PREFIX as u64 {
                break;
            }
            reader.read_exact(&mut prefix)?;
            let len = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
            if len > MAX_PAYLOAD || file_len - pos - (FRAME_PREFIX as u64) < len as u64 {
                break;
            }
            let Some(envelope) = try_decode_envelope(&prefix[4..]) else {
                break;
            };
            let mut payload = vec![0u8; len as usize];
            reader.read_exact(&mut payload)?;
            if check_frame(self.chronicle, self.tail(), &envelope, &payload).is_err() {
                break;
            }
            pos += FRAME_PREFIX as u64 + len as u64;
            self.hashes.push(envelope.hash);
            self.ends.push(pos);
        }
        Ok(())
    }
}

// ── Frame checks and envelope codec ─────────────────────────────────

pub(crate) fn check_frame(
    chronicle: ChronicleId,
    tail: Position,
    env: &Envelope,
    payload: &[u8],
) -> Result<(), SegmentError> {
    if payload.len() > MAX_PAYLOAD as usize {
        return Err(SegmentError::PayloadTooLarge { len: payload.len() });
    }
    if env.chronicle != chronicle {
        return Err(SegmentError::ChronicleMismatch {
            expected: chronicle,
            got: env.chronicle,
        });
    }
    let expected = tail.lsn.next();
    if env.lsn != expected {
        return Err(SegmentError::NotNext {
            lsn: env.lsn,
            expected,
        });
    }
    if env.prev != tail.hash {
        return Err(SegmentError::PrevMismatch { lsn: env.lsn });
    }
    if !env.verify() {
        return Err(SegmentError::BadHash { lsn: env.lsn });
    }
    if payload_hash(payload) != env.payload_hash {
        return Err(SegmentError::PayloadHashMismatch { lsn: env.lsn });
    }
    Ok(())
}

pub(crate) fn encode_envelope(e: &Envelope, out: &mut Vec<u8>) {
    out.extend_from_slice(e.chronicle.as_bytes());
    out.extend_from_slice(&e.branch.get().to_be_bytes());
    out.extend_from_slice(&e.epoch.get().to_be_bytes());
    out.push(e.stream as u8);
    out.extend_from_slice(&e.lsn.get().to_be_bytes());
    out.extend_from_slice(e.prev.as_bytes());
    out.extend_from_slice(e.payload_hash.as_bytes());
    out.extend_from_slice(e.hash.as_bytes());
}

/// Decode an envelope; `None` if the stream byte is unknown.  The hash is
/// taken as stored, not recomputed — callers verify.
pub(crate) fn try_decode_envelope(b: &[u8]) -> Option<Envelope> {
    let stream = match b[32] {
        0 => Stream::Fs,
        1 => Stream::Db,
        2 => Stream::Transcript,
        3 => Stream::Effect,
        4 => Stream::Ctl,
        _ => return None,
    };
    Some(Envelope {
        chronicle: ChronicleId::from_bytes(arr(&b[0..16])),
        branch: BranchId::new(be_u64(&b[16..24])),
        epoch: Epoch::new(be_u64(&b[24..32])),
        stream,
        lsn: Lsn::new(be_u64(&b[33..41])),
        prev: HashVal::from_bytes(arr(&b[41..73])),
        payload_hash: HashVal::from_bytes(arr(&b[73..105])),
        hash: HashVal::from_bytes(arr(&b[105..137])),
    })
}

/// Decode an envelope already accepted by `scan` or `append`.
fn decode_envelope(b: &[u8]) -> Envelope {
    try_decode_envelope(b).expect("indexed frame has a valid stream byte")
}

fn read_header(file: &File) -> Result<(ChronicleId, Position), SegmentError> {
    let mut h = [0u8; HEADER_LEN as usize];
    file.read_exact_at(&mut h, 0).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => SegmentError::BadHeader("file shorter than the header"),
        _ => SegmentError::Io(e),
    })?;
    if h[0..8] != MAGIC {
        return Err(SegmentError::BadHeader("wrong magic"));
    }
    if h[8] != VERSION {
        return Err(SegmentError::BadHeader("unknown version"));
    }
    let chronicle = ChronicleId::from_bytes(arr(&h[9..25]));
    let base = Position {
        lsn: Lsn::new(be_u64(&h[25..33])),
        hash: HashVal::from_bytes(arr(&h[33..65])),
    };
    Ok((chronicle, base))
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    File::open(dir)?.sync_all()
}

fn arr<const N: usize>(b: &[u8]) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(b);
    a
}

fn be_u64(b: &[u8]) -> u64 {
    u64::from_be_bytes(arr(b))
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use taso_core::canon::Canonical;
    use taso_core::record::{Payload, Record};

    fn chron(n: u8) -> ChronicleId {
        ChronicleId::from_bytes([n; 16])
    }

    /// `n` chained records from `base`, payload sizes from `sizes`.
    fn chain(c: ChronicleId, base: Position, sizes: &[usize]) -> Vec<(Envelope, Vec<u8>)> {
        let mut prev = base;
        sizes
            .iter()
            .enumerate()
            .map(|(i, &size)| {
                let payload = Payload::Raw(vec![i as u8; size]);
                let rec = Record::new(
                    c,
                    BranchId::TRUNK,
                    Epoch::FIRST,
                    Stream::Fs,
                    prev.lsn.next(),
                    prev.hash,
                    payload,
                );
                prev = Position {
                    lsn: rec.envelope.lsn,
                    hash: rec.envelope.hash,
                };
                (rec.envelope, rec.payload.canon_bytes())
            })
            .collect()
    }

    fn head(p: Position) -> ChronicleHead {
        ChronicleHead {
            lsn: p.lsn,
            hash: p.hash,
            epoch: Epoch::FIRST,
        }
    }

    fn fresh(base: Position) -> (tempfile::TempDir, PathBuf, Segment) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg-0");
        let seg = Segment::create(&path, chron(1), base).unwrap();
        (dir, path, seg)
    }

    fn file_len(p: &Path) -> u64 {
        std::fs::metadata(p).unwrap().len()
    }

    // ── append and read back ────────────────────────────────────────

    /// A batch is written whole, after every frame passes; one bad frame
    /// writes nothing.
    #[test]
    fn batches_are_checked_whole() {
        let (_d, path, mut seg) = fresh(Position::GENESIS);
        let recs = chain(chron(1), Position::GENESIS, &[1, 2, 3, 4]);
        let all: Vec<(&Envelope, &[u8])> = recs.iter().map(|(e, p)| (e, p.as_slice())).collect();
        let len = file_len(&path);
        // The third does not follow the second.
        let bad = [all[0], all[1], all[3]];
        assert!(seg.append_batch(&bad).is_err());
        assert_eq!((seg.tail(), file_len(&path)), (Position::GENESIS, len));
        assert_eq!(seg.append_batch(&[]).unwrap(), Position::GENESIS);
        seg.append_batch(&all[..3]).unwrap();
        seg.append_batch(&all[3..]).unwrap();
        assert_eq!(seg.tail().lsn, Lsn::new(4));
        drop(seg);
        let (seg, _) = Segment::open(
            &path,
            head(Position {
                lsn: Lsn::new(4),
                hash: recs[3].0.hash,
            }),
        )
        .unwrap();
        let frames = seg.frames().unwrap();
        assert_eq!(
            frames
                .iter()
                .map(|f| (&f.envelope, f.payload.as_slice()))
                .collect::<Vec<_>>(),
            all
        );
    }

    /// Reads by lsn match the full read, from a segment based past
    /// genesis too, and touch nothing they do not hold.
    #[test]
    fn reads_by_lsn() {
        for base in [
            Position::GENESIS,
            Position {
                lsn: Lsn::new(7),
                hash: HashVal::from_bytes([7; 32]),
            },
        ] {
            let (_d, _p, mut seg) = fresh(base);
            for (e, p) in &chain(chron(1), base, &[0, 1, 100, 4096, 3]) {
                seg.append(e, p).unwrap();
            }
            let all = seg.frames().unwrap();
            let b = base.lsn.get();
            for k in 0..=5u64 {
                assert_eq!(
                    seg.frames_after(Lsn::new(b + k)).unwrap(),
                    all[k as usize..],
                    "after {k}"
                );
            }
            assert_eq!(seg.frames_after(Lsn::new(b + 9)).unwrap(), vec![]);
            assert_eq!(
                seg.frames_after(Lsn::new(0)).unwrap(),
                all,
                "before the base: everything"
            );
            for (i, f) in all.iter().enumerate() {
                let lsn = Lsn::new(b + 1 + i as u64);
                assert_eq!(seg.frame(lsn).unwrap().as_ref(), Some(f));
                assert_eq!(seg.hash_at(lsn), Some(f.envelope.hash));
            }
            assert_eq!(seg.frame(base.lsn).unwrap(), None, "the base is no frame");
            assert_eq!(seg.hash_at(base.lsn), Some(base.hash));
            assert_eq!(seg.frame(Lsn::new(b + 6)).unwrap(), None);
            assert_eq!(seg.hash_at(Lsn::new(b + 6)), None);
        }
    }

    #[test]
    fn round_trip_and_reopen() {
        let (_d, path, mut seg) = fresh(Position::GENESIS);
        let recs = chain(chron(1), Position::GENESIS, &[0, 1, 100, 4096]);
        for (e, p) in &recs {
            seg.append(e, p).unwrap();
        }
        let tail = seg.tail();
        assert_eq!(tail.lsn, Lsn::new(4));
        let frames = seg.frames().unwrap();
        assert_eq!(frames.len(), 4);
        for (f, (e, p)) in frames.iter().zip(&recs) {
            assert_eq!((&f.envelope, &f.payload), (e, p));
        }
        drop(seg);

        let (seg, rec) = Segment::open(&path, head(tail)).unwrap();
        assert_eq!(rec, Recovery::default());
        assert_eq!(seg.tail(), tail);
        assert_eq!(seg.frames().unwrap(), frames);
    }

    #[test]
    fn non_genesis_base() {
        let base = Position {
            lsn: Lsn::new(41),
            hash: HashVal::from_bytes([9; 32]),
        };
        let (_d, path, mut seg) = fresh(base);
        assert_eq!(seg.tail(), base);
        let recs = chain(chron(1), base, &[8, 8]);
        for (e, p) in &recs {
            seg.append(e, p).unwrap();
        }
        assert_eq!(seg.tail().lsn, Lsn::new(43));
        drop(seg);
        // Anchored exactly at the base: both frames are unaccepted.
        let (seg, rec) = Segment::open(&path, head(base)).unwrap();
        assert_eq!(rec.unaccepted_frames, 2);
        assert_eq!(seg.tail(), base);
        assert!(seg.is_empty());
    }

    /// A closed segment is read whole and never cut: a torn tail is an
    /// error, not something to repair, and it refuses appends.
    #[test]
    fn closed_segments_are_complete_and_read_only() {
        let (_d, path, mut seg) = fresh(Position::GENESIS);
        let recs = chain(chron(1), Position::GENESIS, &[3, 3, 3]);
        for (e, p) in &recs {
            seg.append(e, p).unwrap();
        }
        let tail = seg.tail();
        drop(seg);
        let len = file_len(&path);
        let mut closed = Segment::open_closed(&path).unwrap();
        assert_eq!((closed.tail(), closed.frames().unwrap().len()), (tail, 3));
        let more = chain(chron(1), tail, &[1]);
        assert!(matches!(
            closed.append(&more[0].0, &more[0].1),
            Err(SegmentError::Poisoned)
        ));
        assert_eq!(file_len(&path), len, "nothing written");
        // A torn tail: refused, and left exactly as it is.
        let f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all_at(&[1, 2, 3], len).unwrap();
        drop(f);
        assert!(matches!(
            Segment::open_closed(&path),
            Err(SegmentError::ClosedTorn { invalid_bytes: 3 })
        ));
        assert_eq!(file_len(&path), len + 3);
    }

    #[test]
    fn create_refuses_existing_file() {
        let (_d, path, _seg) = fresh(Position::GENESIS);
        assert!(matches!(
            Segment::create(&path, chron(1), Position::GENESIS),
            Err(SegmentError::Io(_))
        ));
    }

    // ── local chain refusals ────────────────────────────────────────

    #[test]
    fn append_refusals_leave_the_file_unchanged() {
        let (_d, path, mut seg) = fresh(Position::GENESIS);
        let recs = chain(chron(1), Position::GENESIS, &[4, 4, 4]);
        seg.append(&recs[0].0, &recs[0].1).unwrap();
        let len = file_len(&path);

        // Skips lsn 2.
        assert!(matches!(
            seg.append(&recs[2].0, &recs[2].1),
            Err(SegmentError::NotNext { .. })
        ));
        // Repeats lsn 1.
        assert!(matches!(
            seg.append(&recs[0].0, &recs[0].1),
            Err(SegmentError::NotNext { .. })
        ));
        // Right lsn, wrong prev (a fork from genesis).
        let fork = chain(chron(1), Position::GENESIS, &[5, 5]);
        let mut bad = fork[1].0;
        bad.prev = HashVal::from_bytes([3; 32]);
        assert!(matches!(
            seg.append(&bad, &fork[1].1),
            Err(SegmentError::PrevMismatch { .. })
        ));
        // Tampered hash.
        let mut bad = recs[1].0;
        bad.hash = HashVal::from_bytes([1; 32]);
        assert!(matches!(
            seg.append(&bad, &recs[1].1),
            Err(SegmentError::BadHash { .. })
        ));
        // Wrong payload.
        assert!(matches!(
            seg.append(&recs[1].0, b"not it"),
            Err(SegmentError::PayloadHashMismatch { .. })
        ));
        // Another Chronicle.
        let other = chain(chron(2), Position::GENESIS, &[4, 4]);
        let mut bad = other[1].0;
        bad.prev = recs[0].0.hash;
        assert!(matches!(
            seg.append(&bad, &other[1].1),
            Err(SegmentError::ChronicleMismatch { .. })
        ));

        assert_eq!(file_len(&path), len);
        assert_eq!(seg.tail().lsn, Lsn::new(1));
        seg.append(&recs[1].0, &recs[1].1).unwrap();
    }

    // ── refused CAS ─────────────────────────────────────────────────

    #[test]
    fn truncate_after_refused_cas() {
        let (_d, path, mut seg) = fresh(Position::GENESIS);
        let recs = chain(chron(1), Position::GENESIS, &[10, 10, 10]);
        seg.append(&recs[0].0, &recs[0].1).unwrap();
        let accepted = seg.tail();
        let len = file_len(&path);
        // Written and fsynced locally, then the coordinator says no.
        seg.append(&recs[1].0, &recs[1].1).unwrap();
        seg.truncate_to(accepted.lsn).unwrap();
        assert_eq!(seg.tail(), accepted);
        assert_eq!(file_len(&path), len);
        assert!(matches!(
            seg.truncate_to(Lsn::new(5)),
            Err(SegmentError::OutOfRange { .. })
        ));
        // The same lsn can be appended again.
        seg.append(&recs[1].0, &recs[1].1).unwrap();
        assert_eq!(seg.tail().lsn, Lsn::new(2));
    }

    // ── recovery ────────────────────────────────────────────────────

    #[test]
    fn open_truncates_unaccepted_and_torn_tail() {
        let (_d, path, mut seg) = fresh(Position::GENESIS);
        let recs = chain(chron(1), Position::GENESIS, &[16, 16, 16, 16]);
        let mut tails = Vec::new();
        for (e, p) in &recs {
            seg.append(e, p).unwrap();
            tails.push((seg.tail(), file_len(&path)));
        }
        drop(seg);
        // A torn half-frame after the last one.
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.write_all_at(&[0xAB; 70], tails[3].1).unwrap();
        drop(f);

        let (seg, rec) = Segment::open(&path, head(tails[1].0)).unwrap();
        assert_eq!(
            rec,
            Recovery {
                unaccepted_frames: 2,
                invalid_bytes: 70
            }
        );
        assert_eq!(seg.tail(), tails[1].0);
        assert_eq!(file_len(&path), tails[1].1);
    }

    #[test]
    fn diverged_is_refused_and_nothing_is_cut() {
        let (_d, path, mut seg) = fresh(Position::GENESIS);
        for (e, p) in &chain(chron(1), Position::GENESIS, &[4, 4]) {
            seg.append(e, p).unwrap();
        }
        drop(seg);
        let len = file_len(&path);
        let other = chain(chron(1), Position::GENESIS, &[9]);
        let wrong = Position {
            lsn: Lsn::new(1),
            hash: other[0].0.hash,
        };
        assert!(matches!(
            Segment::open(&path, head(wrong)),
            Err(SegmentError::Diverged { .. })
        ));
        assert_eq!(file_len(&path), len);
    }

    #[test]
    fn missing_accepted_is_refused_and_nothing_is_cut() {
        let (_d, path, mut seg) = fresh(Position::GENESIS);
        let recs = chain(chron(1), Position::GENESIS, &[4, 4, 4]);
        seg.append(&recs[0].0, &recs[0].1).unwrap();
        drop(seg);
        let len = file_len(&path);
        let ahead = Position {
            lsn: Lsn::new(3),
            hash: recs[2].0.hash,
        };
        assert!(matches!(
            Segment::open(&path, head(ahead)),
            Err(SegmentError::MissingAccepted { .. })
        ));
        assert_eq!(file_len(&path), len);
    }

    #[test]
    fn anchor_before_base() {
        let base = Position {
            lsn: Lsn::new(10),
            hash: HashVal::from_bytes([2; 32]),
        };
        let (_d, path, seg) = fresh(base);
        drop(seg);
        assert!(matches!(
            Segment::open(&path, head(Position::GENESIS)),
            Err(SegmentError::AnchorBeforeBase { .. })
        ));
    }

    #[test]
    fn bad_headers() {
        let dir = tempfile::tempdir().unwrap();
        let short = dir.path().join("short");
        std::fs::write(&short, b"TASOSEG").unwrap();
        assert!(matches!(
            Segment::open(&short, head(Position::GENESIS)),
            Err(SegmentError::BadHeader(_))
        ));
        let magic = dir.path().join("magic");
        std::fs::write(&magic, [0u8; HEADER_LEN as usize]).unwrap();
        assert!(matches!(
            Segment::open(&magic, head(Position::GENESIS)),
            Err(SegmentError::BadHeader("wrong magic"))
        ));
    }

    #[test]
    fn oversized_length_field_ends_the_prefix() {
        let (_d, path, mut seg) = fresh(Position::GENESIS);
        let recs = chain(chron(1), Position::GENESIS, &[4]);
        seg.append(&recs[0].0, &recs[0].1).unwrap();
        let tail = seg.tail();
        let len = file_len(&path);
        drop(seg);
        let mut junk = vec![0u8; FRAME_PREFIX + 8];
        junk[0..4].copy_from_slice(&u32::MAX.to_be_bytes());
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.write_all_at(&junk, len).unwrap();
        drop(f);
        let (seg, rec) = Segment::open(&path, head(tail)).unwrap();
        assert_eq!(rec.invalid_bytes, junk.len() as u64);
        assert_eq!(seg.tail(), tail);
    }

    // ── crash at any byte ───────────────────────────────────────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Write N frames, crash at any byte at or after the anchored
        /// frame's end, reopen against the anchor: recovery lands exactly
        /// on the anchor with every earlier frame intact.
        #[test]
        fn crash_anywhere_after_anchor_recovers_to_anchor(
            sizes in proptest::collection::vec(0usize..300, 1..16),
            anchor_pick in any::<prop::sample::Index>(),
            cut_pick in any::<prop::sample::Index>(),
            garbage in proptest::collection::vec(any::<u8>(), 0..200),
        ) {
            let (_d, path, mut seg) = fresh(Position::GENESIS);
            let recs = chain(chron(1), Position::GENESIS, &sizes);
            let mut points = vec![(Position::GENESIS, HEADER_LEN)];
            for (e, p) in &recs {
                seg.append(e, p).unwrap();
                points.push((seg.tail(), file_len(&path)));
            }
            drop(seg);
            let full = file_len(&path);
            let k = anchor_pick.index(points.len());
            let (anchor, anchor_end) = points[k];
            let cut = anchor_end + cut_pick.index((full - anchor_end + 1) as usize) as u64;

            let f = OpenOptions::new().write(true).open(&path).unwrap();
            f.set_len(cut).unwrap();
            f.write_all_at(&garbage, cut).unwrap();
            drop(f);

            let (seg, _rec) = Segment::open(&path, head(anchor)).unwrap();
            prop_assert_eq!(seg.tail(), anchor);
            prop_assert_eq!(file_len(&path), anchor_end);
            let frames = seg.frames().unwrap();
            prop_assert_eq!(frames.len(), k);
            for (f, (e, p)) in frames.iter().zip(&recs) {
                prop_assert_eq!(&f.envelope, e);
                prop_assert_eq!(&f.payload, p);
            }
        }

        /// Crash before the anchored frame is fully on disk: refused as
        /// MissingAccepted, and the file is left as it was.
        #[test]
        fn crash_before_anchor_is_missing_accepted(
            sizes in proptest::collection::vec(0usize..300, 1..16),
            anchor_pick in any::<prop::sample::Index>(),
            cut_pick in any::<prop::sample::Index>(),
        ) {
            let (_d, path, mut seg) = fresh(Position::GENESIS);
            let recs = chain(chron(1), Position::GENESIS, &sizes);
            let mut points = vec![(Position::GENESIS, HEADER_LEN)];
            for (e, p) in &recs {
                seg.append(e, p).unwrap();
                points.push((seg.tail(), file_len(&path)));
            }
            drop(seg);
            // Anchor at frame 1..=N; cut strictly inside [header, anchor_end).
            let k = 1 + anchor_pick.index(points.len() - 1);
            let (anchor, anchor_end) = points[k];
            let cut = HEADER_LEN + cut_pick.index((anchor_end - HEADER_LEN) as usize) as u64;
            let f = OpenOptions::new().write(true).open(&path).unwrap();
            f.set_len(cut).unwrap();
            drop(f);

            let refused = matches!(
                Segment::open(&path, head(anchor)),
                Err(SegmentError::MissingAccepted { .. })
            );
            prop_assert!(refused, "expected MissingAccepted");
            prop_assert_eq!(file_len(&path), cut);
        }
    }
}
