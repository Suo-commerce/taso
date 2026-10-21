//! Packs: a Chronicle shipped off the node in few, self-verifying objects
//! (v1.0 §1 P2, §3).
//!
//! # Why packs
//!
//! An fsynced object put is expensive and puts are applied one after
//! another (about 85 puts/s on the test server, fewer on a consumer SSD),
//! while object size barely matters.  So a shipment is one object holding
//! everything accepted and not yet shipped, and for a Seal also its `fs`
//! stream: one put per Seal.
//!
//! # Layout
//!
//! ```text
//! header      magic "TASOPAK\0" (8) · version (1) · chronicle (16)
//!             · base lsn (8) · base hash (32) · end lsn (8) · end hash (32)
//!             · has fs (1) · fs base kind (1: 0 full, 1 seal, 2 origin)
//!             · origin chronicle (16) · fs base lsn (8) · fs base hash (32)
//!             · origin guid (8) · to lsn (8) · to hash (32) · to guid (8)
//!                                                                = 219 bytes
//! log         frames base+1 ..= end, each [payload len u32 · envelope 137 · payload]
//!             exactly as in a segment
//! log digest  BLAKE3 (derive-key "taso.pack.log.v1") over header + log (32)
//! fs          if has fs: chunks [len u32 · bytes], a 0 length ends them
//! trailer     length of everything before it (u64) · BLAKE3 (derive-key
//!             "taso.pack.v1") over everything before it (32)
//! ```
//!
//! All integers are big-endian.  The log digest lets [`Packs::chain`]
//! verify every pack's log without reading its `fs` stream, which can be
//! gigabytes; the trailer is checked by [`Packs::open_fs`] at the end of
//! the stream, and `zfs receive` never sees the last byte of a stream that
//! fails it ([`crate::zfs::HoldBack`]).
//!
//! # Keys are derived from content
//!
//! `<prefix>/<chronicle hex>/pack/<end>-<base>-<fs to or 0>` (20 digits
//! each).  A fenced Warden may still be alive and shipping: the
//! coordinator refuses its appends, but the store does not know who holds
//! the Chronicle.  With keys taken from what a pack contains, two writers
//! can only collide on the same accepted frames and the same Seal, which
//! are the same records, so an overwrite is harmless.  Two writers that
//! ship different ranges write different keys, and the reader merges.
//!
//! # What may be shipped
//!
//! - Only **accepted** frames: the caller passes the position to ship up
//!   to, which must be at or below the anchored head.
//! - Each pack starts where the store's packs end ([`Packs::shipped`]),
//!   so a call with nothing new ships nothing, and a crash between put
//!   and return is resolved by reading the store, not local state.
//! - An `fs` section brings the dataset to a Seal whose record is a `Ctl`
//!   frame with that hash, at or before the pack's end.  Its base is
//!   - for the first section, what the Chronicle's `Lineage` record (lsn 1)
//!     says the dataset was born from: nothing for a Vessel born from the
//!     void (a full stream, small because it starts empty), or the
//!     parent's Seal snapshot for a fork or a succession (an incremental
//!     from the parent, usually a Template, so rebirth moves only what the
//!     Vessel changed);
//!   - for every later section, the previous shipped `fs` Seal.
//!
//!   Its identity is `(base, to, guid)`, not its bytes: ZFS does not
//!   promise byte-identical streams, and the snapshot guid survives send
//!   and receive.
//! - A section is **named** by an `FsShipped` record the holder appends
//!   after the put ([`SealShipped::record`]): the identity, and the length
//!   and BLAKE3 of the plain stream, hashed while it was shipped.  Only a
//!   named section is used, by the reader and by the next Seal, which
//!   builds on the newest one the local log names.  A section put but
//!   never named (a crash in between) is shipped again under the same key.
//!
//! # Reading back
//!
//! [`Packs::chain`] verifies every pack's header and log, merges them by
//! lsn (an lsn held by two packs must hold the same record), checks the
//! log is continuous from genesis (through Gap records), that every `fs`
//! section an `FsShipped` record names is in a pack and anchored in the
//! log, that the first one starts from what the
//! lineage says and the rest form one chain, and, given an
//! anchor from an authority the store cannot write (the coordinator),
//! that the chain contains it.  Without an anchor a chain only proves it
//! is self-consistent: anyone who can write the bucket can build one.
//! [`Packs::open_fs`] checks a stream against its `FsShipped` record,
//! which is in the hash chain; the pack trailer only shows the pack is
//! whole.
//! With an anchor it returns nothing past it: packs beyond it are still
//! read, and two that disagree are still a conflict, but a missing lsn
//! beyond the anchor only ends what is read.
//!
//! # Gaps (rebirth)
//!
//! A Warden that takes a Chronicle over keeps only what was shipped and
//! anchored, up to `kept`, and writes a `Gap` record saying records
//! `(kept, resumes]` are lost to it (v1.0 §1 P2).  Its local log jumps
//! there, and so may its packs: a frame **follows** the one before it if
//! it is the next lsn chained to it, or it is a well-formed Gap record
//! that jumps.  Inside one pack (one writer's log) a Gap must keep exactly
//! the frame before it.  Across packs it may keep an earlier one: a
//! Warden SIGKILLed after a put but before the coordinator's shipped
//! anchor moved leaves a pack past `kept`, which the store still holds.
//!
//! Such records are verified and checked for conflicts, but
//! [`Packs::chain`] does not return them, nor any `fs` section whose Seal
//! is among them: the chain is exactly what the local logs hold, so a log
//! rebuilt from it passes the same joint check as on disk.  The `kept`
//! hash binds the Gap to the kept record even when its `prev` points at
//! a lost one, and the Gap is chained forward to the anchor.
//!
//! For the same reason a writer never starts from something only an
//! unanchored pack holds: a pack's log starts where the store's packs end
//! if the local log holds that position, else at the `kept` of the local
//! gap it falls in; a Seal's `fs` stream starts from the last shipped `fs`
//! Seal the local log holds, skipping any the gap swallowed.
//!
//! Version 1 of this format was first written with a 195-byte header whose
//! `fs` base could only be this Chronicle's own Seal; it changed to the
//! 219-byte header above before any pack left a test, so the version did
//! not move.
//!
//! Normative references: v1.0 §1 (P2), §3; v0.4 §8.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read};

use taso_core::envelope::{ChronicleId, HashVal, Lsn, Stream};
use taso_core::record::{
    FsShippedRecord, GapRecord, Origin, ParentSeal, Payload, StreamBase, FS_STREAM_DOMAIN,
};

use std::sync::{Arc, Mutex};

use taso_core::envelope::Epoch;
use taso_core::model::WardenId;

use crate::coordinator::Coord;
use crate::effects::{Publish, PublishError};
use crate::segment::{self, Frame, Position, Segment, SegmentError, MAX_PAYLOAD};
use crate::ship::{valid_key, ByteStream, ObjectStore, Sender};
use crate::zfs::Snapshot;

const MAGIC: [u8; 8] = *b"TASOPAK\0";
const VERSION: u8 = 1;
const LOG_DOMAIN: &str = "taso.pack.log.v1";
const PACK_DOMAIN: &str = "taso.pack.v1";

/// Size of a pack header.
pub const HEADER_LEN: usize = 8 + 1 + 16 + 40 + 40 + 1 + 1 + 16 + 40 + 8 + 40 + 8;

/// Bytes per `fs` chunk when writing.
const FS_CHUNK: usize = 1 << 20;
/// Largest `fs` chunk a reader accepts.
const MAX_FS_CHUNK: u32 = 16 << 20;
/// Digits per number in a pack's name.
const NAME_DIGITS: usize = 20;

// ── Types ───────────────────────────────────────────────────────────

/// What an `fs` stream starts from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsBase {
    /// Nothing: a full stream.  Only the first section of a Vessel born
    /// from the void.
    Full,
    /// This Chronicle's previous shipped `fs` Seal.
    Seal(Position),
    /// The parent's Seal snapshot this Vessel's dataset is a clone of (a
    /// fork or a succession).  Only the first section.
    Origin {
        /// The parent Chronicle.
        chronicle: ChronicleId,
        /// The parent's Seal record.
        seal: Position,
        /// The ZFS guid of the parent's Seal snapshot.
        guid: u64,
    },
}

/// What an `fs` section is: the stream that brings a dataset to a Seal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsRef {
    /// What it is incremental from.
    pub base: FsBase,
    /// The Seal it brings the dataset to.
    pub to: Position,
    /// The ZFS guid of the `to` snapshot (kept by send and receive).
    pub guid: u64,
}

/// A pack's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackHeader {
    /// The Chronicle.
    pub chronicle: ChronicleId,
    /// The position the log section chains from.
    pub base: Position,
    /// The last frame in the log section (`base` if it is empty).
    pub end: Position,
    /// The `fs` section, if any.
    pub fs: Option<FsRef>,
}

/// Where the store's packs end, as [`Packs::shipped`] reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shipped {
    /// The last shipped frame ([`Position::GENESIS`] if none).
    pub log: Position,
    /// The last shipped `fs` section, if any.
    pub fs: Option<FsRef>,
}

/// An `fs` section named by an `FsShipped` record in the chain: what it is,
/// and the length and digest of its plain stream, which
/// [`Packs::open_fs`] checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShippedFs {
    /// The section.
    pub fs: FsRef,
    /// The plain stream's length.
    pub bytes: u64,
    /// BLAKE3 (derive-key [`FS_STREAM_DOMAIN`]) of the plain stream.
    pub digest: HashVal,
}

/// A Seal pack just put, and the `FsShipped` record that names its `fs`
/// section.  The caller appends the record: until it is in the chain, the
/// section is not used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealShipped {
    /// The pack's header.
    pub header: PackHeader,
    /// The record to append.
    pub record: FsShippedRecord,
}

/// The verified, merged contents of every pack of a Chronicle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    /// Frames 1 ..= `end`, in order, chained from genesis and jumping only
    /// at Gap records: exactly what the local logs hold.  Records a Gap
    /// says are lost are not here, even if a pack holds them.
    pub frames: Vec<Frame>,
    /// The last position: the anchor if one was given, else the last
    /// frame's ([`Position::GENESIS`] if none).
    pub end: Position,
    /// The `fs` sections up to `end` that an `FsShipped` record in the
    /// chain names, in Seal order, forming one chain; none whose Seal is
    /// lost.
    pub seals: Vec<ShippedFs>,
}

/// Why packing or reading packs failed.
#[derive(Debug)]
pub enum PackError {
    /// The store, the sender, or a read failed.
    Io(io::Error),
    /// The local segment failed.
    Segment(SegmentError),
    /// A key under the pack directory is not a pack name.
    BadKey(String),
    /// An object is not a valid pack, or does not match its key.
    Corrupt {
        /// The key.
        key: String,
        /// What is wrong.
        why: String,
    },
    /// Two packs hold different records at the same lsn, or different
    /// `fs` identities for the same Seal: another history.
    Conflict {
        /// Where they differ.
        lsn: Lsn,
    },
    /// No pack holds this lsn, though later ones exist.
    Gap {
        /// The first missing lsn.
        missing: Lsn,
    },
    /// An `fs` section names a Seal that is not a shipped `Ctl` record
    /// with that hash.
    FsAheadOfLog {
        /// The Seal it names.
        to: Lsn,
    },
    /// An `fs` section's base is not what it must be: the lineage's
    /// origin for the first, the previous `fs` Seal for the rest.
    BrokenFsChain {
        /// The Seal whose base is wrong.
        at: Lsn,
    },
    /// The log's first record is not a readable `Lineage` record.
    NoLineage,
    /// An `FsShipped` record names a section no pack holds.
    FsMissing {
        /// The Seal it names.
        seal: Lsn,
    },
    /// The chain does not contain the anchor.
    NotAnchored {
        /// The anchor.
        anchor: Position,
    },
    /// A log ship would pass a Seal record whose `fs` is not shipped: the
    /// anchor would then let a rebirth resume after a turn whose files
    /// are not there (fencing review F4).  Ship the Seal first.
    SealNotShipped {
        /// The Seal.
        seal: Lsn,
    },
    /// The request contradicts the local segment or what is shipped.
    Refused(String),
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Segment(e) => write!(f, "segment: {e}"),
            Self::BadKey(k) => write!(f, "{k} is not a pack name"),
            Self::Corrupt { key, why } => write!(f, "pack {key} is corrupt: {why}"),
            Self::Conflict { lsn } => {
                write!(f, "packs disagree at lsn {}: another history", lsn.get())
            }
            Self::Gap { missing } => write!(f, "no pack holds lsn {}", missing.get()),
            Self::FsAheadOfLog { to } => {
                write!(
                    f,
                    "an fs section names Seal {} which is not a shipped Seal record",
                    to.get()
                )
            }
            Self::BrokenFsChain { at } => write!(
                f,
                "the fs section for Seal {} does not start where it must",
                at.get()
            ),
            Self::NoLineage => write!(f, "lsn 1 is not a Lineage record"),
            Self::FsMissing { seal } => {
                write!(
                    f,
                    "an FsShipped record names the fs of Seal {}, which no pack holds",
                    seal.get()
                )
            }
            Self::NotAnchored { anchor } => {
                write!(
                    f,
                    "the shipped chain does not contain lsn {} with hash {}",
                    anchor.lsn.get(),
                    anchor.hash
                )
            }
            Self::SealNotShipped { seal } => {
                write!(
                    f,
                    "the log cannot be shipped past Seal {}: its fs is not shipped yet",
                    seal.get()
                )
            }
            Self::Refused(why) => write!(f, "refused: {why}"),
        }
    }
}

impl std::error::Error for PackError {}

impl From<io::Error> for PackError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<SegmentError> for PackError {
    fn from(e: SegmentError) -> Self {
        Self::Segment(e)
    }
}

// ── Header and names ────────────────────────────────────────────────

fn put_pos(out: &mut Vec<u8>, p: Position) {
    out.extend_from_slice(&p.lsn.get().to_be_bytes());
    out.extend_from_slice(p.hash.as_bytes());
}

fn get_u64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[..8].try_into().expect("8 bytes"))
}

fn get_pos(b: &[u8]) -> Position {
    Position {
        lsn: Lsn::new(get_u64(b)),
        hash: HashVal::from_bytes(b[8..40].try_into().expect("32 bytes")),
    }
}

impl PackHeader {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.extend_from_slice(self.chronicle.as_bytes());
        put_pos(&mut out, self.base);
        put_pos(&mut out, self.end);
        let zero = Position {
            lsn: Lsn::new(0),
            hash: HashVal::from_bytes([0; 32]),
        };
        let (has, kind, chron, base, base_guid, to, to_guid) = match self.fs {
            None => (0, 0, [0u8; 16], zero, 0, zero, 0),
            Some(fs) => match fs.base {
                FsBase::Full => (1, 0, [0u8; 16], zero, 0, fs.to, fs.guid),
                FsBase::Seal(p) => (1, 1, [0u8; 16], p, 0, fs.to, fs.guid),
                FsBase::Origin {
                    chronicle,
                    seal,
                    guid,
                } => (1, 2, *chronicle.as_bytes(), seal, guid, fs.to, fs.guid),
            },
        };
        out.push(has);
        out.push(kind);
        out.extend_from_slice(&chron);
        put_pos(&mut out, base);
        out.extend_from_slice(&u64::to_be_bytes(base_guid));
        put_pos(&mut out, to);
        out.extend_from_slice(&u64::to_be_bytes(to_guid));
        debug_assert_eq!(out.len(), HEADER_LEN);
        out
    }

    fn decode(b: &[u8]) -> Result<Self, &'static str> {
        if b.len() != HEADER_LEN {
            return Err("wrong header length");
        }
        if b[0..8] != MAGIC {
            return Err("wrong magic");
        }
        if b[8] != VERSION {
            return Err("unknown version");
        }
        let chronicle = ChronicleId::from_bytes(b[9..25].try_into().expect("16 bytes"));
        let base = get_pos(&b[25..65]);
        let end = get_pos(&b[65..105]);
        let (has_fs, kind) = (b[105], b[106]);
        let origin_chronicle = &b[107..123];
        let fs_base = get_pos(&b[123..163]);
        let origin_guid = get_u64(&b[163..171]);
        let to = get_pos(&b[171..211]);
        let guid = get_u64(&b[211..219]);
        let zero = |r: std::ops::Range<usize>| b[r].iter().all(|&x| x == 0);
        if base.lsn > end.lsn {
            return Err("base is after end");
        }
        let fs = match (has_fs, kind) {
            (0, 0) => {
                if !zero(107..219) {
                    return Err("fs fields set without an fs section");
                }
                if base.lsn == end.lsn {
                    return Err("an empty log section without an fs section");
                }
                None
            }
            (1, k @ 0..=2) => {
                let fs_base = match k {
                    0 if zero(107..171) => FsBase::Full,
                    1 if zero(107..123) && zero(163..171) => {
                        if fs_base.lsn == Lsn::new(0) || fs_base.lsn >= to.lsn {
                            return Err("fs section does not move forward");
                        }
                        FsBase::Seal(fs_base)
                    }
                    2 => {
                        let c =
                            ChronicleId::from_bytes(origin_chronicle.try_into().expect("16 bytes"));
                        if c == chronicle {
                            return Err("a Chronicle cannot be its own origin");
                        }
                        FsBase::Origin {
                            chronicle: c,
                            seal: fs_base,
                            guid: origin_guid,
                        }
                    }
                    _ => return Err("fs base fields do not match its kind"),
                };
                if to.lsn == Lsn::new(0) {
                    return Err("fs section brings the dataset nowhere");
                }
                if to.lsn > end.lsn {
                    return Err("fs section names a Seal after the pack's end");
                }
                Some(FsRef {
                    base: fs_base,
                    to,
                    guid,
                })
            }
            _ => return Err("bad fs flags"),
        };
        Ok(Self {
            chronicle,
            base,
            end,
            fs,
        })
    }

    /// The object name: `<end>-<base>-<fs to or 0>`.
    fn name(&self) -> String {
        let to = self.fs.map_or(0, |f| f.to.lsn.get());
        format!(
            "{:020}-{:020}-{:020}",
            self.end.lsn.get(),
            self.base.lsn.get(),
            to
        )
    }
}

/// The numbers in a pack's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Name {
    end: Lsn,
    base: Lsn,
    fs_to: Option<Lsn>,
}

fn parse_name(s: &str) -> Option<Name> {
    let parts: Vec<&str> = s.split('-').collect();
    let [e, b, t] = parts[..] else { return None };
    let num = |x: &str| {
        (x.len() == NAME_DIGITS && x.bytes().all(|c| c.is_ascii_digit()))
            .then(|| x.parse::<u64>().ok())
            .flatten()
    };
    let (end, base, to) = (num(e)?, num(b)?, num(t)?);
    Some(Name {
        end: Lsn::new(end),
        base: Lsn::new(base),
        fs_to: (to != 0).then_some(Lsn::new(to)),
    })
}

fn name_of(h: &PackHeader) -> Name {
    Name {
        end: h.end.lsn,
        base: h.base.lsn,
        fs_to: h.fs.map(|f| f.to.lsn),
    }
}

// ── Writing ─────────────────────────────────────────────────────────

/// A pack as a byte stream: header and log (already encoded), then the
/// `fs` stream in chunks, then the trailer.  A read error from the `fs`
/// stream is passed on, so a failed send never becomes an object.
struct PackStream {
    pending: io::Cursor<Vec<u8>>,
    fs: Option<ByteStream>,
    state: StreamState,
    hasher: blake3::Hasher,
    total: u64,
    chunk: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamState {
    Prefix,
    Fs,
    Trailer,
    Done,
}

impl PackStream {
    fn new(prefix: Vec<u8>, fs: Option<ByteStream>) -> Self {
        let mut s = Self {
            pending: io::Cursor::new(Vec::new()),
            fs,
            state: StreamState::Prefix,
            hasher: blake3::Hasher::new_derive_key(PACK_DOMAIN),
            total: 0,
            chunk: vec![0u8; FS_CHUNK],
        };
        s.emit(prefix, true);
        s
    }

    fn emit(&mut self, bytes: Vec<u8>, hashed: bool) {
        if hashed {
            self.hasher.update(&bytes);
            self.total += bytes.len() as u64;
        }
        self.pending = io::Cursor::new(bytes);
    }

    /// Queue the next piece; false when there is nothing more.
    fn advance(&mut self) -> io::Result<bool> {
        match self.state {
            StreamState::Prefix => {
                self.state = if self.fs.is_some() {
                    StreamState::Fs
                } else {
                    StreamState::Trailer
                };
                if self.state == StreamState::Trailer {
                    self.emit_trailer();
                }
            }
            StreamState::Fs => {
                let fs = self.fs.as_mut().expect("fs state has a stream");
                let mut n = 0;
                while n < self.chunk.len() {
                    match fs.read(&mut self.chunk[n..]) {
                        Ok(0) => break,
                        Ok(k) => n += k,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e),
                    }
                }
                let mut out = Vec::with_capacity(4 + n);
                out.extend_from_slice(&(n as u32).to_be_bytes());
                out.extend_from_slice(&self.chunk[..n]);
                self.emit(out, true);
                if n == 0 {
                    self.state = StreamState::Trailer;
                    self.fs = None;
                }
                return Ok(true);
            }
            StreamState::Trailer => {
                self.emit_trailer();
            }
            StreamState::Done => return Ok(false),
        }
        Ok(true)
    }

    fn emit_trailer(&mut self) {
        let mut t = Vec::with_capacity(40);
        t.extend_from_slice(&self.total.to_be_bytes());
        t.extend_from_slice(self.hasher.finalize().as_bytes());
        self.emit(t, false);
        self.state = StreamState::Done;
    }
}

impl Read for PackStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = self.pending.read(buf)?;
            if n > 0 || buf.is_empty() {
                return Ok(n);
            }
            if !self.advance()? {
                return Ok(0);
            }
        }
    }
}

fn encode_frames(frames: &[Frame], out: &mut Vec<u8>) {
    for f in frames {
        out.extend_from_slice(&(f.payload.len() as u32).to_be_bytes());
        segment::encode_envelope(&f.envelope, out);
        out.extend_from_slice(&f.payload);
    }
}

// ── Reading ─────────────────────────────────────────────────────────

/// Reads a pack front to back, hashing everything for the trailer.
struct PackIn {
    r: ByteStream,
    hasher: blake3::Hasher,
    total: u64,
}

impl PackIn {
    fn take(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut b = vec![0u8; n];
        self.r.read_exact(&mut b)?;
        self.hasher.update(&b);
        self.total += n as u64;
        Ok(b)
    }
}

/// The de-chunked `fs` stream of a pack; fails at the end unless the
/// trailer matches, nothing follows it, and the plain stream has exactly
/// the length and digest its `FsShipped` record says.
struct FsOut {
    pin: PackIn,
    chunk: io::Cursor<Vec<u8>>,
    done: bool,
    plain: blake3::Hasher,
    count: u64,
    expect: (u64, HashVal),
}

fn bad(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.to_string())
}

impl Read for FsOut {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = self.chunk.read(buf)?;
            if n > 0 || buf.is_empty() {
                return Ok(n);
            }
            if self.done {
                return Ok(0);
            }
            let len = u32::from_be_bytes(self.pin.take(4)?.try_into().expect("4 bytes"));
            if len > MAX_FS_CHUNK {
                return Err(bad("fs chunk is too large"));
            }
            if len == 0 {
                let (total, digest) = (self.pin.total, *self.pin.hasher.finalize().as_bytes());
                let mut t = [0u8; 40];
                self.pin
                    .r
                    .read_exact(&mut t)
                    .map_err(|_| bad("pack ends before its trailer"))?;
                if get_u64(&t) != total || t[8..] != digest {
                    return Err(bad("pack does not match its trailer"));
                }
                let mut extra = [0u8; 1];
                if self.pin.r.read(&mut extra)? != 0 {
                    return Err(bad("bytes after the pack's trailer"));
                }
                let digest = HashVal::from_bytes(*self.plain.finalize().as_bytes());
                if (self.count, digest) != self.expect {
                    return Err(bad("the fs stream does not match its FsShipped record"));
                }
                self.done = true;
                return Ok(0);
            }
            let chunk = self.pin.take(len as usize)?;
            self.plain.update(&chunk);
            self.count += chunk.len() as u64;
            self.chunk = io::Cursor::new(chunk);
        }
    }
}

// ── FsShipped ───────────────────────────────────────────────────────

/// Counts and hashes the plain `fs` stream as the pack takes it.  The
/// result is read only after a successful put, which means the stream was
/// read to its end.
struct Digesting {
    inner: ByteStream,
    state: Arc<Mutex<(u64, blake3::Hasher)>>,
}

impl Read for Digesting {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        let mut st = self.state.lock().expect("not poisoned");
        st.0 += n as u64;
        st.1.update(&buf[..n]);
        Ok(n)
    }
}

/// The record's form of an `fs` base.
fn stream_base(b: FsBase) -> StreamBase {
    match b {
        FsBase::Full => StreamBase::Full,
        FsBase::Seal(p) => StreamBase::Seal {
            lsn: p.lsn,
            hash: p.hash,
        },
        FsBase::Origin {
            chronicle,
            seal,
            guid,
        } => StreamBase::Origin {
            parent: ParentSeal {
                chronicle,
                seal: seal.lsn,
                seal_hash: seal.hash,
            },
            guid,
        },
    }
}

/// Whether `r` names the section `fs`: the same Seal, base and guid.
fn names(r: &FsShippedRecord, fs: &FsRef) -> bool {
    r.seal == fs.to.lsn
        && r.seal_hash == fs.to.hash
        && r.guid == fs.guid
        && r.base == stream_base(fs.base)
}

/// Whether a frame is a Seal record.
fn is_seal(f: &Frame) -> bool {
    f.envelope.stream == Stream::Ctl && matches!(Payload::decode(&f.payload), Ok(Payload::Seal(_)))
}

/// The `FsShipped` record a frame holds, if it is one.
fn fs_shipped_of(f: &Frame) -> Option<FsShippedRecord> {
    if f.envelope.stream != Stream::Ctl {
        return None;
    }
    match Payload::decode(&f.payload) {
        Ok(Payload::FsShipped(r)) => Some(r),
        _ => None,
    }
}

// ── Gaps and the link rule ──────────────────────────────────────────

/// The Gap record a frame holds, if it is one.
fn gap_of(f: &Frame) -> Option<GapRecord> {
    if f.envelope.stream != Stream::Ctl {
        return None;
    }
    match Payload::decode(&f.payload) {
        Ok(Payload::Gap(g)) => Some(g),
        _ => None,
    }
}

fn kept_of(g: &GapRecord) -> Position {
    Position {
        lsn: g.kept,
        hash: g.kept_hash,
    }
}

fn resumes_of(g: &GapRecord) -> Position {
    Position {
        lsn: g.resumes,
        hash: g.resumes_hash,
    }
}

/// A Gap record is well-formed where it stands: it resumes right after
/// the record it chains to, and keeps something before that.
fn gap_well_formed(f: &Frame, g: &GapRecord) -> bool {
    g.resumes.next() == f.envelope.lsn && g.resumes_hash == f.envelope.prev && g.kept < g.resumes
}

/// How `f` follows `tail` in one writer's log: as the next record, or as a
/// Gap record keeping exactly `tail`.  Returns the position `f` chains
/// from (its `prev`), which [`segment::check_frame`] then verifies.
fn link_strict(tail: Position, f: &Frame) -> Result<Position, &'static str> {
    let gap = gap_of(f);
    if gap.as_ref().is_some_and(|g| !gap_well_formed(f, g)) {
        return Err("a malformed Gap record");
    }
    let lsn = f.envelope.lsn;
    if lsn <= tail.lsn {
        return Err("records out of order");
    }
    if lsn == tail.lsn.next() {
        return Ok(tail);
    }
    match gap {
        Some(g) if kept_of(&g) == tail => Ok(resumes_of(&g)),
        Some(_) => Err("a Gap record that does not keep the record before it"),
        None => Err("records are skipped without a Gap record"),
    }
}

/// Where an lsn is in the local log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Spot {
    /// Lsn 0.
    Genesis,
    /// A frame in segment `i`.
    Frame(usize),
    /// The base of segment `i`, held by no local frame: its hash is the
    /// segment's base hash.  For `i > 0` it is the last record lost in a
    /// gap.
    Base(usize),
    /// Strictly inside a gap: lost; the gap keeps this.
    Lost { kept: Position },
    /// Before the oldest local segment (rolled away).
    Before,
    /// After the local log.
    Beyond,
}

/// Locate `lsn` among `segments` (oldest first) from their bases and tails
/// only; reads no file.
fn locate(segments: &[&Segment], lsn: Lsn) -> Spot {
    if lsn == Lsn::new(0) {
        return Spot::Genesis;
    }
    for (i, s) in segments.iter().enumerate() {
        if s.base().lsn < lsn && lsn <= s.tail().lsn {
            return Spot::Frame(i);
        }
        if lsn == s.base().lsn {
            return Spot::Base(i);
        }
        if lsn < s.base().lsn {
            return match i {
                0 => Spot::Before,
                _ => Spot::Lost {
                    kept: segments[i - 1].tail(),
                },
            };
        }
    }
    Spot::Beyond
}

/// The local frame at `lsn`, if segment `i` holds it (one read).
fn local_frame(segments: &[&Segment], i: usize, lsn: Lsn) -> Result<Option<Frame>, PackError> {
    Ok(segments[i].frame(lsn)?)
}

// ── Packs ───────────────────────────────────────────────────────────

/// One Chronicle's packs in a store.
pub struct Packs<S: ObjectStore, X: Sender> {
    store: S,
    sender: X,
    chronicle: ChronicleId,
    dir: String,
    cache: Mutex<Cache>,
}

/// What this `Packs` learned from its own puts, so the hot path does not
/// list the store.  Only ever behind the store: another writer may have
/// shipped more, and a pack built from a stale end only overlaps packs
/// already there, which [`Packs::chain`] merges.  A fresh `Packs` reads
/// the store once.
#[derive(Default)]
struct Cache {
    /// Where the store's log ends, as far as this `Packs` knows.
    log_end: Option<Position>,
    /// The last `fs` section this `Packs` put, and the record that names it.
    named: Option<(FsShippedRecord, FsRef)>,
    /// Seal packs this `Packs` put, by Seal lsn (a retry reuses the header).
    seals_put: BTreeMap<Lsn, PackHeader>,
    /// The local tail when this `Packs` listed the store for Seal packs.
    /// A pack left unnamed by an earlier process can only be for a Seal
    /// already in the log then; Seals after it need no listing.
    seals_listed_to: Option<Lsn>,
}

impl<S: ObjectStore, X: Sender> Packs<S, X> {
    /// The packs of Chronicle `id` under `prefix` in `store`; `sender`
    /// produces `fs` streams.
    pub fn new(store: S, sender: X, prefix: &str, id: ChronicleId) -> io::Result<Self> {
        let hex: String = id.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let dir = format!("{prefix}/{hex}/pack");
        if !valid_key(&dir) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid object key {dir:?}"),
            ));
        }
        Ok(Self {
            store,
            sender,
            chronicle: id,
            dir,
            cache: Mutex::default(),
        })
    }

    fn key(&self, h: &PackHeader) -> String {
        format!("{}/{}", self.dir, h.name())
    }

    /// Every pack, by name, in name order.
    fn names(&self) -> Result<Vec<(String, Name)>, PackError> {
        let mut out = Vec::new();
        let skip = self.dir.len() + 1;
        for key in self.store.list(&self.dir)? {
            let name = key
                .get(skip..)
                .and_then(parse_name)
                .ok_or_else(|| PackError::BadKey(key.clone()))?;
            out.push((key, name));
        }
        out.sort_by_key(|(_, n)| *n);
        Ok(out)
    }

    fn open(&self, key: &str) -> Result<ByteStream, PackError> {
        self.store.get(key)?.ok_or_else(|| PackError::Corrupt {
            key: key.into(),
            why: "listed but missing".into(),
        })
    }

    /// Read and check a header: it decodes, is this Chronicle's, and is
    /// the one its key names.
    fn header_from(&self, key: &str, name: Name, bytes: &[u8]) -> Result<PackHeader, PackError> {
        let corrupt = |why: &str| PackError::Corrupt {
            key: key.into(),
            why: why.into(),
        };
        let h = PackHeader::decode(bytes).map_err(corrupt)?;
        if h.chronicle != self.chronicle {
            return Err(corrupt("belongs to another Chronicle"));
        }
        if name_of(&h) != name {
            return Err(corrupt("header does not match the key"));
        }
        Ok(h)
    }

    /// The header of one pack; reads nothing past it.
    fn read_header(&self, key: &str, name: Name) -> Result<PackHeader, PackError> {
        let mut r = self.open(key)?;
        let mut b = vec![0u8; HEADER_LEN];
        r.read_exact(&mut b).map_err(|_| PackError::Corrupt {
            key: key.into(),
            why: "shorter than a header".into(),
        })?;
        self.header_from(key, name, &b)
    }

    /// Header and verified log of one pack, and the reader positioned at
    /// its `fs` section.
    fn read_log(
        &self,
        key: &str,
        name: Name,
    ) -> Result<(PackHeader, Vec<Frame>, PackIn), PackError> {
        let corrupt = |why: String| PackError::Corrupt {
            key: key.into(),
            why,
        };
        let mut pin = PackIn {
            r: self.open(key)?,
            hasher: blake3::Hasher::new_derive_key(PACK_DOMAIN),
            total: 0,
        };
        let mut log = blake3::Hasher::new_derive_key(LOG_DOMAIN);
        let short = |e: io::Error| corrupt(format!("truncated: {e}"));
        let hb = pin.take(HEADER_LEN).map_err(short)?;
        log.update(&hb);
        let h = self.header_from(key, name, &hb)?;
        let mut frames = Vec::new();
        let mut tail = h.base;
        while tail.lsn < h.end.lsn {
            let pre = pin.take(4 + segment::ENVELOPE_LEN).map_err(short)?;
            log.update(&pre);
            let len = u32::from_be_bytes(pre[..4].try_into().expect("4 bytes"));
            if len > MAX_PAYLOAD {
                return Err(corrupt(format!("payload of {len} bytes")));
            }
            let env = segment::try_decode_envelope(&pre[4..])
                .ok_or_else(|| corrupt("bad envelope".into()))?;
            let payload = pin.take(len as usize).map_err(short)?;
            log.update(&payload);
            let frame = Frame {
                envelope: env,
                payload,
            };
            let from = link_strict(tail, &frame).map_err(|why| corrupt(why.into()))?;
            segment::check_frame(self.chronicle, from, &frame.envelope, &frame.payload)
                .map_err(|e| corrupt(e.to_string()))?;
            tail = Position {
                lsn: frame.envelope.lsn,
                hash: frame.envelope.hash,
            };
            frames.push(frame);
        }
        if tail != h.end {
            return Err(corrupt("the log does not end at the header's end".into()));
        }
        let digest = pin.take(32).map_err(short)?;
        if digest[..] != log.finalize().as_bytes()[..] {
            return Err(corrupt("the log does not match its digest".into()));
        }
        Ok((h, frames, pin))
    }

    /// Where the store's packs end.  Reads at most two headers (the pack
    /// with the highest end, and the one with the highest `fs` Seal) and
    /// no pack body.  It trusts the store; [`Packs::chain`] verifies it.
    pub fn shipped(&self) -> Result<Shipped, PackError> {
        let names = self.names()?;
        let log = match names.iter().max_by_key(|(_, n)| n.end) {
            None => Position::GENESIS,
            Some((k, n)) => self.read_header(k, *n)?.end,
        };
        let fs = match names
            .iter()
            .filter(|(_, n)| n.fs_to.is_some())
            .max_by_key(|(_, n)| n.fs_to)
        {
            None => None,
            Some((k, n)) => self.read_header(k, *n)?.fs,
        };
        Ok(Shipped { log, fs })
    }

    /// Frames `after+1 ..= upto` from the local segments (oldest first),
    /// following `after` by the link rule and ending exactly at `upto`.
    /// Reads only the segments holding frames past `after`.
    fn frames_after(
        &self,
        segments: &[&Segment],
        after: Position,
        upto: Position,
    ) -> Result<Vec<Frame>, PackError> {
        if segments.iter().any(|s| s.chronicle() != self.chronicle) {
            return Err(PackError::Refused(
                "a segment belongs to another Chronicle".into(),
            ));
        }
        let refused = || {
            PackError::Refused(format!(
                "the local segments do not hold lsn {}..={} chained from what is shipped",
                after.lsn.get() + 1,
                upto.lsn.get()
            ))
        };
        let mut frames = Vec::new();
        for s in segments
            .iter()
            .filter(|s| s.tail().lsn > after.lsn && s.base().lsn < upto.lsn)
        {
            frames.extend(
                s.frames_after(after.lsn)?
                    .into_iter()
                    .filter(|f| f.envelope.lsn <= upto.lsn),
            );
        }
        let mut tail = after;
        for f in &frames {
            let from = link_strict(tail, f).map_err(|_| refused())?;
            if f.envelope.prev != from.hash {
                return Err(refused());
            }
            tail = Position {
                lsn: f.envelope.lsn,
                hash: f.envelope.hash,
            };
        }
        if frames.is_empty() || tail != upto {
            return Err(refused());
        }
        Ok(frames)
    }

    /// Where the next pack's log starts, given where the store's packs
    /// end: there, if the local log holds that position; the `kept` of the
    /// local gap it falls in, if it is lost to this node (an unanchored
    /// pack of a Warden that lost the Chronicle).
    fn log_base(&self, segments: &[&Segment], end: Position) -> Result<Position, PackError> {
        let conflict = PackError::Conflict { lsn: end.lsn };
        match locate(segments, end.lsn) {
            Spot::Genesis => (end.hash == HashVal::GENESIS)
                .then_some(end)
                .ok_or(conflict),
            Spot::Frame(i) => (segments[i].hash_at(end.lsn) == Some(end.hash))
                .then_some(end)
                .ok_or(conflict),
            Spot::Base(i) => (segments[i].base() == end).then_some(end).ok_or(conflict),
            Spot::Lost { kept } => Ok(kept),
            Spot::Before => Err(PackError::Refused(format!(
                "the store ends at lsn {}, before the local segments",
                end.lsn.get()
            ))),
            Spot::Beyond => Err(PackError::Refused(format!(
                "the store ends at lsn {}, past the local log",
                end.lsn.get()
            ))),
        }
    }

    /// The newest `FsShipped` record in the local log, if any.  Reads
    /// frame by frame back from the tail and stops at the first: it sits
    /// after the last published Seal, a turn or two back.
    fn newest_named(segments: &[&Segment]) -> Result<Option<FsShippedRecord>, PackError> {
        Self::named_upto(segments, Lsn::new(u64::MAX))
    }

    /// The newest `FsShipped` record at or below `upto` in the local log,
    /// if any (as [`Packs::newest_named`], from `upto` down).
    fn named_upto(segments: &[&Segment], upto: Lsn) -> Result<Option<FsShippedRecord>, PackError> {
        for seg in segments.iter().rev() {
            let mut lsn = seg.tail().lsn.min(upto);
            while lsn > seg.base().lsn {
                if let Some(f) = seg.frame(lsn)? {
                    if let Some(r) = fs_shipped_of(&f) {
                        return Ok(Some(r));
                    }
                    // A Checkpoint stands for every record before it
                    // (which may be pruned): its FsShipped is the newest.
                    if f.envelope.stream == Stream::Ctl {
                        if let Ok(Payload::Checkpoint(c)) = Payload::decode(&f.payload) {
                            return Ok(c.fs_shipped);
                        }
                    }
                }
                lsn = Lsn::new(lsn.get() - 1);
            }
        }
        Ok(None)
    }

    /// The packs holding an `fs` section for the Seal at `to`, with their
    /// headers.  Reads one header per candidate.
    fn fs_packs(&self, to: Lsn) -> Result<Vec<(String, Name, PackHeader)>, PackError> {
        let mut out = Vec::new();
        for (key, name) in self
            .names()?
            .into_iter()
            .filter(|(_, n)| n.fs_to == Some(to))
        {
            let h = self.read_header(&key, name)?;
            out.push((key, name, h));
        }
        Ok(out)
    }

    /// The `fs` section the next one builds on: the one the newest local
    /// `FsShipped` record names, which a pack must hold.  A section no
    /// local record names is never built on: a crash after its put and
    /// before its record, or a Seal a gap swallowed (it was never
    /// anchored, and this node has no snapshot of it).
    fn fs_base(&self, segments: &[&Segment]) -> Result<Option<FsRef>, PackError> {
        let Some(r) = Self::newest_named(segments)? else {
            return Ok(None);
        };
        if let Some((cr, fs)) = &self.cache().named {
            if *cr == r {
                return Ok(Some(*fs));
            }
        }
        self.fs_packs(r.seal)?
            .into_iter()
            .filter_map(|(_, _, h)| h.fs)
            .find(|fs| names(&r, fs))
            .map(Some)
            .ok_or(PackError::FsMissing { seal: r.seal })
    }

    /// The header of a Seal pack already in the store for the Seal at
    /// `seal` but not named (a crash after its put): this `Packs`' own, or
    /// one an earlier process left, found by listing the store once.
    fn unnamed_seal_pack(
        &self,
        segments: &[&Segment],
        seal: Lsn,
    ) -> Result<Option<PackHeader>, PackError> {
        if let Some(h) = self.cache().seals_put.get(&seal) {
            return Ok(Some(*h));
        }
        let listed = self.cache().seals_listed_to;
        if listed.is_some_and(|to| seal > to) {
            return Ok(None);
        }
        let tail = segments.last().map_or(Lsn::new(0), |s| s.tail().lsn);
        let found = self.fs_packs(seal)?.first().map(|(_, _, h)| *h);
        let mut c = self.cache();
        c.seals_listed_to = Some(c.seals_listed_to.map_or(tail, |t| t.max(tail)));
        Ok(found)
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Where the store's log ends: from this `Packs`' own puts, or read
    /// from the store once ([`Packs::shipped`]).
    fn log_end(&self) -> Result<Position, PackError> {
        if let Some(end) = self.cache().log_end {
            return Ok(end);
        }
        let end = self.shipped()?.log;
        self.cache().log_end = Some(end);
        Ok(end)
    }

    /// Write one pack; returns its header.
    fn put_pack(
        &self,
        h: PackHeader,
        frames: &[Frame],
        fs: Option<ByteStream>,
    ) -> Result<PackHeader, PackError> {
        let mut prefix = h.encode();
        encode_frames(frames, &mut prefix);
        let digest = blake3::Hasher::new_derive_key(LOG_DOMAIN)
            .update(&prefix)
            .finalize();
        prefix.extend_from_slice(digest.as_bytes());
        let mut stream = PackStream::new(prefix, fs);
        self.store.put(&self.key(&h), &mut stream)?;
        let mut c = self.cache();
        if c.log_end.is_some_and(|e| e.lsn < h.end.lsn) {
            c.log_end = Some(h.end);
        }
        Ok(h)
    }

    /// Ship every accepted frame not yet shipped, up to `upto` (which
    /// must be accepted: at or below the anchored head), as one pack.
    /// `segments` are the Chronicle's local segments, oldest first.
    /// `None` if there is nothing new.
    ///
    /// Refused ([`PackError::SealNotShipped`]) if the frames to ship hold
    /// a Seal record that no `FsShipped` record at or below `upto` covers
    /// — a named Seal covers every Seal before it, since `fs` sections
    /// chain.  Otherwise the anchor could pass a Seal whose files were
    /// never shipped, and a rebirth would resume after a turn whose files
    /// are not there (fencing review F4).  [`Packs::ship_seal`] ships the
    /// Seal's log and `fs` together and is not subject to this.
    pub fn ship_log(
        &self,
        segments: &[&Segment],
        upto: Position,
    ) -> Result<Option<PackHeader>, PackError> {
        let t = crate::timing::span("pack.shipped");
        let end = self.log_end()?;
        drop(t);
        if upto.lsn <= end.lsn {
            if upto.lsn == end.lsn && upto.hash != end.hash {
                return Err(PackError::Conflict { lsn: upto.lsn });
            }
            return Ok(None);
        }
        let t = crate::timing::span("pack.local");
        let base = self.log_base(segments, end)?;
        let frames = self.frames_after(segments, base, upto)?;
        if let Some(seal) = frames
            .iter()
            .filter(|f| is_seal(f))
            .map(|f| f.envelope.lsn)
            .max()
        {
            let covered = Self::named_upto(segments, upto.lsn)?.map_or(Lsn::new(0), |r| r.seal);
            if covered < seal {
                return Err(PackError::SealNotShipped { seal });
            }
        }
        drop(t);
        let _t = crate::timing::span("pack.put");
        self.put_pack(
            PackHeader {
                chronicle: self.chronicle,
                base,
                end: upto,
                fs: None,
            },
            &frames,
            None,
        )
        .map(Some)
    }

    /// Ship the Seal of `snapshot` (an accepted Seal's layer): the log up
    /// to its record if not shipped yet, and its `fs` stream, in one put.
    /// Returns the header and the `FsShipped` record the caller must
    /// append to name the section; `None` if a local `FsShipped` record
    /// already names this Seal's section.
    ///
    /// The stream is incremental from the section the newest local
    /// `FsShipped` record names.  For the first one,
    /// the `Lineage` record decides: born from the void, a full stream
    /// (`origin` must be `None`); a fork or a succession, an incremental
    /// from the parent's Seal snapshot, which the caller passes as `origin`
    /// and which must be bound to exactly the lineage's parent Seal.
    /// `origin` is refused for any later Seal.
    ///
    /// If the store already holds an unnamed section for this Seal (a
    /// crash after the put, before the record), it is shipped again under
    /// the same key, so a Seal never has two packs.
    pub fn ship_seal(
        &self,
        segments: &[&Segment],
        snapshot: &Snapshot,
        origin: Option<&Snapshot>,
    ) -> Result<Option<SealShipped>, PackError> {
        let hash = snapshot
            .seal_hash
            .ok_or_else(|| PackError::Refused("the snapshot is not bound to a Seal".into()))?;
        let seal = Position {
            lsn: snapshot.seal,
            hash,
        };
        let t = crate::timing::span("pack.fs_base");
        let named = self.fs_base(segments)?;
        drop(t);
        if let Some(f) = named {
            if f.to == seal && f.guid == snapshot.guid {
                return Ok(None);
            }
            if f.to.lsn >= seal.lsn {
                return Err(PackError::Refused(format!(
                    "the fs of Seal {} is shipped; Seal {} cannot follow it",
                    f.to.lsn.get(),
                    seal.lsn.get()
                )));
            }
        }
        // The Seal must be a Ctl record with this hash in the local log.
        let is_seal = match locate(segments, seal.lsn) {
            Spot::Frame(i) => local_frame(segments, i, seal.lsn)?
                .is_some_and(|f| f.envelope.hash == seal.hash && f.envelope.stream == Stream::Ctl),
            _ => false,
        };
        if !is_seal {
            return Err(PackError::Refused(format!(
                "lsn {} is not a Seal record with this hash in the local segments",
                seal.lsn.get()
            )));
        }
        let (base, from_snapshot) = match named {
            Some(f) => {
                if origin.is_some() {
                    return Err(PackError::Refused(
                        "an origin is only for a Vessel's first Seal".into(),
                    ));
                }
                (
                    FsBase::Seal(f.to),
                    Some(snapshot.dataset.seal_snapshot(f.to.lsn)),
                )
            }
            None => {
                let first = match locate(segments, Lsn::new(1)) {
                    Spot::Frame(i) => local_frame(segments, i, Lsn::new(1))?,
                    _ => None,
                };
                let lineage = first
                    .and_then(|f| match Payload::decode(&f.payload) {
                        Ok(Payload::Lineage(l)) => Some(l),
                        _ => None,
                    })
                    .ok_or(PackError::NoLineage)?;
                match (lineage.origin.parent(), origin) {
                    (None, None) => (FsBase::Full, None),
                    (None, Some(_)) => {
                        return Err(PackError::Refused(
                            "born from the void: there is no origin to send from".into(),
                        ))
                    }
                    (Some(_), None) => {
                        return Err(PackError::Refused(
                            "a child Vessel's first Seal needs its origin snapshot".into(),
                        ))
                    }
                    (Some(parent), Some(o)) => {
                        if o.seal != parent.seal || o.seal_hash != Some(parent.seal_hash) {
                            return Err(PackError::Refused(format!(
                                "{} is not the lineage's parent Seal (lsn {})",
                                o.name(),
                                parent.seal.get()
                            )));
                        }
                        let base = FsBase::Origin {
                            chronicle: parent.chronicle,
                            seal: Position {
                                lsn: parent.seal,
                                hash: parent.seal_hash,
                            },
                            guid: o.guid,
                        };
                        (base, Some(o.name()))
                    }
                }
            }
        };
        let fs = FsRef {
            base,
            to: seal,
            guid: snapshot.guid,
        };
        // The log section: the same as an unnamed pack for this Seal (so
        // the put replaces it), else from where the store's packs end.
        let unnamed = self.unnamed_seal_pack(segments, seal.lsn)?;
        let (log_base, end) = match unnamed {
            Some(h) => (h.base, h.end),
            None => {
                let b = self.log_base(segments, self.log_end()?)?;
                (b, if seal.lsn > b.lsn { seal } else { b })
            }
        };
        let frames = if end.lsn > log_base.lsn {
            self.frames_after(segments, log_base, end)?
        } else {
            Vec::new()
        };
        let state = Arc::new(Mutex::new((
            0u64,
            blake3::Hasher::new_derive_key(FS_STREAM_DOMAIN),
        )));
        let stream = self
            .sender
            .send(&snapshot.dataset, from_snapshot.as_deref(), seal.lsn)?;
        let stream: ByteStream = Box::new(Digesting {
            inner: stream,
            state: state.clone(),
        });
        let t = crate::timing::span("pack.put_seal");
        let header = self.put_pack(
            PackHeader {
                chronicle: self.chronicle,
                base: log_base,
                end,
                fs: Some(fs),
            },
            &frames,
            Some(stream),
        )?;
        drop(t);
        self.cache().seals_put.insert(seal.lsn, header);
        let (bytes, digest) = {
            let st = state.lock().expect("not poisoned");
            (st.0, HashVal::from_bytes(*st.1.finalize().as_bytes()))
        };
        let record = FsShippedRecord {
            seal: seal.lsn,
            seal_hash: seal.hash,
            base: stream_base(base),
            guid: snapshot.guid,
            bytes,
            digest,
        };
        self.cache().named = Some((record.clone(), fs));
        Ok(Some(SealShipped { header, record }))
    }

    /// Verify and merge every pack (see the module docs).  With `anchor`,
    /// the chain must also contain that position, and ends there.
    pub fn chain(&self, anchor: Option<Position>) -> Result<Chain, PackError> {
        let mut by_lsn: BTreeMap<Lsn, Frame> = BTreeMap::new();
        let mut fs_by_to: BTreeMap<Lsn, FsRef> = BTreeMap::new();
        let mut bases = Vec::new();
        for (key, name) in self.names()? {
            let (h, frames, _) = self.read_log(&key, name)?;
            for f in frames {
                match by_lsn.get(&f.envelope.lsn) {
                    Some(g) if g.envelope.hash != f.envelope.hash => {
                        return Err(PackError::Conflict {
                            lsn: f.envelope.lsn,
                        })
                    }
                    Some(_) => {}
                    None => {
                        by_lsn.insert(f.envelope.lsn, f);
                    }
                }
            }
            if let Some(fs) = h.fs {
                match fs_by_to.get(&fs.to.lsn) {
                    Some(g) if *g != fs => return Err(PackError::Conflict { lsn: fs.to.lsn }),
                    _ => {
                        fs_by_to.insert(fs.to.lsn, fs);
                    }
                }
            }
            bases.push(h.base);
        }
        // Walk from genesis: each frame follows the one before, as the next
        // record chained to it or as a Gap record that keeps a record the
        // chain holds (an earlier one than the tail if an unanchored pack
        // of the previous holder is in the store).  Records a Gap says are
        // lost are verified here but not returned.
        let mut tail = Position::GENESIS;
        let mut lost: Vec<(Lsn, Lsn)> = Vec::new(); // (kept, resumes]
        let mut resumed: Vec<Position> = Vec::new(); // known by a Gap's hash
        let is_lost =
            |lost: &[(Lsn, Lsn)], lsn: Lsn| lost.iter().any(|&(k, r)| k < lsn && lsn <= r);
        let seen = |p: Position| -> bool {
            if p.lsn == Lsn::new(0) {
                p.hash == HashVal::GENESIS
            } else {
                by_lsn
                    .get(&p.lsn)
                    .is_some_and(|f| f.envelope.hash == p.hash)
            }
        };
        for (lsn, f) in &by_lsn {
            let gap = gap_of(f);
            // Every Gap here is well-formed: `read_log` checked it.  It must
            // keep a record the chain holds and returns (so one before the
            // tail: the walk is in lsn order).
            if let Some(g) = &gap {
                let kept = kept_of(g);
                if is_lost(&lost, kept.lsn) || !seen(kept) {
                    return Err(PackError::Conflict { lsn: *lsn });
                }
            }
            if *lsn == tail.lsn.next() {
                if f.envelope.prev != tail.hash {
                    return Err(PackError::Conflict { lsn: *lsn });
                }
            } else if gap.is_none() {
                if anchor.is_some_and(|a| tail.lsn >= a.lsn) {
                    break; // nothing past the anchor is used
                }
                return Err(PackError::Gap {
                    missing: tail.lsn.next(),
                });
            }
            if let Some(g) = &gap {
                lost.push((g.kept, g.resumes));
                resumed.push(resumes_of(g));
            }
            tail = Position {
                lsn: *lsn,
                hash: f.envelope.hash,
            };
        }
        // A position the chain returns: walked, held, and not lost.
        let returned = |p: Position| p.lsn <= tail.lsn && !is_lost(&lost, p.lsn) && seen(p);
        let end = match anchor {
            Some(a) if !returned(a) => return Err(PackError::NotAnchored { anchor: a }),
            Some(a) => a,
            None => tail,
        };
        // Every pack's base is a position of this chain (lost ones too:
        // the previous holder's packs start there).  Past the anchor only
        // the walk's conflicts count.
        let based = |b: Position| (b.lsn <= tail.lsn && seen(b)) || resumed.contains(&b);
        if let Some(b) = bases
            .iter()
            .find(|b| !(based(**b) || (anchor.is_some() && b.lsn > tail.lsn)))
        {
            return Err(PackError::Conflict { lsn: b.lsn });
        }
        // The FsShipped records the chain returns, one per Seal, each after
        // the Seal it names.  Only a section one of them names is used:
        // the record is in the hash chain, the pack is not.
        let mut named: BTreeMap<Lsn, FsShippedRecord> = BTreeMap::new();
        for (lsn, f) in by_lsn.range(..=end.lsn) {
            if is_lost(&lost, *lsn) {
                continue;
            }
            if let Some(r) = fs_shipped_of(f) {
                // A record follows the Seal it names: it cannot hold a later
                // record's hash, so the Seal check below covers that.
                match named.get(&r.seal) {
                    Some(o) if *o != r => return Err(PackError::Conflict { lsn: *lsn }),
                    Some(_) => {}
                    None => {
                        named.insert(r.seal, r);
                    }
                }
            }
        }
        // Every named section is in a pack and anchored in the log; the
        // first starts from what the lineage says, every later one from the
        // one before.
        let mut seals = Vec::new();
        let mut prev: Option<Position> = None;
        for r in named.values() {
            let fs = fs_by_to
                .get(&r.seal)
                .filter(|fs| names(r, fs))
                .ok_or(PackError::FsMissing { seal: r.seal })?;
            let is_seal = !is_lost(&lost, fs.to.lsn)
                && by_lsn.get(&fs.to.lsn).is_some_and(|f| {
                    f.envelope.hash == fs.to.hash && f.envelope.stream == Stream::Ctl
                });
            if !is_seal {
                return Err(PackError::FsAheadOfLog { to: fs.to.lsn });
            }
            let ok = match (prev, fs.base) {
                (Some(p), FsBase::Seal(b)) => b == p,
                (Some(_), _) => false,
                (None, base) => {
                    let lineage = by_lsn
                        .get(&Lsn::new(1))
                        .and_then(|f| match Payload::decode(&f.payload) {
                            Ok(Payload::Lineage(l)) => Some(l),
                            _ => None,
                        })
                        .ok_or(PackError::NoLineage)?;
                    match (lineage.origin, base) {
                        (Origin::Void, FsBase::Full) => true,
                        (
                            Origin::Fork { parent } | Origin::Succession { parent, .. },
                            FsBase::Origin {
                                chronicle, seal, ..
                            },
                        ) => {
                            chronicle == parent.chronicle
                                && seal
                                    == Position {
                                        lsn: parent.seal,
                                        hash: parent.seal_hash,
                                    }
                        }
                        _ => false,
                    }
                }
            };
            if !ok {
                return Err(PackError::BrokenFsChain { at: fs.to.lsn });
            }
            prev = Some(fs.to);
            seals.push(ShippedFs {
                fs: *fs,
                bytes: r.bytes,
                digest: r.digest,
            });
        }
        let frames = by_lsn
            .into_values()
            .filter(|f| f.envelope.lsn <= end.lsn && !is_lost(&lost, f.envelope.lsn))
            .collect();
        Ok(Chain { frames, end, seals })
    }

    /// The `fs` stream of a named section (from [`Packs::chain`]), read
    /// from its pack and verified as it is read: the reader fails at the
    /// end unless the pack matches its trailer and the plain stream has
    /// the record's length and digest.  `None` if no pack has it.
    pub fn open_fs(&self, shipped: &ShippedFs) -> Result<Option<ByteStream>, PackError> {
        let Some((key, name, _)) = self
            .fs_packs(shipped.fs.to.lsn)?
            .into_iter()
            .find(|(_, _, h)| h.fs == Some(shipped.fs))
        else {
            return Ok(None);
        };
        let (_, _, pin) = self.read_log(&key, name)?;
        Ok(Some(Box::new(FsOut {
            pin,
            chunk: io::Cursor::new(Vec::new()),
            done: false,
            plain: blake3::Hasher::new_derive_key(FS_STREAM_DOMAIN),
            count: 0,
            expect: (shipped.bytes, shipped.digest),
        })))
    }
}

// ── Publishing before dispatch ──────────────────────────────────────

/// The real [`Publish`]: ship a log pack with everything accepted and not
/// yet shipped, then advance the coordinator's shipped anchor to it.  The
/// effect engine sends nothing until both are done.
pub struct PackPublisher<S: ObjectStore, X: Sender> {
    packs: Packs<S, X>,
    coord: Arc<dyn Coord>,
    warden: WardenId,
}

impl<S: ObjectStore, X: Sender> PackPublisher<S, X> {
    /// Publish through `packs` and `coord`, as `warden`.
    pub fn new(packs: Packs<S, X>, coord: Arc<dyn Coord>, warden: WardenId) -> Self {
        Self {
            packs,
            coord,
            warden,
        }
    }
}

impl<S: ObjectStore, X: Sender> Publish for PackPublisher<S, X> {
    fn publish(
        &mut self,
        chronicle: ChronicleId,
        epoch: Epoch,
        segments: &[&Segment],
        upto: Position,
    ) -> Result<(), PublishError> {
        if chronicle != self.packs.chronicle {
            return Err(PublishError("the packs belong to another Chronicle".into()));
        }
        self.packs
            .ship_log(segments, upto)
            .map_err(|e| PublishError(format!("pack: {e}")))?;
        let _t = crate::timing::span("pack.advance");
        self.coord
            .advance_shipped(self.warden, chronicle, epoch, upto)
            .map_err(|e| PublishError(format!("coordinator: {e}")))?;
        Ok(())
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ship::LocalStore;
    use crate::zfs::Dataset;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use taso_core::canon::Canonical;
    use taso_core::envelope::{BranchId, Epoch};
    use taso_core::record::{
        LayerRef, LineageRecord, Namespace, ParentSeal, Record, SealRecord, StreamCut, TurnId,
        Verdict,
    };

    const ID: ChronicleId = ChronicleId::from_bytes([0xC1; 16]);

    // ── fixtures ────────────────────────────────────────────────────

    /// Local segments with records 1..=n; the lsns in `seals` are Seal
    /// records.  `seg` is the first; `more` follow it, and the last is
    /// written.
    struct Log {
        _dir: tempfile::TempDir,
        seg: Segment,
        more: Vec<Segment>,
        pos: Vec<Position>, // pos[i] = position of lsn i (pos[0] = genesis)
        last_seal: Option<HashVal>,
    }

    impl Log {
        /// No lineage record: lsn 1 is whatever is pushed first.
        fn bare() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let seg = Segment::create(dir.path().join("seg"), ID, Position::GENESIS).unwrap();
            Self {
                _dir: dir,
                seg,
                more: Vec::new(),
                pos: vec![Position::GENESIS],
                last_seal: None,
            }
        }
        /// Every segment, oldest first.
        fn segs(&self) -> Vec<&Segment> {
            std::iter::once(&self.seg).chain(self.more.iter()).collect()
        }
        /// Every local frame, oldest first.
        fn frames(&self) -> Vec<Frame> {
            self.segs()
                .iter()
                .flat_map(|s| s.frames().unwrap())
                .collect()
        }
        fn lsns(frames: &[Frame]) -> Vec<u64> {
            frames.iter().map(|f| f.envelope.lsn.get()).collect()
        }
        /// Continue in a new segment from the tail (no gap).
        fn split(&mut self) {
            let tail = *self.pos.last().unwrap();
            let path = self
                ._dir
                .path()
                .join(format!("seg-{}", self.more.len() + 1));
            self.more.push(Segment::create(path, ID, tail).unwrap());
        }
        /// Node B after taking `old` over with only `kept` shipped and
        /// anchored: its first segment holds `old`'s records 1..=kept, a
        /// second starts at `old`'s head and opens with `gap` (as
        /// `Chronicle::open_after_gap` writes it).
        fn takeover_with(old: &Log, kept: u64, gap: GapRecord) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let mut seg = Segment::create(dir.path().join("seg"), ID, Position::GENESIS).unwrap();
            for f in old
                .seg
                .frames()
                .unwrap()
                .iter()
                .filter(|f| f.envelope.lsn.get() <= kept)
            {
                seg.append(&f.envelope, &f.payload).unwrap();
            }
            let head = *old.pos.last().unwrap();
            let cont = Segment::create(dir.path().join("seg-1"), ID, head).unwrap();
            let mut l = Self {
                _dir: dir,
                seg,
                more: vec![cont],
                pos: old.pos.clone(),
                last_seal: None,
            };
            l.push_payload(Stream::Ctl, Payload::Gap(gap));
            l
        }
        fn takeover(old: &Log, kept: u64) -> Self {
            let head = *old.pos.last().unwrap();
            let gap = GapRecord {
                kept: Lsn::new(kept),
                kept_hash: old.at(kept).hash,
                resumes: head.lsn,
                resumes_hash: head.hash,
            };
            Self::takeover_with(old, kept, gap)
        }
        fn with_origin(origin: Origin) -> Self {
            let mut l = Self::bare();
            let lineage = Payload::Lineage(LineageRecord {
                origin,
                namespace: Namespace::from_bytes([1; 16]),
                ledger_pos: Lsn::new(0),
            });
            l.push_payload(Stream::Ctl, lineage);
            l
        }
        /// Born from the void.
        fn new() -> Self {
            Self::with_origin(Origin::Void)
        }
        /// Forked from `parent`.
        fn fork(parent: ParentSeal) -> Self {
            Self::with_origin(Origin::Fork { parent })
        }
        fn push_payload(&mut self, stream: Stream, payload: Payload) -> Position {
            let tail = *self.pos.last().unwrap();
            let lsn = tail.lsn.next();
            let rec = Record::new(
                ID,
                BranchId::TRUNK,
                Epoch::FIRST,
                stream,
                lsn,
                tail.hash,
                payload,
            );
            let seg = self.more.last_mut().unwrap_or(&mut self.seg);
            seg.append(&rec.envelope, &rec.payload.canon_bytes())
                .unwrap();
            let p = Position {
                lsn,
                hash: rec.envelope.hash,
            };
            self.pos.push(p);
            p
        }
        fn push(&mut self, seal: bool, tag: u8) -> Position {
            let lsn = self.pos.last().unwrap().lsn.next();
            let (stream, payload) = if seal {
                let p = Payload::Seal(SealRecord {
                    parent: self.last_seal,
                    cut: StreamCut {
                        fs: Lsn::new(0),
                        db: Lsn::new(0),
                        transcript: Lsn::new(0),
                    },
                    layer: LayerRef::new(lsn.get()),
                    verdict: Verdict::Clean,
                    ledger_pos: Lsn::new(0),
                    turn: TurnId::new(lsn.get()),
                });
                (Stream::Ctl, p)
            } else {
                (Stream::Fs, Payload::Raw(vec![tag; 3 + tag as usize % 5]))
            };
            let p = self.push_payload(stream, payload);
            if seal {
                self.last_seal = Some(p.hash);
            }
            p
        }
        fn fill(&mut self, upto: u64, seals: &[u64]) {
            while (self.pos.len() as u64) <= upto {
                let lsn = self.pos.len() as u64;
                self.push(seals.contains(&lsn), lsn as u8);
            }
        }
        fn at(&self, lsn: u64) -> Position {
            self.pos[lsn as usize]
        }
        fn tail(&self) -> Position {
            *self.pos.last().unwrap()
        }
        /// What the Warden does at a Seal (3c): ship it, append the
        /// FsShipped record that names its section, ship the log.
        fn publish(
            &mut self,
            e: &Env,
            lsn: u64,
            guid: u64,
            origin: Option<&Snapshot>,
        ) -> Option<SealShipped> {
            let s = e
                .packs
                .ship_seal(&self.segs(), &self.snap(lsn, guid), origin)
                .unwrap()?;
            let at = self.push_payload(Stream::Ctl, Payload::FsShipped(s.record.clone()));
            e.packs.ship_log(&self.segs(), at).unwrap();
            Some(s)
        }
        /// Append an FsShipped record naming `fs`, whose plain stream is
        /// `bytes`.
        fn name(&mut self, fs: FsRef, bytes: &[u8]) -> Position {
            self.push_payload(Stream::Ctl, Payload::FsShipped(record_for(fs, bytes)))
        }
        fn snap(&self, lsn: u64, guid: u64) -> Snapshot {
            Snapshot {
                dataset: Dataset::new("tank/v").unwrap(),
                seal: Lsn::new(lsn),
                createtxg: 1,
                guid,
                seal_hash: Some(self.at(lsn).hash),
            }
        }
    }

    fn record_for(fs: FsRef, bytes: &[u8]) -> FsShippedRecord {
        FsShippedRecord {
            seal: fs.to.lsn,
            seal_hash: fs.to.hash,
            base: stream_base(fs.base),
            guid: fs.guid,
            bytes: bytes.len() as u64,
            digest: HashVal::from_bytes(blake3::derive_key(FS_STREAM_DOMAIN, bytes)),
        }
    }

    /// One `send(from, to)`.
    type SendCall = (Option<String>, Lsn);

    /// Streams describe themselves; `variant` changes the bytes (as a
    /// regenerated `zfs send` may) without changing what they are.
    #[derive(Clone, Default)]
    struct FakeSend {
        variant: Rc<Cell<u8>>,
        fail: Rc<Cell<bool>>,
        calls: Rc<RefCell<Vec<SendCall>>>,
    }

    fn body(from: Option<&str>, to: Lsn, variant: u8) -> Vec<u8> {
        let mut v = match from {
            Some(f) => format!("incremental {f}..{} ", to.get()),
            None => format!("full {} ", to.get()),
        }
        .repeat(30_000)
        .into_bytes();
        v.push(variant);
        v
    }

    struct Dies(io::Cursor<Vec<u8>>);
    impl Read for Dies {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.read(buf)? {
                0 => Err(io::Error::other("zfs send died")),
                n => Ok(n),
            }
        }
    }

    impl Sender for FakeSend {
        fn send(&self, _d: &Dataset, from: Option<&str>, to: Lsn) -> io::Result<ByteStream> {
            self.calls.borrow_mut().push((from.map(str::to_string), to));
            let b = body(from, to, self.variant.get());
            Ok(if self.fail.get() {
                Box::new(Dies(io::Cursor::new(b)))
            } else {
                Box::new(io::Cursor::new(b))
            })
        }
    }

    /// Counts what is read from the store.
    struct Counting {
        inner: LocalStore,
        opened: Arc<AtomicU64>,
        bytes: Arc<AtomicU64>,
        lists: Arc<AtomicU64>,
    }

    struct CountRead {
        inner: ByteStream,
        bytes: Arc<AtomicU64>,
    }
    impl Read for CountRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.bytes.fetch_add(n as u64, Ordering::Relaxed);
            Ok(n)
        }
    }

    impl ObjectStore for Counting {
        fn put(&self, key: &str, data: &mut dyn Read) -> io::Result<u64> {
            self.inner.put(key, data)
        }
        fn get(&self, key: &str) -> io::Result<Option<ByteStream>> {
            self.opened.fetch_add(1, Ordering::Relaxed);
            Ok(self.inner.get(key)?.map(|r| {
                Box::new(CountRead {
                    inner: r,
                    bytes: self.bytes.clone(),
                }) as ByteStream
            }))
        }
        fn exists(&self, key: &str) -> io::Result<bool> {
            self.inner.exists(key)
        }
        fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
            self.lists.fetch_add(1, Ordering::Relaxed);
            self.inner.list(prefix)
        }
    }

    struct Env {
        dir: tempfile::TempDir,
        send: FakeSend,
        packs: Packs<Counting, FakeSend>,
        opened: Arc<AtomicU64>,
        bytes: Arc<AtomicU64>,
        lists: Arc<AtomicU64>,
    }

    fn env() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let (opened, bytes, lists) = (
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        let store = Counting {
            inner: LocalStore::new(dir.path()),
            opened: opened.clone(),
            bytes: bytes.clone(),
            lists: lists.clone(),
        };
        let send = FakeSend::default();
        let packs = Packs::new(store, send.clone(), "vessels", ID).unwrap();
        Env {
            dir,
            send,
            packs,
            opened,
            bytes,
            lists,
        }
    }

    impl Env {
        fn keys(&self) -> Vec<String> {
            self.packs.store.list(&self.packs.dir).unwrap()
        }
        fn path(&self, key: &str) -> std::path::PathBuf {
            self.dir.path().join(key)
        }
        /// The named section for Seal `to`, from the chain.
        fn shipped(&self, to: u64) -> ShippedFs {
            *self
                .packs
                .chain(None)
                .unwrap()
                .seals
                .iter()
                .find(|s| s.fs.to.lsn == Lsn::new(to))
                .expect("named")
        }
        fn read_fs(&self, to: u64) -> io::Result<Vec<u8>> {
            let mut r = self.packs.open_fs(&self.shipped(to)).unwrap().unwrap();
            let mut v = Vec::new();
            r.read_to_end(&mut v)?;
            Ok(v)
        }
    }

    // ── format ──────────────────────────────────────────────────────

    #[test]
    fn header_round_trips_and_rejects_junk() {
        let p = |n: u64| Position {
            lsn: Lsn::new(n),
            hash: HashVal::from_bytes([n as u8; 32]),
        };
        let hs = [
            PackHeader {
                chronicle: ID,
                base: p(0),
                end: p(5),
                fs: None,
            },
            PackHeader {
                chronicle: ID,
                base: p(5),
                end: p(9),
                fs: Some(FsRef {
                    base: FsBase::Full,
                    to: p(9),
                    guid: 77,
                }),
            },
            PackHeader {
                chronicle: ID,
                base: p(9),
                end: p(9),
                fs: Some(FsRef {
                    base: FsBase::Seal(p(4)),
                    to: p(7),
                    guid: 1,
                }),
            },
            PackHeader {
                chronicle: ID,
                base: p(0),
                end: p(3),
                fs: Some(FsRef {
                    base: FsBase::Origin {
                        chronicle: ChronicleId::from_bytes([9; 16]),
                        seal: p(40),
                        guid: 5,
                    },
                    to: p(3),
                    guid: 6,
                }),
            },
        ];
        for h in hs {
            let b = h.encode();
            assert_eq!(b.len(), HEADER_LEN);
            assert_eq!(PackHeader::decode(&b), Ok(h));
            assert_eq!(parse_name(&h.name()), Some(name_of(&h)));
        }
        let mut b = hs[0].encode();
        b[0] ^= 1;
        assert!(PackHeader::decode(&b).is_err(), "magic");
        let mut b = hs[0].encode();
        b[8] = 2;
        assert!(PackHeader::decode(&b).is_err(), "version");
        let empty = PackHeader {
            chronicle: ID,
            base: p(5),
            end: p(5),
            fs: None,
        };
        assert!(
            PackHeader::decode(&empty.encode()).is_err(),
            "empty log pack"
        );
        let ahead = PackHeader {
            chronicle: ID,
            base: p(0),
            end: p(5),
            fs: Some(FsRef {
                base: FsBase::Full,
                to: p(6),
                guid: 1,
            }),
        };
        assert!(PackHeader::decode(&ahead.encode()).is_err(), "fs after end");
        let back = PackHeader {
            chronicle: ID,
            base: p(0),
            end: p(9),
            fs: Some(FsRef {
                base: FsBase::Seal(p(7)),
                to: p(7),
                guid: 1,
            }),
        };
        assert!(
            PackHeader::decode(&back.encode()).is_err(),
            "fs not forward"
        );
        let own = FsBase::Origin {
            chronicle: ID,
            seal: p(2),
            guid: 1,
        };
        let selfish = PackHeader {
            chronicle: ID,
            base: p(0),
            end: p(3),
            fs: Some(FsRef {
                base: own,
                to: p(3),
                guid: 1,
            }),
        };
        assert!(PackHeader::decode(&selfish.encode()).is_err(), "own origin");
        let mut b = hs[1].encode();
        b[107] = 1; // an origin chronicle on a full stream
        assert!(
            PackHeader::decode(&b).is_err(),
            "fields that do not match the kind"
        );
        for n in [
            "",
            "1-2-3",
            "00000000000000000001-00000000000000000000",
            "0000000000000000000a-00000000000000000000-00000000000000000000",
        ] {
            assert_eq!(parse_name(n), None, "{n:?}");
        }
    }

    // ── writing ─────────────────────────────────────────────────────

    #[test]
    fn log_pack_round_trips() {
        let e = env();
        let mut log = Log::new();
        log.fill(5, &[]);
        let h = e.packs.ship_log(&log.segs(), log.at(5)).unwrap().unwrap();
        assert_eq!((h.base, h.end, h.fs), (Position::GENESIS, log.at(5), None));
        let c = e.packs.chain(Some(log.at(5))).unwrap();
        assert_eq!(c.frames, log.seg.frames().unwrap());
        assert_eq!(c.end, log.at(5));
        assert!(c.seals.is_empty());
        assert_eq!(
            e.packs.shipped().unwrap(),
            Shipped {
                log: log.at(5),
                fs: None
            }
        );
    }

    #[test]
    fn nothing_new_ships_nothing_and_the_next_pack_starts_where_the_last_ended() {
        let e = env();
        let mut log = Log::new();
        log.fill(5, &[]);
        e.packs.ship_log(&log.segs(), log.at(5)).unwrap();
        assert_eq!(e.packs.ship_log(&log.segs(), log.at(5)).unwrap(), None);
        assert_eq!(
            e.packs.ship_log(&log.segs(), log.at(3)).unwrap(),
            None,
            "older positions are shipped too"
        );
        assert_eq!(e.keys().len(), 1);
        log.fill(8, &[]);
        let h = e.packs.ship_log(&log.segs(), log.at(8)).unwrap().unwrap();
        assert_eq!((h.base, h.end), (log.at(5), log.at(8)));
        assert_eq!(e.keys().len(), 2);
        assert_eq!(e.packs.chain(Some(log.at(8))).unwrap().frames.len(), 8);
    }

    #[test]
    fn seal_packs_carry_the_log_and_the_fs_stream() {
        let e = env();
        let mut log = Log::new();
        log.fill(6, &[6]);
        let h = log.publish(&e, 6, 100, None).unwrap();
        assert_eq!(
            (h.header.base, h.header.end),
            (Position::GENESIS, log.at(6))
        );
        let fs = FsRef {
            base: FsBase::Full,
            to: log.at(6),
            guid: 100,
        };
        assert_eq!(h.header.fs, Some(fs));
        // The record names the section, with the plain stream's length and
        // digest as shipped.
        assert_eq!(h.record, record_for(fs, &body(None, Lsn::new(6), 0)));
        assert_eq!(e.read_fs(6).unwrap(), body(None, Lsn::new(6), 0));
        // Again: nothing.
        assert_eq!(
            e.packs
                .ship_seal(&log.segs(), &log.snap(6, 100), None)
                .unwrap(),
            None
        );
        // A second Seal is incremental from the first.
        log.fill(9, &[6, 9]);
        let h2 = log.publish(&e, 9, 101, None).unwrap();
        assert_eq!(h2.header.fs.unwrap().base, FsBase::Seal(log.at(6)));
        let s6 = "tank/v@taso-seal-00000000000000000006";
        assert_eq!(
            *e.send.calls.borrow(),
            vec![(None, Lsn::new(6)), (Some(s6.to_string()), Lsn::new(9))]
        );
        assert_eq!(e.read_fs(9).unwrap(), body(Some(s6), Lsn::new(9), 0));
        let c = e.packs.chain(Some(log.tail())).unwrap();
        assert_eq!(
            c.seals
                .iter()
                .map(|f| f.fs.to.lsn.get())
                .collect::<Vec<_>>(),
            vec![6, 9]
        );
    }

    /// F4 (fencing review 2026-10-17): a dispatch flush cannot ship the
    /// log past a Seal whose fs is not shipped — before it, the Seal pack
    /// would have had an empty log section and the anchor could pass the
    /// Seal, so a rebirth would resume after a turn whose files are not
    /// there.  The log ships up to the Seal's predecessor, the Seal pack
    /// carries the Seal's record, and after the FsShipped record the log
    /// ships on; a later named Seal covers an earlier unnamed one.
    #[test]
    fn the_log_is_never_shipped_past_an_unshipped_seal() {
        let e = env();
        let mut log = Log::new();
        log.fill(8, &[6]);
        assert!(
            matches!(e.packs.ship_log(&log.segs(), log.at(8)), Err(PackError::SealNotShipped { seal }) if seal == Lsn::new(6))
        );
        assert!(
            matches!(e.packs.ship_log(&log.segs(), log.at(6)), Err(PackError::SealNotShipped { seal }) if seal == Lsn::new(6))
        );
        assert!(e.keys().is_empty(), "a refusal puts nothing");
        e.packs.ship_log(&log.segs(), log.at(5)).unwrap();
        let h = log.publish(&e, 6, 5, None).unwrap();
        assert_eq!(
            (h.header.base, h.header.end),
            (log.at(5), log.at(6)),
            "the Seal pack carries the Seal's record"
        );
        // publish appended the FsShipped record (lsn 9) and shipped to it.
        assert_eq!(e.packs.log_end().unwrap(), log.at(9));
        let c = e.packs.chain(None).unwrap();
        assert_eq!(
            c.seals
                .iter()
                .map(|f| f.fs.to.lsn.get())
                .collect::<Vec<_>>(),
            vec![6]
        );

        // Seal 10 unnamed, Seal 12 named: the log may ship past 10 only
        // once 12's FsShipped record is in it.
        log.fill(13, &[10, 12]);
        assert!(
            matches!(e.packs.ship_log(&log.segs(), log.at(13)), Err(PackError::SealNotShipped { seal }) if seal == Lsn::new(12))
        );
        log.publish(&e, 12, 7, None).unwrap();
        assert_eq!(e.packs.log_end().unwrap(), log.at(14));
        log.fill(16, &[]);
        e.packs.ship_log(&log.segs(), log.at(16)).unwrap();
        assert_eq!(e.packs.log_end().unwrap(), log.at(16));
    }

    #[test]
    fn writer_refuses_what_it_cannot_prove() {
        let e = env();
        let mut log = Log::new();
        log.fill(6, &[4]);
        // Not in the segment, or a different hash.
        assert!(matches!(
            e.packs.ship_log(
                &log.segs(),
                Position {
                    lsn: Lsn::new(9),
                    hash: log.at(6).hash
                }
            ),
            Err(PackError::Refused(_))
        ));
        assert!(matches!(
            e.packs.ship_log(
                &log.segs(),
                Position {
                    lsn: Lsn::new(6),
                    hash: log.at(5).hash
                }
            ),
            Err(PackError::Refused(_))
        ));
        // A snapshot whose Seal is not a Seal record, or unbound.
        assert!(matches!(
            e.packs.ship_seal(&log.segs(), &log.snap(5, 1), None),
            Err(PackError::Refused(_))
        ));
        let mut unbound = log.snap(4, 1);
        unbound.seal_hash = None;
        assert!(matches!(
            e.packs.ship_seal(&log.segs(), &unbound, None),
            Err(PackError::Refused(_))
        ));
        assert!(e.keys().is_empty());
        // An older Seal after a newer one.
        log.fill(7, &[4, 7]);
        log.publish(&e, 7, 2, None).unwrap();
        assert!(matches!(
            e.packs.ship_seal(&log.segs(), &log.snap(4, 1), None),
            Err(PackError::Refused(_))
        ));
    }

    #[test]
    fn a_failed_send_leaves_no_pack() {
        let e = env();
        let mut log = Log::new();
        log.fill(3, &[3]);
        e.send.fail.set(true);
        assert!(matches!(
            e.packs.ship_seal(&log.segs(), &log.snap(3, 1), None),
            Err(PackError::Io(_))
        ));
        assert!(e.keys().is_empty());
        e.send.fail.set(false);
        assert!(e
            .packs
            .ship_seal(&log.segs(), &log.snap(3, 1), None)
            .unwrap()
            .is_some());
    }

    /// `shipped()` runs on every start and after every crash: it reads at
    /// most two headers, never a body.
    #[test]
    fn shipped_reads_headers_only() {
        let e = env();
        let mut log = Log::new();
        log.fill(6, &[6]);
        e.packs
            .ship_seal(&log.segs(), &log.snap(6, 1), None)
            .unwrap();
        log.fill(20, &[6]);
        e.packs.ship_log(&log.segs(), log.at(20)).unwrap();
        e.opened.store(0, Ordering::Relaxed);
        e.bytes.store(0, Ordering::Relaxed);
        let s = e.packs.shipped().unwrap();
        assert_eq!(s.log, log.at(20));
        assert_eq!(s.fs.unwrap().to, log.at(6));
        let (opened, bytes) = (
            e.opened.load(Ordering::Relaxed),
            e.bytes.load(Ordering::Relaxed),
        );
        assert!(opened <= 2, "opened {opened}");
        assert!(bytes <= 2 * HEADER_LEN as u64, "read {bytes} bytes");
    }

    // ── reading ─────────────────────────────────────────────────────

    /// A put whose answer was lost, retried with more frames: the packs
    /// overlap and merge.  The same Seal shipped twice with different
    /// stream bytes but the same identity is fine too.
    #[test]
    fn overlapping_packs_merge() {
        let e = env();
        let mut log = Log::new();
        log.fill(7, &[6]);
        let p = &e.packs;
        p.put_pack(
            PackHeader {
                chronicle: ID,
                base: Position::GENESIS,
                end: log.at(5),
                fs: None,
            },
            &log.seg.frames().unwrap()[..5],
            None,
        )
        .unwrap();
        p.put_pack(
            PackHeader {
                chronicle: ID,
                base: log.at(2),
                end: log.at(7),
                fs: None,
            },
            &log.seg.frames().unwrap()[2..7],
            None,
        )
        .unwrap();
        let fs = FsRef {
            base: FsBase::Full,
            to: log.at(6),
            guid: 9,
        };
        let s1: ByteStream = Box::new(io::Cursor::new(body(None, Lsn::new(6), 1)));
        let s2: ByteStream = Box::new(io::Cursor::new(body(None, Lsn::new(6), 2)));
        p.put_pack(
            PackHeader {
                chronicle: ID,
                base: log.at(7),
                end: log.at(7),
                fs: Some(fs),
            },
            &[],
            Some(s1),
        )
        .unwrap();
        p.put_pack(
            PackHeader {
                chronicle: ID,
                base: log.at(5),
                end: log.at(7),
                fs: Some(fs),
            },
            &log.seg.frames().unwrap()[5..7],
            Some(s2),
        )
        .unwrap();
        // The record names the section; either pack's bytes are the same
        // section, the record holds the digest of one.
        let at = log.name(fs, &body(None, Lsn::new(6), 1));
        p.ship_log(&log.segs(), at).unwrap();
        let c = p.chain(Some(at)).unwrap();
        assert_eq!(c.frames, log.frames());
        let one = record_for(fs, &body(None, Lsn::new(6), 1));
        assert_eq!(
            c.seals,
            vec![ShippedFs {
                fs,
                bytes: one.bytes,
                digest: one.digest
            }]
        );
        // A different guid for the same Seal is another history.
        let s3: ByteStream = Box::new(io::Cursor::new(body(None, Lsn::new(6), 3)));
        p.put_pack(
            PackHeader {
                chronicle: ID,
                base: log.at(6),
                end: log.at(7),
                fs: Some(FsRef { guid: 10, ..fs }),
            },
            &log.seg.frames().unwrap()[6..7],
            Some(s3),
        )
        .unwrap();
        assert!(matches!(p.chain(None), Err(PackError::Conflict { lsn }) if lsn == Lsn::new(6)));
    }

    #[test]
    fn another_history_is_refused() {
        let e = env();
        let mut log = Log::new();
        log.fill(5, &[]);
        e.packs.ship_log(&log.segs(), log.at(5)).unwrap();
        // Same Chronicle, different record at lsn 3 onwards.
        let mut other = Log::new();
        other.fill(2, &[]);
        other.push(false, 99);
        other.fill(6, &[]);
        e.packs
            .put_pack(
                PackHeader {
                    chronicle: ID,
                    base: other.at(2),
                    end: other.at(6),
                    fs: None,
                },
                &other.seg.frames().unwrap()[2..6],
                None,
            )
            .unwrap();
        assert!(
            matches!(e.packs.chain(None), Err(PackError::Conflict { lsn }) if lsn == Lsn::new(3))
        );
    }

    #[test]
    fn a_missing_pack_is_a_gap() {
        let e = env();
        let mut log = Log::new();
        log.fill(5, &[]);
        let first = e.packs.ship_log(&log.segs(), log.at(5)).unwrap().unwrap();
        log.fill(8, &[]);
        e.packs.ship_log(&log.segs(), log.at(8)).unwrap();
        std::fs::remove_file(e.path(&e.packs.key(&first))).unwrap();
        assert!(
            matches!(e.packs.chain(None), Err(PackError::Gap { missing }) if missing == Lsn::new(1))
        );
    }

    /// A named fs section whose Seal the log does not hold as a Ctl record
    /// with that hash.
    #[test]
    fn fs_ahead_of_the_log_is_refused() {
        let e = env();
        let mut log = Log::new();
        log.fill(6, &[]);
        // lsn 6 is a Raw Fs record, not a Seal.
        let fs = FsRef {
            base: FsBase::Full,
            to: log.at(6),
            guid: 1,
        };
        log.name(fs, b"x");
        let frames = log.frames();
        let s: ByteStream = Box::new(io::Cursor::new(b"x".to_vec()));
        e.packs
            .put_pack(
                PackHeader {
                    chronicle: ID,
                    base: Position::GENESIS,
                    end: log.at(7),
                    fs: Some(fs),
                },
                &frames,
                Some(s),
            )
            .unwrap();
        assert!(
            matches!(e.packs.chain(None), Err(PackError::FsAheadOfLog { to }) if to == Lsn::new(6))
        );
    }

    #[test]
    fn fs_sections_must_form_one_chain() {
        let e = env();
        let mut log = Log::new();
        log.fill(9, &[3, 6, 9]);
        let s = || -> ByteStream { Box::new(io::Cursor::new(b"x".to_vec())) };
        let p = &e.packs;
        let f3 = FsRef {
            base: FsBase::Full,
            to: log.at(3),
            guid: 1,
        };
        // Seal 9 claims to follow Seal 6, which was never shipped.
        let f9 = FsRef {
            base: FsBase::Seal(log.at(6)),
            to: log.at(9),
            guid: 3,
        };
        let frames = log.frames();
        p.put_pack(
            PackHeader {
                chronicle: ID,
                base: Position::GENESIS,
                end: log.at(3),
                fs: Some(f3),
            },
            &frames[..3],
            Some(s()),
        )
        .unwrap();
        p.put_pack(
            PackHeader {
                chronicle: ID,
                base: log.at(3),
                end: log.at(9),
                fs: Some(f9),
            },
            &frames[3..9],
            Some(s()),
        )
        .unwrap();
        log.name(f3, b"x");
        let at = log.name(f9, b"x");
        p.ship_log(&log.segs(), at).unwrap();
        assert!(matches!(p.chain(None), Err(PackError::BrokenFsChain { at }) if at == Lsn::new(9)));
    }

    #[test]
    fn anchors_are_checked() {
        let e = env();
        let mut log = Log::new();
        log.fill(5, &[]);
        e.packs.ship_log(&log.segs(), log.at(5)).unwrap();
        assert!(e.packs.chain(Some(log.at(3))).is_ok());
        assert!(e.packs.chain(Some(Position::GENESIS)).is_ok());
        let wrong = Position {
            lsn: Lsn::new(3),
            hash: log.at(4).hash,
        };
        assert!(matches!(
            e.packs.chain(Some(wrong)),
            Err(PackError::NotAnchored { .. })
        ));
        let beyond = Position {
            lsn: Lsn::new(6),
            hash: log.at(5).hash,
        };
        assert!(matches!(
            e.packs.chain(Some(beyond)),
            Err(PackError::NotAnchored { .. })
        ));
    }

    /// A flipped byte in the log fails `chain`; in the fs section it is
    /// found by `open_fs`, at the end; truncation and trailing bytes too.
    #[test]
    fn corruption_is_found() {
        let e = env();
        let mut log = Log::new();
        log.fill(4, &[4]);
        let h = log.publish(&e, 4, 1, None).unwrap().header;
        let path = e.path(&e.packs.key(&h));
        let good = std::fs::read(&path).unwrap();
        let write = |b: &[u8]| std::fs::write(&path, b).unwrap();

        let mut b = good.clone();
        b[HEADER_LEN + 10] ^= 1; // inside the first frame
        write(&b);
        assert!(matches!(
            e.packs.chain(None),
            Err(PackError::Corrupt { .. })
        ));

        let mut b = good.clone();
        let mid = good.len() - 1000; // inside the fs section
        b[mid] ^= 1;
        write(&b);
        assert!(
            e.packs.chain(None).is_ok(),
            "chain does not read fs sections"
        );
        assert_eq!(e.read_fs(4).unwrap_err().kind(), io::ErrorKind::InvalidData);

        write(&good[..good.len() - 1]);
        assert!(e.read_fs(4).is_err());
        let mut b = good.clone();
        b.push(0);
        write(&b);
        assert_eq!(e.read_fs(4).unwrap_err().kind(), io::ErrorKind::InvalidData);

        write(&good);
        assert_eq!(e.read_fs(4).unwrap(), body(None, Lsn::new(4), 0));

        // A whole, well-formed pack of the same section with other bytes:
        // the trailer matches, the FsShipped record does not.
        let other: ByteStream = Box::new(io::Cursor::new(body(None, Lsn::new(4), 9)));
        e.packs
            .put_pack(h, &log.seg.frames().unwrap()[..4], Some(other))
            .unwrap();
        let err = e.read_fs(4).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("FsShipped"), "{err}");
    }

    #[test]
    fn keys_must_be_pack_names_and_match_their_header() {
        let e = env();
        let mut log = Log::new();
        log.fill(5, &[]);
        let h = e.packs.ship_log(&log.segs(), log.at(5)).unwrap().unwrap();
        // The same pack under a name that claims another range.
        let good = std::fs::read(e.path(&e.packs.key(&h))).unwrap();
        let liar = format!("{}/{:020}-{:020}-{:020}", e.packs.dir, 9, 0, 0);
        std::fs::write(e.path(&liar), &good).unwrap();
        assert!(matches!(
            e.packs.chain(None),
            Err(PackError::Corrupt { .. })
        ));
        std::fs::remove_file(e.path(&liar)).unwrap();
        // Something that is not a pack name at all.
        std::fs::write(e.path(&format!("{}/notes.txt", e.packs.dir)), b"hi").unwrap();
        assert!(matches!(e.packs.chain(None), Err(PackError::BadKey(_))));
        assert!(matches!(e.packs.shipped(), Err(PackError::BadKey(_))));
    }

    #[test]
    fn a_pack_of_another_chronicle_is_refused() {
        let e = env();
        let mut log = Log::new();
        log.fill(3, &[]);
        let h = e.packs.ship_log(&log.segs(), log.at(3)).unwrap().unwrap();
        let key = e.packs.key(&h);
        let mut b = std::fs::read(e.path(&key)).unwrap();
        b[9] ^= 1; // the chronicle id
        std::fs::write(e.path(&key), &b).unwrap();
        assert!(matches!(
            e.packs.chain(None),
            Err(PackError::Corrupt { .. })
        ));
    }

    // ── the cache ───────────────────────────────────────────────────

    /// A `Packs` reads where the store ends once, then knows it from its
    /// own puts: shipping the log lists nothing.
    #[test]
    fn shipping_lists_the_store_once() {
        let e = env();
        let mut log = Log::new();
        for n in [3, 5, 8, 9] {
            log.fill(n, &[]);
            e.packs.ship_log(&log.segs(), log.at(n)).unwrap().unwrap();
        }
        assert_eq!(e.lists.load(Ordering::Relaxed), 1);
        assert_eq!(e.packs.chain(Some(log.at(9))).unwrap().frames, log.frames());
    }

    /// Two `Packs` over one store each know only their own puts.  A stale
    /// end only makes a pack overlap one already there, and the chain
    /// merges them.
    #[test]
    fn a_stale_cache_only_overlaps() {
        let e = env();
        let other = Packs::new(
            LocalStore::new(e.dir.path()),
            FakeSend::default(),
            "vessels",
            ID,
        )
        .unwrap();
        let mut log = Log::new();
        log.fill(3, &[]);
        e.packs.ship_log(&log.segs(), log.at(3)).unwrap();
        log.fill(5, &[]);
        other.ship_log(&log.segs(), log.at(5)).unwrap(); // read the store: from 3
        log.fill(7, &[]);
        let h = e.packs.ship_log(&log.segs(), log.at(7)).unwrap().unwrap();
        assert_eq!(h.base, log.at(3), "stale: overlaps (3..5]");
        assert_eq!(e.packs.chain(Some(log.at(7))).unwrap().frames, log.frames());
    }

    // ── FsShipped ───────────────────────────────────────────────────

    /// A crash after the Seal pack's put, before its record: the section
    /// is unnamed, so nothing uses it, and the Seal is shipped again under
    /// the same key (one pack per Seal).  The next Seal builds on the last
    /// named one.
    #[test]
    fn an_unnamed_section_is_shipped_again_under_the_same_key() {
        let e = env();
        let mut log = Log::new();
        log.fill(3, &[3]);
        log.publish(&e, 3, 30, None).unwrap();
        log.fill(6, &[3, 6]);
        let lost = e
            .packs
            .ship_seal(&log.segs(), &log.snap(6, 60), None)
            .unwrap()
            .unwrap(); // the record never made it
        assert_eq!(
            e.packs.chain(None).unwrap().seals.len(),
            1,
            "unnamed: not used"
        );
        let keys = e.keys();
        // A regenerated stream: other bytes, the same section.
        e.send.variant.set(7);
        let again = log.publish(&e, 6, 60, None).unwrap();
        assert_eq!(again.header, lost.header);
        assert_ne!(again.record.digest, lost.record.digest);
        assert_eq!(
            e.keys().len(),
            keys.len() + 1,
            "the Seal pack was replaced; only the log pack is new"
        );
        let s3 = "tank/v@taso-seal-00000000000000000003";
        assert_eq!(e.read_fs(6).unwrap(), body(Some(s3), Lsn::new(6), 7));
        assert_eq!(e.packs.chain(None).unwrap().seals.len(), 2);
        // A crash after the record, before the log was shipped: nothing to
        // ship again; the next log ship carries the record.
        assert_eq!(
            e.packs
                .ship_seal(&log.segs(), &log.snap(6, 60), None)
                .unwrap(),
            None
        );
    }

    /// After a restart (a fresh `Packs`), a Seal pack the old process put
    /// but never named is found by listing once, and replaced under the
    /// same key; later Seals list nothing.
    #[test]
    fn a_restarted_writer_finds_the_unnamed_pack() {
        let e = env();
        let mut log = Log::new();
        log.fill(3, &[3]);
        log.publish(&e, 3, 30, None).unwrap();
        log.fill(6, &[3, 6]);
        let lost = e
            .packs
            .ship_seal(&log.segs(), &log.snap(6, 60), None)
            .unwrap()
            .unwrap();
        // The process dies; a new one opens the same store.
        let lists = Arc::new(AtomicU64::new(0));
        let store = Counting {
            inner: LocalStore::new(e.dir.path()),
            opened: Arc::default(),
            bytes: Arc::default(),
            lists: lists.clone(),
        };
        let fresh = Packs::new(store, FakeSend::default(), "vessels", ID).unwrap();
        let keys = e.keys().len();
        let again = fresh
            .ship_seal(&log.segs(), &log.snap(6, 60), None)
            .unwrap()
            .unwrap();
        assert_eq!(again.header, lost.header);
        assert_eq!(e.keys().len(), keys, "replaced, not added");
        let at = log.push_payload(Stream::Ctl, Payload::FsShipped(again.record));
        fresh.ship_log(&log.segs(), at).unwrap();
        let before = lists.load(Ordering::Relaxed);
        log.fill(10, &[3, 6, 10]);
        let next = fresh
            .ship_seal(&log.segs(), &log.snap(10, 100), None)
            .unwrap()
            .unwrap();
        assert_eq!(next.header.fs.unwrap().base, FsBase::Seal(log.at(6)));
        assert_eq!(
            lists.load(Ordering::Relaxed),
            before,
            "a Seal after the listing lists nothing"
        );
    }

    #[test]
    fn fs_shipped_records_are_checked() {
        // Two different records for one Seal.
        let e = env();
        let mut log = Log::new();
        log.fill(3, &[3]);
        log.publish(&e, 3, 30, None).unwrap();
        let fs = FsRef {
            base: FsBase::Full,
            to: log.at(3),
            guid: 30,
        };
        let at = log.name(fs, b"other bytes");
        e.packs.ship_log(&log.segs(), at).unwrap();
        assert!(
            matches!(e.packs.chain(None), Err(PackError::Conflict { lsn }) if lsn == Lsn::new(5))
        );
        // A record whose pack is gone.
        let e = env();
        let mut log = Log::new();
        log.fill(3, &[3]);
        let h = log.publish(&e, 3, 30, None).unwrap();
        std::fs::remove_file(e.path(&e.packs.key(&h.header))).unwrap();
        // The pack held lsns 1..3 too; ship them again as a log pack.
        e.packs
            .put_pack(
                PackHeader {
                    chronicle: ID,
                    base: Position::GENESIS,
                    end: log.at(3),
                    fs: None,
                },
                &log.frames()[..3],
                None,
            )
            .unwrap();
        assert!(
            matches!(e.packs.chain(None), Err(PackError::FsMissing { seal }) if seal == Lsn::new(3))
        );
        // A record that does not follow the Seal it names.
        let e = env();
        let mut log = Log::new();
        log.fill(3, &[3]);
        let ahead = FsRef {
            base: FsBase::Full,
            to: Position {
                lsn: Lsn::new(5),
                hash: log.at(3).hash,
            },
            guid: 1,
        };
        let at = log.name(ahead, b"x");
        e.packs.ship_log(&log.segs(), at).unwrap();
        assert!(
            matches!(e.packs.chain(None), Err(PackError::FsMissing { seal }) if seal == Lsn::new(5))
        );
        // A record that names the Seal with another hash, or another base,
        // names no pack's section.
        for wrong in [
            FsRef {
                base: FsBase::Full,
                to: Position {
                    lsn: Lsn::new(3),
                    hash: HashVal::from_bytes([7; 32]),
                },
                guid: 30,
            },
            FsRef {
                base: FsBase::Seal(Position::GENESIS),
                to: Position {
                    lsn: Lsn::new(3),
                    hash: HashVal::GENESIS,
                },
                guid: 30,
            },
        ] {
            let e = env();
            let mut log = Log::new();
            log.fill(3, &[3]);
            let wrong = FsRef {
                to: Position {
                    hash: if wrong.to.hash == HashVal::GENESIS {
                        log.at(3).hash
                    } else {
                        wrong.to.hash
                    },
                    ..wrong.to
                },
                ..wrong
            };
            e.packs
                .ship_seal(&log.segs(), &log.snap(3, 30), None)
                .unwrap()
                .unwrap();
            let at = log.name(wrong, &body(None, Lsn::new(3), 0));
            e.packs.ship_log(&log.segs(), at).unwrap();
            assert!(
                matches!(e.packs.chain(None), Err(PackError::FsMissing { seal }) if seal == Lsn::new(3)),
                "{wrong:?}"
            );
        }
        // Past the anchor a record names nothing yet.
        let e = env();
        let mut log = Log::new();
        log.fill(3, &[3]);
        log.publish(&e, 3, 30, None).unwrap();
        assert!(e.packs.chain(Some(log.at(3))).unwrap().seals.is_empty());
        assert_eq!(e.packs.chain(Some(log.at(4))).unwrap().seals.len(), 1);
    }

    // ── several segments, gaps, unanchored packs ────────────────────

    /// Packs start inside a closed segment and run into the next one.
    #[test]
    fn ships_across_segments() {
        let e = env();
        let mut log = Log::new();
        log.fill(5, &[]);
        e.packs.ship_log(&log.segs(), log.at(3)).unwrap();
        log.split();
        log.fill(8, &[]);
        let h = e.packs.ship_log(&log.segs(), log.at(8)).unwrap().unwrap();
        assert_eq!((h.base, h.end), (log.at(3), log.at(8)));
        assert_eq!(e.packs.chain(Some(log.at(8))).unwrap().frames, log.frames());
    }

    /// The takeover shape: B holds 1..=3 and continues after the head (5)
    /// with a Gap record at 6.  It ships from the anchor in its closed
    /// segment, through the Gap, and the chain is exactly B's local log.
    #[test]
    fn ships_through_a_gap() {
        let e = env();
        let mut old = Log::new();
        old.fill(5, &[]);
        e.packs.ship_log(&old.segs(), old.at(3)).unwrap();
        let mut b = Log::takeover(&old, 3);
        b.fill(7, &[]);
        let h = e.packs.ship_log(&b.segs(), b.at(7)).unwrap().unwrap();
        assert_eq!((h.base, h.end), (old.at(3), b.at(7)));
        let c = e.packs.chain(Some(b.at(7))).unwrap();
        assert_eq!(Log::lsns(&c.frames), vec![1, 2, 3, 6, 7]);
        assert_eq!(c.frames, b.frames());
        assert_eq!(c.end, b.at(7));
        assert_eq!(e.packs.chain(None).unwrap().frames, b.frames());
    }

    /// The old Warden shipped up to its head (5) but died before the
    /// anchor moved.  B ships from there (it knows 5 by its segment's base
    /// hash); the Gap at 6 is then a plain link, and 4, 5 are verified but
    /// not returned.
    #[test]
    fn an_unanchored_pack_up_to_the_old_head() {
        let e = env();
        let mut old = Log::new();
        old.fill(5, &[]);
        e.packs.ship_log(&old.segs(), old.at(3)).unwrap();
        let stale = e.packs.ship_log(&old.segs(), old.at(5)).unwrap().unwrap(); // never anchored
        let mut b = Log::takeover(&old, 3);
        b.fill(7, &[]);
        let h = e.packs.ship_log(&b.segs(), b.at(7)).unwrap().unwrap();
        assert_eq!(h.base, old.at(5));
        for anchor in [None, Some(b.at(7))] {
            let c = e.packs.chain(anchor).unwrap();
            assert_eq!(Log::lsns(&c.frames), vec![1, 2, 3, 6, 7], "{anchor:?}");
            assert_eq!(c.frames, b.frames());
        }
        // Without the stale pack B's pack still has a known base: the
        // Gap's `resumes` hash.
        std::fs::remove_file(e.path(&e.packs.key(&stale))).unwrap();
        assert_eq!(e.packs.chain(Some(b.at(7))).unwrap().frames, b.frames());
        // A lost position is no anchor, even where a pack holds it.
        assert!(matches!(
            e.packs.chain(Some(old.at(5))),
            Err(PackError::NotAnchored { .. })
        ));
    }

    /// The old Warden's unanchored pack ends inside the gap (4): B holds
    /// no lsn 4, so it ships from the Gap's `kept` (3), and the merge lets
    /// the Gap keep a record before the tail.
    #[test]
    fn an_unanchored_pack_inside_the_gap() {
        let e = env();
        let mut old = Log::new();
        old.fill(5, &[]);
        e.packs.ship_log(&old.segs(), old.at(3)).unwrap();
        e.packs.ship_log(&old.segs(), old.at(4)).unwrap(); // never anchored
        let mut b = Log::takeover(&old, 3);
        b.fill(7, &[]);
        let h = e.packs.ship_log(&b.segs(), b.at(7)).unwrap().unwrap();
        assert_eq!(h.base, old.at(3));
        let c = e.packs.chain(Some(b.at(7))).unwrap();
        assert_eq!(c.frames, b.frames());
        assert!(matches!(
            e.packs.chain(Some(old.at(4))),
            Err(PackError::NotAnchored { .. })
        ));
        // And the next pack starts where B's ended.
        b.fill(9, &[]);
        let h = e.packs.ship_log(&b.segs(), b.at(9)).unwrap().unwrap();
        assert_eq!(h.base, b.at(7));
        assert_eq!(e.packs.chain(Some(b.at(9))).unwrap().frames, b.frames());
    }

    /// The gap swallows Seals: the old Warden published Seals 4 and 6 but
    /// only lsn 3 (the FsShipped record of Seal 2) was anchored.  B never
    /// received them; its next Seal ships from the last Seal it names (2),
    /// and the chain skips the swallowed ones.
    #[test]
    fn a_gap_that_swallows_a_seal() {
        let e = env();
        let mut old = Log::new();
        old.fill(2, &[2]);
        old.publish(&e, 2, 20, None).unwrap(); // record at 3: the anchor
        old.fill(4, &[2, 4]);
        old.publish(&e, 4, 40, None).unwrap(); // never anchored
        old.fill(6, &[2, 4, 6]);
        old.publish(&e, 6, 60, None).unwrap(); // never anchored; head 7
        let mut b = Log::takeover(&old, 3);
        b.fill(10, &[10]);
        let h = b.publish(&e, 10, 100, None).unwrap();
        assert_eq!(h.header.fs.unwrap().base, FsBase::Seal(old.at(2)));
        assert_eq!(
            h.header.base,
            old.at(7),
            "the log starts where the store ends, which B knows by hash"
        );
        let s2 = "tank/v@taso-seal-00000000000000000002".to_string();
        assert_eq!(
            e.send.calls.borrow().last().unwrap(),
            &(Some(s2), Lsn::new(10))
        );
        for anchor in [None, Some(b.tail())] {
            let c = e.packs.chain(anchor).unwrap();
            assert_eq!(
                Log::lsns(&c.frames),
                vec![1, 2, 3, 8, 9, 10, 11],
                "{anchor:?}"
            );
            assert_eq!(
                c.seals
                    .iter()
                    .map(|f| f.fs.to.lsn.get())
                    .collect::<Vec<_>>(),
                vec![2, 10]
            );
        }
        assert_eq!(
            e.read_fs(10).unwrap(),
            body(
                Some("tank/v@taso-seal-00000000000000000002"),
                Lsn::new(10),
                0
            )
        );
        // Again: nothing.
        assert_eq!(
            e.packs
                .ship_seal(&b.segs(), &b.snap(10, 100), None)
                .unwrap(),
            None
        );
    }

    /// What rebirth reads: up to the anchor and no further.  Packs past it
    /// are not used, but a conflict there is still reported; a hole there
    /// only ends what is read.
    #[test]
    fn chain_ends_at_the_anchor() {
        let e = env();
        let mut old = Log::new();
        old.fill(2, &[2]);
        let r2 = old.publish(&e, 2, 1, None).unwrap().record; // record at 3
        old.fill(5, &[2, 5]);
        old.publish(&e, 5, 2, None).unwrap(); // record at 6
        let c = e.packs.chain(Some(old.at(3))).unwrap();
        assert_eq!(Log::lsns(&c.frames), vec![1, 2, 3]);
        assert_eq!((c.end, c.seals.len()), (old.at(3), 1));
        assert_eq!(e.packs.chain(None).unwrap().seals.len(), 2);
        // A hole past the anchor: a pack (7..8] with nothing holding 7.
        old.fill(8, &[2, 5]);
        let frames = old.seg.frames().unwrap();
        e.packs
            .put_pack(
                PackHeader {
                    chronicle: ID,
                    base: old.at(7),
                    end: old.at(8),
                    fs: None,
                },
                &frames[7..8],
                None,
            )
            .unwrap();
        assert_eq!(e.packs.chain(Some(old.at(3))).unwrap().end, old.at(3));
        assert!(
            matches!(e.packs.chain(None), Err(PackError::Gap { missing }) if missing == Lsn::new(7))
        );
        // Another history past the anchor is still a conflict.
        let mut other = Log::new();
        other.fill(2, &[2]);
        other.push_payload(Stream::Ctl, Payload::FsShipped(r2));
        assert_eq!(other.at(3), old.at(3));
        other.push(false, 99);
        let of = other.seg.frames().unwrap();
        e.packs
            .put_pack(
                PackHeader {
                    chronicle: ID,
                    base: other.at(3),
                    end: other.at(4),
                    fs: None,
                },
                &of[3..4],
                None,
            )
            .unwrap();
        assert!(
            matches!(e.packs.chain(Some(old.at(3))), Err(PackError::Conflict { lsn }) if lsn == Lsn::new(4))
        );
    }

    /// One pack with the takeover's frames, put by hand.
    fn put_takeover(e: &Env, b: &Log, base: Position, upto: u64) {
        let frames: Vec<Frame> = b
            .frames()
            .into_iter()
            .filter(|f| f.envelope.lsn > base.lsn && f.envelope.lsn.get() <= upto)
            .collect();
        e.packs
            .put_pack(
                PackHeader {
                    chronicle: ID,
                    base,
                    end: b.at(upto),
                    fs: None,
                },
                &frames,
                None,
            )
            .unwrap();
    }

    #[test]
    fn gaps_must_keep_what_the_chain_holds() {
        // Inside one pack a Gap keeps exactly the frame before it.
        let mut old = Log::new();
        old.fill(5, &[]);
        let wrong = GapRecord {
            kept: Lsn::new(3),
            kept_hash: old.at(2).hash,
            resumes: Lsn::new(5),
            resumes_hash: old.at(5).hash,
        };
        let b = Log::takeover_with(&old, 3, wrong.clone());
        let e = env();
        e.packs.ship_log(&old.segs(), old.at(3)).unwrap();
        put_takeover(&e, &b, old.at(3), 6);
        assert!(matches!(
            e.packs.chain(None),
            Err(PackError::Corrupt { .. })
        ));
        // Across packs, with a plain link at 6: still checked.
        let e = env();
        e.packs.ship_log(&old.segs(), old.at(5)).unwrap();
        put_takeover(&e, &b, old.at(5), 6);
        assert!(
            matches!(e.packs.chain(None), Err(PackError::Conflict { lsn }) if lsn == Lsn::new(6))
        );
        // A Gap that keeps a record after the tail.
        let mut old = Log::new();
        old.fill(6, &[]);
        let late = GapRecord {
            kept: Lsn::new(5),
            kept_hash: old.at(5).hash,
            resumes: Lsn::new(6),
            resumes_hash: old.at(6).hash,
        };
        let b = Log::takeover_with(&old, 3, late);
        let e = env();
        e.packs.ship_log(&old.segs(), old.at(3)).unwrap();
        put_takeover(&e, &b, old.at(6), 7);
        assert!(
            matches!(e.packs.chain(None), Err(PackError::Conflict { lsn }) if lsn == Lsn::new(7))
        );
        // A second takeover keeping a record the first one lost (4).
        let mut old = Log::new();
        old.fill(5, &[]);
        let mut b = Log::takeover(&old, 3);
        b.fill(7, &[]);
        let twice = GapRecord {
            kept: Lsn::new(4),
            kept_hash: old.at(4).hash,
            resumes: Lsn::new(7),
            resumes_hash: b.at(7).hash,
        };
        let c = Log::takeover_with(&b, 3, twice);
        let e = env();
        e.packs.ship_log(&old.segs(), old.at(5)).unwrap();
        e.packs.ship_log(&b.segs(), b.at(7)).unwrap();
        put_takeover(&e, &c, b.at(7), 8);
        assert!(
            matches!(e.packs.chain(None), Err(PackError::Conflict { lsn }) if lsn == Lsn::new(8))
        );
        // A malformed Gap: it does not resume right before itself.
        let mut old = Log::new();
        old.fill(5, &[]);
        let bad = GapRecord {
            kept: Lsn::new(3),
            kept_hash: old.at(3).hash,
            resumes: Lsn::new(4),
            resumes_hash: old.at(4).hash,
        };
        let b = Log::takeover_with(&old, 3, bad);
        let e = env();
        e.packs.ship_log(&old.segs(), old.at(5)).unwrap();
        put_takeover(&e, &b, old.at(5), 6);
        assert!(matches!(
            e.packs.chain(None),
            Err(PackError::Corrupt { .. })
        ));
        // A jump without a Gap record.
        let mut old = Log::new();
        old.fill(7, &[]);
        let e = env();
        e.packs.ship_log(&old.segs(), old.at(3)).unwrap();
        let frames = old.seg.frames().unwrap();
        e.packs
            .put_pack(
                PackHeader {
                    chronicle: ID,
                    base: old.at(5),
                    end: old.at(7),
                    fs: None,
                },
                &frames[5..7],
                None,
            )
            .unwrap();
        assert!(
            matches!(e.packs.chain(None), Err(PackError::Gap { missing }) if missing == Lsn::new(4))
        );
    }

    /// The writer never builds on what it cannot hold.
    #[test]
    fn the_writer_refuses_a_store_it_does_not_hold() {
        let mut old = Log::new();
        old.fill(5, &[]);
        let mut b = Log::takeover(&old, 3);
        b.fill(8, &[8]);
        // The store ends at B's segment base (5), but with another record.
        let mut other = Log::new();
        other.fill(3, &[2, 4]);
        other.push(false, 99);
        other.fill(5, &[2, 4]);
        let e = env();
        e.packs.ship_log(&old.segs(), old.at(3)).unwrap();
        e.packs
            .put_pack(
                PackHeader {
                    chronicle: ID,
                    base: old.at(3),
                    end: other.at(5),
                    fs: None,
                },
                &other.seg.frames().unwrap()[3..5],
                None,
            )
            .unwrap();
        assert!(
            matches!(e.packs.ship_log(&b.segs(), b.at(7)), Err(PackError::Conflict { lsn }) if lsn == Lsn::new(5))
        );
        // Where the store ends, read against B's local log.
        let at = |lsn: u64, hash: HashVal| Position {
            lsn: Lsn::new(lsn),
            hash,
        };
        let p = &e.packs;
        assert_eq!(
            p.log_base(&b.segs(), Position::GENESIS).unwrap(),
            Position::GENESIS
        );
        assert_eq!(p.log_base(&b.segs(), b.at(2)).unwrap(), b.at(2));
        assert!(matches!(
            p.log_base(&b.segs(), at(2, b.at(1).hash)),
            Err(PackError::Conflict { .. })
        ));
        assert_eq!(
            p.log_base(&b.segs(), old.at(4)).unwrap(),
            old.at(3),
            "inside the gap: kept"
        );
        assert_eq!(
            p.log_base(&b.segs(), at(4, b.at(1).hash)).unwrap(),
            old.at(3),
            "a lost hash cannot be checked"
        );
        assert_eq!(p.log_base(&b.segs(), old.at(5)).unwrap(), old.at(5));
        assert!(matches!(
            p.log_base(&b.segs(), at(9, b.at(8).hash)),
            Err(PackError::Refused(_))
        ));
        // Frames after a position the local log holds with another hash.
        assert!(matches!(
            p.frames_after(&b.segs(), at(2, b.at(1).hash), b.at(7)),
            Err(PackError::Refused(_))
        ));
        assert!(matches!(
            p.frames_after(&b.segs(), at(5, b.at(1).hash), b.at(7)),
            Err(PackError::Refused(_))
        ));
        assert_eq!(
            Log::lsns(&p.frames_after(&b.segs(), old.at(3), b.at(7)).unwrap()),
            vec![6, 7]
        );
        // A local FsShipped record whose section no pack holds.
        let e = env();
        let mut log = Log::new();
        log.fill(3, &[3]);
        log.publish(&e, 3, 1, None).unwrap();
        log.fill(6, &[3, 6]);
        assert!(
            matches!(env().packs.ship_seal(&log.segs(), &log.snap(6, 2), None), Err(PackError::FsMissing { seal }) if seal == Lsn::new(3))
        );
        // Or a pack whose section is another one (another guid).
        let e2 = env();
        let mut twin = Log::new();
        twin.fill(3, &[3]);
        assert_eq!(twin.at(3), log.at(3));
        e2.packs
            .ship_seal(&twin.segs(), &twin.snap(3, 9), None)
            .unwrap()
            .unwrap();
        assert!(matches!(
            e2.packs.ship_seal(&log.segs(), &log.snap(6, 2), None),
            Err(PackError::FsMissing { .. })
        ));
        assert!(e
            .packs
            .ship_seal(&log.segs(), &log.snap(6, 2), None)
            .unwrap()
            .is_some());
    }

    #[test]
    fn locate_reads_bases_and_tails() {
        let mut old = Log::new();
        old.fill(5, &[]);
        let mut b = Log::takeover(&old, 3);
        b.fill(7, &[]);
        let segs = b.segs();
        let l = |n: u64| locate(&segs, Lsn::new(n));
        assert_eq!(l(0), Spot::Genesis);
        assert_eq!(l(3), Spot::Frame(0));
        assert_eq!(l(4), Spot::Lost { kept: old.at(3) });
        assert_eq!(l(5), Spot::Base(1));
        assert_eq!(l(6), Spot::Frame(1));
        assert_eq!(l(8), Spot::Beyond);
        // A split without a gap: the joint is the first segment's frame.
        let mut log = Log::new();
        log.fill(3, &[]);
        log.split();
        log.fill(5, &[]);
        let segs = log.segs();
        assert_eq!(locate(&segs, Lsn::new(3)), Spot::Frame(0));
        assert_eq!(locate(&segs, Lsn::new(4)), Spot::Frame(1));
    }

    #[test]
    fn publisher_ships_from_every_segment() {
        let mut log = Log::new();
        log.fill(5, &[]);
        log.split();
        log.fill(8, &[]);
        let (_cd, coord) = coord_for(&log);
        let dir = tempfile::tempdir().unwrap();
        let packs = Packs::new(
            LocalStore::new(dir.path()),
            FakeSend::default(),
            "vessels",
            ID,
        )
        .unwrap();
        let mut p = PackPublisher::new(packs, coord.clone(), WardenId::new(1));
        p.publish(ID, Epoch::FIRST, &log.segs(), log.at(3)).unwrap();
        p.publish(ID, Epoch::FIRST, &log.segs(), log.at(8)).unwrap();
        assert_eq!(coord.shipped(ID).unwrap(), log.at(8));
        let reader = Packs::new(
            LocalStore::new(dir.path()),
            FakeSend::default(),
            "vessels",
            ID,
        )
        .unwrap();
        assert_eq!(reader.chain(Some(log.at(8))).unwrap().frames, log.frames());
    }

    // ── PackPublisher ───────────────────────────────────────────────

    /// A coordinator that has accepted every frame of `log`, held by A.
    fn coord_for(log: &Log) -> (tempfile::TempDir, Arc<dyn Coord>) {
        use crate::coordinator::Coordinator;
        let dir = tempfile::tempdir().unwrap();
        let c = Coordinator::open(dir.path().join("coord.redb")).unwrap();
        c.register(ID, WardenId::new(1)).unwrap();
        for f in log.frames() {
            c.append(WardenId::new(1), &f.envelope).unwrap();
        }
        (dir, Arc::new(c))
    }

    #[test]
    fn publisher_ships_then_anchors_and_the_chain_verifies_against_the_anchor() {
        let mut log = Log::new();
        log.fill(5, &[]);
        let (_cd, coord) = coord_for(&log);
        let dir = tempfile::tempdir().unwrap();
        let packs = Packs::new(
            LocalStore::new(dir.path()),
            FakeSend::default(),
            "vessels",
            ID,
        )
        .unwrap();
        let mut p = PackPublisher::new(packs, coord.clone(), WardenId::new(1));
        p.publish(ID, Epoch::FIRST, &log.segs(), log.at(3)).unwrap();
        assert_eq!(coord.shipped(ID).unwrap(), log.at(3));
        p.publish(ID, Epoch::FIRST, &log.segs(), log.at(5)).unwrap();
        assert_eq!(coord.shipped(ID).unwrap(), log.at(5));
        // Nothing new: still fine, nothing changes.
        p.publish(ID, Epoch::FIRST, &log.segs(), log.at(5)).unwrap();
        let reader = Packs::new(
            LocalStore::new(dir.path()),
            FakeSend::default(),
            "vessels",
            ID,
        )
        .unwrap();
        assert_eq!(
            reader.chain(Some(coord.shipped(ID).unwrap())).unwrap().end,
            log.at(5)
        );
        assert_eq!(reader.store.list(&reader.dir).unwrap().len(), 2);
    }

    #[test]
    fn publisher_fails_on_the_store_or_the_coordinator() {
        let mut log = Log::new();
        log.fill(4, &[]);
        let (_cd, coord) = coord_for(&log);
        // The store fails: its root is a file.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("not-a-dir");
        std::fs::write(&root, b"x").unwrap();
        let packs = Packs::new(LocalStore::new(&root), FakeSend::default(), "vessels", ID).unwrap();
        let mut p = PackPublisher::new(packs, coord.clone(), WardenId::new(1));
        assert!(p.publish(ID, Epoch::FIRST, &log.segs(), log.at(4)).is_err());
        assert_eq!(
            coord.shipped(ID).unwrap(),
            Position::GENESIS,
            "no anchor without the pack"
        );
        // The coordinator refuses: a stale epoch, another holder.
        let packs = Packs::new(
            LocalStore::new(dir.path()),
            FakeSend::default(),
            "vessels",
            ID,
        )
        .unwrap();
        let mut p = PackPublisher::new(packs, coord.clone(), WardenId::new(1));
        assert!(p
            .publish(ID, Epoch::new(7), &log.segs(), log.at(4))
            .is_err());
        let packs = Packs::new(
            LocalStore::new(dir.path()),
            FakeSend::default(),
            "vessels",
            ID,
        )
        .unwrap();
        let mut other = PackPublisher::new(packs, coord.clone(), WardenId::new(2));
        assert!(other
            .publish(ID, Epoch::FIRST, &log.segs(), log.at(4))
            .is_err());
        assert_eq!(coord.shipped(ID).unwrap(), Position::GENESIS);
        // Another Chronicle's packs.
        let packs = Packs::new(
            LocalStore::new(dir.path()),
            FakeSend::default(),
            "vessels",
            TPL,
        )
        .unwrap();
        let mut wrong = PackPublisher::new(packs, coord.clone(), WardenId::new(1));
        assert!(wrong
            .publish(ID, Epoch::FIRST, &log.segs(), log.at(4))
            .is_err());
    }

    // ── the first fs section starts where the lineage says ──────────

    const TPL: ChronicleId = ChronicleId::from_bytes([0x7E; 16]);

    fn parent() -> ParentSeal {
        ParentSeal {
            chronicle: TPL,
            seal: Lsn::new(40),
            seal_hash: HashVal::from_bytes([0x40; 32]),
        }
    }

    fn origin_snap(guid: u64) -> Snapshot {
        Snapshot {
            dataset: Dataset::new("tank/tpl").unwrap(),
            seal: Lsn::new(40),
            createtxg: 1,
            guid,
            seal_hash: Some(HashVal::from_bytes([0x40; 32])),
        }
    }

    #[test]
    fn a_forked_vessel_ships_its_first_seal_from_its_origin() {
        let e = env();
        let mut log = Log::fork(parent());
        log.fill(3, &[3]);
        let h = log.publish(&e, 3, 7, Some(&origin_snap(500))).unwrap();
        let want = FsBase::Origin {
            chronicle: TPL,
            seal: Position {
                lsn: Lsn::new(40),
                hash: HashVal::from_bytes([0x40; 32]),
            },
            guid: 500,
        };
        assert_eq!(h.header.fs.unwrap().base, want);
        assert_eq!(
            h.record.base,
            StreamBase::Origin {
                parent: parent(),
                guid: 500
            }
        );
        assert_eq!(
            e.send.calls.borrow()[0].0.as_deref(),
            Some("tank/tpl@taso-seal-00000000000000000040")
        );
        // Later Seals are incremental from the previous one; no origin then.
        log.fill(6, &[3, 6]);
        assert!(matches!(
            e.packs
                .ship_seal(&log.segs(), &log.snap(6, 8), Some(&origin_snap(500))),
            Err(PackError::Refused(_))
        ));
        let h2 = log.publish(&e, 6, 8, None).unwrap();
        assert_eq!(h2.header.fs.unwrap().base, FsBase::Seal(log.at(3)));
        let c = e.packs.chain(Some(log.tail())).unwrap();
        assert_eq!(
            c.seals.iter().map(|f| f.fs.base).collect::<Vec<_>>(),
            vec![want, FsBase::Seal(log.at(3))]
        );
    }

    #[test]
    fn the_first_seal_must_match_the_lineage() {
        // A fork without its origin, or with another snapshot.
        let e = env();
        let mut fork = Log::fork(parent());
        fork.fill(3, &[3]);
        assert!(matches!(
            e.packs.ship_seal(&fork.segs(), &fork.snap(3, 1), None),
            Err(PackError::Refused(_))
        ));
        let mut wrong = origin_snap(1);
        wrong.seal = Lsn::new(41);
        assert!(matches!(
            e.packs
                .ship_seal(&fork.segs(), &fork.snap(3, 1), Some(&wrong)),
            Err(PackError::Refused(_))
        ));
        let mut wrong = origin_snap(1);
        wrong.seal_hash = Some(HashVal::from_bytes([1; 32]));
        assert!(matches!(
            e.packs
                .ship_seal(&fork.segs(), &fork.snap(3, 1), Some(&wrong)),
            Err(PackError::Refused(_))
        ));
        // A void-born Vessel given an origin.
        let mut void = Log::new();
        void.fill(3, &[3]);
        assert!(matches!(
            e.packs
                .ship_seal(&void.segs(), &void.snap(3, 1), Some(&origin_snap(1))),
            Err(PackError::Refused(_))
        ));
        // No lineage at lsn 1 at all.
        let mut bare = Log::bare();
        bare.fill(3, &[3]);
        assert!(matches!(
            e.packs.ship_seal(&bare.segs(), &bare.snap(3, 1), None),
            Err(PackError::NoLineage)
        ));
        assert!(e.keys().is_empty());
    }

    /// The reader holds the first fs section to the lineage too.
    #[test]
    fn chain_holds_the_first_fs_section_to_the_lineage() {
        let s = || -> ByteStream { Box::new(io::Cursor::new(b"x".to_vec())) };
        let origin = |chronicle: ChronicleId, lsn: u64| FsBase::Origin {
            chronicle,
            seal: Position {
                lsn: Lsn::new(lsn),
                hash: HashVal::from_bytes([0x40; 32]),
            },
            guid: 1,
        };
        let cases: Vec<(Log, FsBase, bool)> = vec![
            (Log::new(), FsBase::Full, true),
            (Log::new(), origin(TPL, 40), false),
            (Log::fork(parent()), origin(TPL, 40), true),
            (Log::fork(parent()), FsBase::Full, false),
            (
                Log::fork(parent()),
                origin(ChronicleId::from_bytes([0x11; 16]), 40),
                false,
            ),
            (Log::fork(parent()), origin(TPL, 39), false),
        ];
        for (mut log, base, ok) in cases {
            let e = env();
            log.fill(3, &[3]);
            let fs = FsRef {
                base,
                to: log.at(3),
                guid: 2,
            };
            log.name(fs, b"x");
            let frames = log.frames();
            e.packs
                .put_pack(
                    PackHeader {
                        chronicle: ID,
                        base: Position::GENESIS,
                        end: log.at(4),
                        fs: Some(fs),
                    },
                    &frames,
                    Some(s()),
                )
                .unwrap();
            let r = e.packs.chain(None);
            if ok {
                assert!(r.is_ok(), "{base:?}: {r:?}");
            } else {
                assert!(
                    matches!(r, Err(PackError::BrokenFsChain { .. })),
                    "{base:?}: {r:?}"
                );
            }
        }
        // No lineage record at lsn 1.
        let e = env();
        let mut bare = Log::bare();
        bare.fill(3, &[3]);
        let fs = FsRef {
            base: FsBase::Full,
            to: bare.at(3),
            guid: 2,
        };
        bare.name(fs, b"x");
        let frames = bare.frames();
        e.packs
            .put_pack(
                PackHeader {
                    chronicle: ID,
                    base: Position::GENESIS,
                    end: bare.at(4),
                    fs: Some(fs),
                },
                &frames,
                Some(s()),
            )
            .unwrap();
        assert!(matches!(e.packs.chain(None), Err(PackError::NoLineage)));
    }

    // ── on a real pool ──────────────────────────────────────────────

    mod node {
        use super::*;
        use crate::ship::ZfsSend;
        use crate::zfs::Zfs;
        use std::process::Command;

        fn zfs(args: &[&str]) -> String {
            let out = Command::new("zfs").args(args).output().expect("run zfs");
            assert!(
                out.status.success(),
                "zfs {:?}: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).into_owned()
        }

        /// A Vessel forked from a Template: its first Seal pack carries an
        /// incremental from the Template's Seal, its second an incremental
        /// from the first.  "Node B" holds the Template (received with its
        /// guid) and rebuilds the Vessel from the packs alone.
        #[test]
        #[ignore = "needs a ZFS pool: set TASO_ZFS_DATASET"]
        fn ship_packs_then_receive_elsewhere() {
            use crate::zfs::CloneBase;
            let base = std::env::var("TASO_ZFS_DATASET").expect("set TASO_ZFS_DATASET");
            let root = format!("{base}/pk-{}", std::process::id());
            zfs(&["create", &root]);
            struct Cleanup(String);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = Command::new("zfs")
                        .args(["destroy", "-R", &self.0])
                        .status();
                }
            }
            let _c = Cleanup(root.clone());
            let z = Zfs::cli();

            // The Template, sealed at its lsn 40.
            let tpl = Dataset::new(&format!("{root}/tpl")).unwrap();
            let tmount = z.create(&tpl).unwrap().mountpoint.unwrap();
            std::fs::write(tmount.join("base.bin"), vec![3u8; 1 << 20]).unwrap();
            std::fs::write(tmount.join("f"), b"template").unwrap();
            let p = parent();
            let t40 = z.snapshot(&tpl, p.seal, p.seal_hash).unwrap();

            // The Vessel, forked from it.
            let src = Dataset::new(&format!("{root}/src")).unwrap();
            let mount = z
                .clone(&tpl, p.seal, p.seal_hash, &src)
                .unwrap()
                .mountpoint
                .unwrap();
            let mut log = Log::fork(p);
            std::fs::write(mount.join("f"), b"one").unwrap();
            log.fill(3, &[3]);
            let s3 = z.snapshot(&src, Lsn::new(3), log.at(3).hash).unwrap();
            let store_dir = tempfile::tempdir().unwrap();
            let packs = Packs::new(
                LocalStore::new(store_dir.path()),
                ZfsSend::default(),
                "vessels",
                ID,
            )
            .unwrap();
            // Publish Seal 3: its pack, then the record naming it.
            let h3 = packs
                .ship_seal(&log.segs(), &s3, Some(&t40))
                .unwrap()
                .unwrap();
            log.push_payload(Stream::Ctl, Payload::FsShipped(h3.record.clone()));
            std::fs::write(mount.join("f"), b"two").unwrap();
            log.fill(7, &[3, 7]);
            let s7 = z.snapshot(&src, Lsn::new(7), log.at(7).hash).unwrap();
            let h7 = packs.ship_seal(&log.segs(), &s7, None).unwrap().unwrap();
            let end = log.push_payload(Stream::Ctl, Payload::FsShipped(h7.record.clone()));
            packs.ship_log(&log.segs(), end).unwrap();
            println!(
                "Seal 3 stream {} bytes, Seal 7 stream {} bytes",
                h3.record.bytes, h7.record.bytes
            );
            let pack3 = std::fs::metadata(store_dir.path().join(packs.key(&h3.header)))
                .unwrap()
                .len();
            println!("first Seal pack {pack3} bytes (Template is over 1 MiB)");
            assert!(
                pack3 < 200_000,
                "the Template does not travel with the Vessel"
            );

            // Node B: the Template arrives first, keeping its guid.
            let tpl_b = Dataset::new(&format!("{root}/b-tpl")).unwrap();
            let out = Command::new("zfs")
                .args(["send", &tpl.seal_snapshot(p.seal)])
                .output()
                .unwrap();
            assert!(out.status.success());
            let tb = z
                .receive(&tpl_b, None, (p.seal, p.seal_hash), &mut &out.stdout[..])
                .unwrap();
            assert_eq!(tb.guid, t40.guid);

            let chain = packs.chain(Some(end)).unwrap();
            assert_eq!(chain.frames, log.seg.frames().unwrap());
            let dst = Dataset::new(&format!("{root}/dst")).unwrap();
            for shipped in &chain.seals {
                let got = shipped.fs;
                let mut stream = packs.open_fs(shipped).unwrap().unwrap();
                let to = (got.to.lsn, got.to.hash);
                let snap = match got.base {
                    FsBase::Origin {
                        chronicle,
                        seal,
                        guid,
                    } => {
                        assert_eq!(chronicle, TPL);
                        let cb = CloneBase {
                            dataset: tpl_b.clone(),
                            seal: seal.lsn,
                            hash: seal.hash,
                            guid,
                        };
                        z.receive_clone(&dst, &cb, to, &mut stream).unwrap()
                    }
                    FsBase::Seal(prev) => z
                        .receive(&dst, Some((prev.lsn, prev.hash)), to, &mut stream)
                        .unwrap(),
                    FsBase::Full => panic!("a forked Vessel has no full stream"),
                };
                assert_eq!(
                    snap.guid, got.guid,
                    "the received snapshot is the one the Seal was taken from"
                );
            }
            assert_eq!(chain.seals[0].fs.guid, s3.guid);
            zfs(&["mount", dst.as_str()]);
            let dmount = std::path::PathBuf::from(
                zfs(&["get", "-H", "-o", "value", "mountpoint", dst.as_str()]).trim(),
            );
            assert_eq!(std::fs::read(dmount.join("f")).unwrap(), b"two");
            assert_eq!(
                std::fs::read(dmount.join("base.bin")).unwrap(),
                vec![3u8; 1 << 20]
            );
            println!("packs: {:?}", packs.store.list(&packs.dir).unwrap());
        }
    }
}
