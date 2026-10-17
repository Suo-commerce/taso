//! The coordinator behind a socket (v1.0 §1 P2; v0.4 §8.1).
//!
//! Rebirth moves a Vessel to another Warden, possibly on another node, and
//! both must talk to the same coordinator.  [`Server`] owns one
//! [`Coord`] (in practice the redb [`Coordinator`](crate::coordinator::Coordinator),
//! the only process holding its file) and serves it over a Unix socket;
//! [`RemoteCoord`] is a [`Coord`] that forwards every call there.  It must
//! pass the same `conformance` test (in `coordinator`'s tests) as
//! the in-process coordinator.
//!
//! # Unknown outcomes
//!
//! A request whose answer never arrives — the connection broke, the server
//! died, the read timed out — may or may not have been applied.  The
//! client returns [`CoordError::Unavailable`] (so
//! [`CoordError::outcome_unknown`] is true), drops the connection, and
//! reconnects on the *next* call.  It never re-sends a request on its own:
//! an append whose answer was lost is exactly the case only recovery
//! against the anchored head may settle.
//!
//! A failure on the server side whose outcome is unknown (redb storage, a
//! corrupt row) arrives as [`CoordError::Unavailable`] carrying the
//! server's message.  Refusals arrive as themselves, field for field.
//!
//! # Wire format (v1)
//!
//! One frame per request and one per reply, framed as the Field protocol
//! (u32 big-endian length, 16 MiB cap).  All integers big-endian.  The
//! layouts are this protocol's own, deliberately not shared with the
//! segment or the coordinator's storage row, so either can change without
//! the other.
//!
//! ```text
//! request  version 1 (1) · op (1) · fields
//!   1 register   chronicle (16) · holder (8)
//!   2 append     warden (8) · envelope (137, as in a segment frame)
//!   3 transfer   chronicle (16) · new_holder (8)
//!   4 ownership  chronicle (16)
//!   5 head       chronicle (16)
//!   6 advance_shipped  warden (8) · chronicle (16) · epoch (8) · position (40)
//!   7 shipped    chronicle (16)
//!   8 append_batch  warden (8) · count (4) · count × envelope (137)
//!
//! reply    status (1) · body
//!   0 ok         head (48) | epoch (8) | ownership: epoch · holder · sealed_prefix (64)
//!                | position (40)
//!   1 refused    reason (1) · fields          (every refusal of CoordError)
//!   2 failed     utf-8 message                (outcome unknown on the server)
//!   3 bad        utf-8 message                (malformed request; nothing done)
//!
//! head     lsn (8) · hash (32) · epoch (8)
//! position lsn (8) · hash (32)
//! ```
//!
//! Operations 6, 7 and 8 were added to version 1 before any server ran
//! outside a test.  A batch holds at most 4096 envelopes.
//!
//! A malformed request gets status 3 and the server closes the connection,
//! since it can no longer trust the framing.  The version byte lets a
//! later version add operations without guessing.
//!
//! # Scope
//!
//! Unix socket only: two Wardens on one host.  The socket is created mode
//! 0600; put it in a directory only the Warden user can enter, since the
//! mode is applied just after `bind`.  TCP for a second machine comes with
//! authentication — a coordinator reachable without it would let anyone
//! transfer ownership.
//!
//! Normative references: v0.4 §8.1–8.3, §8.7; v1.0 §1 (P2).

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use taso_core::envelope::{BranchId, ChronicleHead, ChronicleId, Envelope, Epoch, HashVal, Lsn, Stream};
use taso_core::model::{Ownership, WardenId};
use taso_field::protocol::{read_frame, write_frame, ProtocolError};

use crate::coordinator::{Coord, CoordError};
use crate::segment::Position;

const WIRE_V1: u8 = 1;

const OP_REGISTER: u8 = 1;
const OP_APPEND: u8 = 2;
const OP_TRANSFER: u8 = 3;
const OP_OWNERSHIP: u8 = 4;
const OP_HEAD: u8 = 5;
const OP_ADVANCE_SHIPPED: u8 = 6;
const OP_SHIPPED: u8 = 7;
const OP_APPEND_BATCH: u8 = 8;

/// The most envelopes one batched append carries.
const MAX_BATCH: u32 = 4096;

const ST_OK: u8 = 0;
const ST_REFUSED: u8 = 1;
const ST_FAILED: u8 = 2;
const ST_BAD: u8 = 3;

const R_UNKNOWN_CHRONICLE: u8 = 1;
const R_ALREADY_REGISTERED: u8 = 2;
const R_BAD_HASH: u8 = 3;
const R_NOT_HOLDER: u8 = 4;
const R_EPOCH_MISMATCH: u8 = 5;
const R_HEAD_MISMATCH: u8 = 6;
const R_LSN_NOT_NEXT: u8 = 7;
const R_SHIPPED_AHEAD: u8 = 8;
const R_SHIPPED_CONFLICT: u8 = 9;
const R_BAD_BATCH: u8 = 10;

/// How often the accept loop checks whether it should stop.
const ACCEPT_POLL: Duration = Duration::from_millis(10);

/// Default time a client waits for an answer before giving up.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

// ── Messages ────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
enum Request {
    Register { chronicle: ChronicleId, holder: WardenId },
    Append { warden: WardenId, envelope: Envelope },
    AppendBatch { warden: WardenId, envelopes: Vec<Envelope> },
    Transfer { chronicle: ChronicleId, new_holder: WardenId },
    Ownership { chronicle: ChronicleId },
    Head { chronicle: ChronicleId },
    AdvanceShipped { warden: WardenId, chronicle: ChronicleId, epoch: Epoch, to: Position },
    Shipped { chronicle: ChronicleId },
}

#[derive(Debug)]
enum Reply {
    Head(ChronicleHead),
    Epoch(Epoch),
    Ownership(Ownership),
    Position(Position),
    /// A refusal, or a server-side failure (always `outcome_unknown`).
    Err(CoordError),
    /// The server could not parse the request.
    Bad(String),
}

/// A request or reply body that cannot be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Malformed(&'static str);

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

// ── Encoding ────────────────────────────────────────────────────────

struct Out(Vec<u8>);

impl Out {
    fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    fn head(&mut self, h: &ChronicleHead) -> &mut Self {
        self.u64(h.lsn.get()).bytes(h.hash.as_bytes()).u64(h.epoch.get())
    }
    fn pos(&mut self, p: &Position) -> &mut Self {
        self.u64(p.lsn.get()).bytes(p.hash.as_bytes())
    }
    fn envelope(&mut self, e: &Envelope) -> &mut Self {
        self.bytes(e.chronicle.as_bytes())
            .u64(e.branch.get())
            .u64(e.epoch.get())
            .u8(e.stream as u8)
            .u64(e.lsn.get())
            .bytes(e.prev.as_bytes())
            .bytes(e.payload_hash.as_bytes())
            .bytes(e.hash.as_bytes())
    }
}

/// Reads fields front to back; every read checks the length.
struct In<'a> {
    b: &'a [u8],
}

impl<'a> In<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        if self.b.len() < n {
            return Err(Malformed("truncated"));
        }
        let (head, rest) = self.b.split_at(n);
        self.b = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64, Malformed> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")))
    }
    fn u32(&mut self) -> Result<u32, Malformed> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }
    fn hash(&mut self) -> Result<HashVal, Malformed> {
        Ok(HashVal::from_bytes(self.take(32)?.try_into().expect("32 bytes")))
    }
    fn chronicle(&mut self) -> Result<ChronicleId, Malformed> {
        Ok(ChronicleId::from_bytes(self.take(16)?.try_into().expect("16 bytes")))
    }
    fn warden(&mut self) -> Result<WardenId, Malformed> {
        Ok(WardenId::new(self.u64()?))
    }
    fn head(&mut self) -> Result<ChronicleHead, Malformed> {
        Ok(ChronicleHead { lsn: Lsn::new(self.u64()?), hash: self.hash()?, epoch: Epoch::new(self.u64()?) })
    }
    fn pos(&mut self) -> Result<Position, Malformed> {
        Ok(Position { lsn: Lsn::new(self.u64()?), hash: self.hash()? })
    }
    fn envelope(&mut self) -> Result<Envelope, Malformed> {
        let chronicle = self.chronicle()?;
        let branch = BranchId::new(self.u64()?);
        let epoch = Epoch::new(self.u64()?);
        let stream = match self.u8()? {
            0 => Stream::Fs,
            1 => Stream::Db,
            2 => Stream::Transcript,
            3 => Stream::Effect,
            4 => Stream::Ctl,
            _ => return Err(Malformed("unknown stream")),
        };
        // The hash is carried as sent; the coordinator verifies it.
        Ok(Envelope {
            chronicle,
            branch,
            epoch,
            stream,
            lsn: Lsn::new(self.u64()?),
            prev: self.hash()?,
            payload_hash: self.hash()?,
            hash: self.hash()?,
        })
    }
    fn text(&mut self) -> String {
        let s = String::from_utf8_lossy(self.b).into_owned();
        self.b = &[];
        s
    }
    fn end(&self) -> Result<(), Malformed> {
        if self.b.is_empty() {
            Ok(())
        } else {
            Err(Malformed("trailing bytes"))
        }
    }
}

impl Request {
    fn encode(&self) -> Vec<u8> {
        let mut o = Out(Vec::with_capacity(2 + 8 + 137));
        o.u8(WIRE_V1);
        match self {
            Self::Register { chronicle, holder } => o.u8(OP_REGISTER).bytes(chronicle.as_bytes()).u64(holder.get()),
            Self::Append { warden, envelope } => o.u8(OP_APPEND).u64(warden.get()).envelope(envelope),
            Self::AppendBatch { warden, envelopes } => {
                o.u8(OP_APPEND_BATCH).u64(warden.get()).u32(envelopes.len() as u32);
                for e in envelopes {
                    o.envelope(e);
                }
                &mut o
            }
            Self::Transfer { chronicle, new_holder } => {
                o.u8(OP_TRANSFER).bytes(chronicle.as_bytes()).u64(new_holder.get())
            }
            Self::Ownership { chronicle } => o.u8(OP_OWNERSHIP).bytes(chronicle.as_bytes()),
            Self::Head { chronicle } => o.u8(OP_HEAD).bytes(chronicle.as_bytes()),
            Self::AdvanceShipped { warden, chronicle, epoch, to } => o
                .u8(OP_ADVANCE_SHIPPED)
                .u64(warden.get())
                .bytes(chronicle.as_bytes())
                .u64(epoch.get())
                .pos(to),
            Self::Shipped { chronicle } => o.u8(OP_SHIPPED).bytes(chronicle.as_bytes()),
        };
        o.0
    }

    fn decode(body: &[u8]) -> Result<Self, Malformed> {
        let mut i = In { b: body };
        if i.u8()? != WIRE_V1 {
            return Err(Malformed("unknown protocol version"));
        }
        let req = match i.u8()? {
            OP_REGISTER => Self::Register { chronicle: i.chronicle()?, holder: i.warden()? },
            OP_APPEND => Self::Append { warden: i.warden()?, envelope: i.envelope()? },
            OP_APPEND_BATCH => {
                let warden = i.warden()?;
                let count = i.u32()?;
                if count > MAX_BATCH {
                    return Err(Malformed("batch too large"));
                }
                let envelopes = (0..count).map(|_| i.envelope()).collect::<Result<_, _>>()?;
                Self::AppendBatch { warden, envelopes }
            }
            OP_TRANSFER => Self::Transfer { chronicle: i.chronicle()?, new_holder: i.warden()? },
            OP_OWNERSHIP => Self::Ownership { chronicle: i.chronicle()? },
            OP_HEAD => Self::Head { chronicle: i.chronicle()? },
            OP_ADVANCE_SHIPPED => Self::AdvanceShipped {
                warden: i.warden()?,
                chronicle: i.chronicle()?,
                epoch: Epoch::new(i.u64()?),
                to: i.pos()?,
            },
            OP_SHIPPED => Self::Shipped { chronicle: i.chronicle()? },
            _ => return Err(Malformed("unknown operation")),
        };
        i.end()?;
        Ok(req)
    }

    /// What kind of reply body an `Ok` carries.
    fn ok_kind(&self) -> OkKind {
        match self {
            Self::Register { .. } | Self::Append { .. } | Self::AppendBatch { .. } | Self::Head { .. } => OkKind::Head,
            Self::Transfer { .. } => OkKind::Epoch,
            Self::Ownership { .. } => OkKind::Ownership,
            Self::AdvanceShipped { .. } | Self::Shipped { .. } => OkKind::Position,
        }
    }
}

#[derive(Clone, Copy)]
enum OkKind {
    Head,
    Epoch,
    Ownership,
    Position,
}

impl Reply {
    fn encode(&self) -> Vec<u8> {
        let mut o = Out(Vec::with_capacity(1 + 64));
        match self {
            Self::Head(h) => {
                o.u8(ST_OK).head(h);
            }
            Self::Epoch(e) => {
                o.u8(ST_OK).u64(e.get());
            }
            Self::Ownership(w) => {
                o.u8(ST_OK).u64(w.epoch.get()).u64(w.holder.get()).head(&w.sealed_prefix);
            }
            Self::Position(p) => {
                o.u8(ST_OK).pos(p);
            }
            Self::Err(e) => match encode_refusal(e) {
                Some(body) => {
                    o.u8(ST_REFUSED).bytes(&body);
                }
                None => {
                    o.u8(ST_FAILED).bytes(e.to_string().as_bytes());
                }
            },
            Self::Bad(why) => {
                o.u8(ST_BAD).bytes(why.as_bytes());
            }
        }
        o.0
    }

    fn decode(body: &[u8], kind: OkKind) -> Result<Self, Malformed> {
        let mut i = In { b: body };
        let reply = match i.u8()? {
            ST_OK => match kind {
                OkKind::Head => Self::Head(i.head()?),
                OkKind::Epoch => Self::Epoch(Epoch::new(i.u64()?)),
                OkKind::Ownership => Self::Ownership(Ownership {
                    epoch: Epoch::new(i.u64()?),
                    holder: i.warden()?,
                    sealed_prefix: i.head()?,
                }),
                OkKind::Position => Self::Position(i.pos()?),
            },
            ST_REFUSED => Self::Err(decode_refusal(&mut i)?),
            ST_FAILED => Self::Err(CoordError::Unavailable(io::Error::other(format!(
                "coordinator failed: {}",
                i.text()
            )))),
            ST_BAD => Self::Bad(i.text()),
            _ => return Err(Malformed("unknown status")),
        };
        i.end()?;
        Ok(reply)
    }
}

/// The wire form of a refusal; `None` for a failure whose outcome is
/// unknown.  Exhaustive, so a new variant must be given a wire form.
fn encode_refusal(e: &CoordError) -> Option<Vec<u8>> {
    let mut o = Out(Vec::with_capacity(1 + 64));
    match e {
        CoordError::UnknownChronicle(c) => o.u8(R_UNKNOWN_CHRONICLE).bytes(c.as_bytes()),
        CoordError::AlreadyRegistered(c) => o.u8(R_ALREADY_REGISTERED).bytes(c.as_bytes()),
        CoordError::BadHash { lsn } => o.u8(R_BAD_HASH).u64(lsn.get()),
        CoordError::NotHolder { warden, holder } => o.u8(R_NOT_HOLDER).u64(warden.get()).u64(holder.get()),
        CoordError::EpochMismatch { record_epoch, current } => {
            o.u8(R_EPOCH_MISMATCH).u64(record_epoch.get()).u64(current.get())
        }
        CoordError::HeadMismatch { prev, anchored } => {
            o.u8(R_HEAD_MISMATCH).bytes(prev.as_bytes()).bytes(anchored.as_bytes())
        }
        CoordError::LsnNotNext { lsn, expected } => o.u8(R_LSN_NOT_NEXT).u64(lsn.get()).u64(expected.get()),
        CoordError::ShippedAhead { to, head } => o.u8(R_SHIPPED_AHEAD).u64(to.get()).u64(head.get()),
        CoordError::ShippedConflict { lsn } => o.u8(R_SHIPPED_CONFLICT).u64(lsn.get()),
        CoordError::BadBatch { lsn } => o.u8(R_BAD_BATCH).u64(lsn.get()),
        CoordError::Corrupt { .. } | CoordError::Storage(_) | CoordError::Unavailable(_) => return None,
    };
    Some(o.0)
}

fn decode_refusal(i: &mut In<'_>) -> Result<CoordError, Malformed> {
    Ok(match i.u8()? {
        R_UNKNOWN_CHRONICLE => CoordError::UnknownChronicle(i.chronicle()?),
        R_ALREADY_REGISTERED => CoordError::AlreadyRegistered(i.chronicle()?),
        R_BAD_HASH => CoordError::BadHash { lsn: Lsn::new(i.u64()?) },
        R_NOT_HOLDER => CoordError::NotHolder { warden: i.warden()?, holder: i.warden()? },
        R_EPOCH_MISMATCH => {
            CoordError::EpochMismatch { record_epoch: Epoch::new(i.u64()?), current: Epoch::new(i.u64()?) }
        }
        R_HEAD_MISMATCH => CoordError::HeadMismatch { prev: i.hash()?, anchored: i.hash()? },
        R_LSN_NOT_NEXT => CoordError::LsnNotNext { lsn: Lsn::new(i.u64()?), expected: Lsn::new(i.u64()?) },
        R_SHIPPED_AHEAD => CoordError::ShippedAhead { to: Lsn::new(i.u64()?), head: Lsn::new(i.u64()?) },
        R_SHIPPED_CONFLICT => CoordError::ShippedConflict { lsn: Lsn::new(i.u64()?) },
        R_BAD_BATCH => CoordError::BadBatch { lsn: Lsn::new(i.u64()?) },
        _ => return Err(Malformed("unknown refusal")),
    })
}

// ── Server ──────────────────────────────────────────────────────────

/// Answer one request.
fn handle(coord: &dyn Coord, req: Request) -> Reply {
    let r = match req {
        Request::Register { chronicle, holder } => coord.register(chronicle, holder).map(Reply::Head),
        Request::Append { warden, envelope } => coord.append(warden, &envelope).map(Reply::Head),
        Request::AppendBatch { warden, envelopes } => coord.append_batch(warden, &envelopes).map(Reply::Head),
        Request::Transfer { chronicle, new_holder } => coord.transfer(chronicle, new_holder).map(Reply::Epoch),
        Request::Ownership { chronicle } => coord.ownership(chronicle).map(Reply::Ownership),
        Request::Head { chronicle } => coord.head(chronicle).map(Reply::Head),
        Request::AdvanceShipped { warden, chronicle, epoch, to } => {
            coord.advance_shipped(warden, chronicle, epoch, to).map(Reply::Position)
        }
        Request::Shipped { chronicle } => coord.shipped(chronicle).map(Reply::Position),
    };
    r.unwrap_or_else(Reply::Err)
}

/// Serve one connection until it closes, breaks, or sends garbage.
fn serve_conn(coord: &dyn Coord, mut stream: UnixStream) {
    loop {
        let body = match read_frame(&mut stream) {
            Ok(Some(b)) => b,
            // Clean end, or a broken connection: nothing to answer.
            Ok(None) | Err(ProtocolError::Io(_)) => return,
            Err(e) => {
                let _ = write_frame(&mut stream, &Reply::Bad(e.to_string()).encode());
                return;
            }
        };
        let reply = match Request::decode(&body) {
            Ok(req) => handle(coord, req),
            Err(m) => {
                let _ = write_frame(&mut stream, &Reply::Bad(m.to_string()).encode());
                return;
            }
        };
        if write_frame(&mut stream, &reply.encode()).is_err() {
            return;
        }
    }
}

/// A coordinator served on a Unix socket.  Stops (and removes the socket)
/// on [`Server::stop`] or drop; when it has stopped, every connection
/// thread has ended and dropped its handle on the coordinator.
pub struct Server {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    /// Live connections, by id; each worker removes its own on exit.
    conns: Arc<Mutex<HashMap<u64, UnixStream>>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    accept: Option<JoinHandle<()>>,
}

impl Server {
    /// Bind `path` (mode 0600) and serve `coord` on it, one thread per
    /// connection.  A stale socket file is replaced; a socket another
    /// server is still answering on is refused (`AddrInUse`).
    pub fn spawn(path: impl AsRef<Path>, coord: Arc<dyn Coord>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_socket() => {
                if UnixStream::connect(&path).is_ok() {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!("{} is served by a live coordinator", path.display()),
                    ));
                }
                std::fs::remove_file(&path)?;
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", path.display()),
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        // The accept loop polls, so stopping never depends on the socket
        // file still being there to connect to.
        listener.set_nonblocking(true)?;

        let stop = Arc::new(AtomicBool::new(false));
        let conns: Arc<Mutex<HashMap<u64, UnixStream>>> = Arc::default();
        let workers: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
        let accept = {
            let (stop, conns, workers) = (stop.clone(), conns.clone(), workers.clone());
            std::thread::spawn(move || {
                let mut next_id = 0u64;
                while !stop.load(Ordering::SeqCst) {
                    let stream = match listener.accept() {
                        Ok((s, _)) => s,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(ACCEPT_POLL);
                            continue;
                        }
                        Err(_) => continue,
                    };
                    // Connections block; only the listener polls.
                    if stream.set_nonblocking(false).is_err() {
                        continue;
                    }
                    let Ok(handle) = stream.try_clone() else { continue };
                    let id = next_id;
                    next_id += 1;
                    conns.lock().expect("conns").insert(id, handle);
                    let (coord, conns_w) = (coord.clone(), conns.clone());
                    let w = std::thread::spawn(move || {
                        serve_conn(coord.as_ref(), stream);
                        conns_w.lock().expect("conns").remove(&id);
                    });
                    let mut ws = workers.lock().expect("workers");
                    ws.retain(|w| !w.is_finished());
                    ws.push(w);
                }
            })
        };
        Ok(Self { path, stop, conns, workers, accept: Some(accept) })
    }

    /// The socket path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stop accepting, close every connection, wait for every thread, and
    /// remove the socket.  A request being handled finishes first; its
    /// reply may be lost, which the client sees as `Unavailable`.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        let Some(accept) = self.accept.take() else { return };
        self.stop.store(true, Ordering::SeqCst);
        let _ = accept.join();
        for c in self.conns.lock().expect("conns").values() {
            let _ = c.shutdown(std::net::Shutdown::Both);
        }
        for w in self.workers.lock().expect("workers").drain(..) {
            let _ = w.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// ── Client ──────────────────────────────────────────────────────────

/// A [`Coord`] served by a [`Server`].
///
/// Concurrent callers each get their own connection, so their requests are
/// in flight together and the server can group-commit them; one connection
/// carries one request at a time.  Idle connections are kept for reuse
/// (at most [`MAX_IDLE`]).  Any failure to get an answer is
/// [`CoordError::Unavailable`]; that connection is dropped, never reused,
/// and the next call opens a new one.  Nothing is retried.
pub struct RemoteCoord {
    path: PathBuf,
    timeout: Duration,
    idle: Mutex<Vec<UnixStream>>,
}

/// Idle connections a [`RemoteCoord`] keeps; more are closed when freed.
pub const MAX_IDLE: usize = 128;

impl RemoteCoord {
    /// A client for the server at `path`, waiting at most
    /// [`DEFAULT_TIMEOUT`] for each answer.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_timeout(path, DEFAULT_TIMEOUT)
    }

    /// A client waiting at most `timeout` for each answer.
    pub fn with_timeout(path: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self { path: path.into(), timeout, idle: Mutex::new(Vec::new()) }
    }

    /// An idle connection, or a new one.
    fn checkout(&self) -> Result<UnixStream, CoordError> {
        if let Some(s) = self.idle.lock().unwrap_or_else(|p| p.into_inner()).pop() {
            return Ok(s);
        }
        // An interrupted connect left nothing behind (a new socket each
        // try): retry it.  See `read_frame` on EINTR.
        let s = loop {
            match UnixStream::connect(&self.path) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                other => break other.map_err(CoordError::Unavailable)?,
            }
        };
        s.set_read_timeout(Some(self.timeout)).map_err(CoordError::Unavailable)?;
        s.set_write_timeout(Some(self.timeout)).map_err(CoordError::Unavailable)?;
        Ok(s)
    }

    /// Give a connection that just answered cleanly back for reuse.
    fn checkin(&self, s: UnixStream) {
        let mut idle = self.idle.lock().unwrap_or_else(|p| p.into_inner());
        if idle.len() < MAX_IDLE {
            idle.push(s);
        }
    }

    fn call(&self, req: Request) -> Result<Reply, CoordError> {
        let mut stream = self.checkout()?;
        let result = (|| {
            write_frame(&mut stream, &req.encode()).map_err(unavailable)?;
            let body = read_frame(&mut stream)
                .map_err(unavailable)?
                .ok_or_else(|| CoordError::Unavailable(io::Error::from(io::ErrorKind::UnexpectedEof)))?;
            Reply::decode(&body, req.ok_kind())
                .map_err(|m| CoordError::Unavailable(io::Error::new(io::ErrorKind::InvalidData, m.0)))
        })();
        match result {
            Ok(Reply::Bad(why)) => {
                // The server could not read our request and closed: a bug
                // on one side.  Nothing was applied, but report it as
                // unavailable rather than invent a refusal.  The
                // connection is dropped.
                Err(CoordError::Unavailable(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("coordinator rejected the request: {why}"),
                )))
            }
            Ok(reply) => {
                self.checkin(stream);
                Ok(reply)
            }
            // The connection is dropped: whatever it holds is not trusted.
            Err(e) => Err(e),
        }
    }
}

fn unavailable(e: ProtocolError) -> CoordError {
    match e {
        ProtocolError::Io(e) => CoordError::Unavailable(e),
        other => CoordError::Unavailable(io::Error::new(io::ErrorKind::InvalidData, other.to_string())),
    }
}

fn unexpected(r: Reply) -> CoordError {
    CoordError::Unavailable(io::Error::new(io::ErrorKind::InvalidData, format!("unexpected reply {r:?}")))
}

impl Coord for RemoteCoord {
    fn register(&self, chronicle: ChronicleId, holder: WardenId) -> Result<ChronicleHead, CoordError> {
        match self.call(Request::Register { chronicle, holder })? {
            Reply::Head(h) => Ok(h),
            Reply::Err(e) => Err(e),
            r => Err(unexpected(r)),
        }
    }

    fn append(&self, warden: WardenId, envelope: &Envelope) -> Result<ChronicleHead, CoordError> {
        match self.call(Request::Append { warden, envelope: *envelope })? {
            Reply::Head(h) => Ok(h),
            Reply::Err(e) => Err(e),
            r => Err(unexpected(r)),
        }
    }

    fn append_batch(&self, warden: WardenId, envelopes: &[Envelope]) -> Result<ChronicleHead, CoordError> {
        if envelopes.len() > MAX_BATCH as usize {
            return Err(CoordError::BadBatch { lsn: envelopes[MAX_BATCH as usize].lsn });
        }
        match self.call(Request::AppendBatch { warden, envelopes: envelopes.to_vec() })? {
            Reply::Head(h) => Ok(h),
            Reply::Err(e) => Err(e),
            r => Err(unexpected(r)),
        }
    }

    fn transfer(&self, chronicle: ChronicleId, new_holder: WardenId) -> Result<Epoch, CoordError> {
        match self.call(Request::Transfer { chronicle, new_holder })? {
            Reply::Epoch(e) => Ok(e),
            Reply::Err(e) => Err(e),
            r => Err(unexpected(r)),
        }
    }

    fn ownership(&self, chronicle: ChronicleId) -> Result<Ownership, CoordError> {
        match self.call(Request::Ownership { chronicle })? {
            Reply::Ownership(o) => Ok(o),
            Reply::Err(e) => Err(e),
            r => Err(unexpected(r)),
        }
    }

    fn head(&self, chronicle: ChronicleId) -> Result<ChronicleHead, CoordError> {
        match self.call(Request::Head { chronicle })? {
            Reply::Head(h) => Ok(h),
            Reply::Err(e) => Err(e),
            r => Err(unexpected(r)),
        }
    }

    fn advance_shipped(
        &self,
        warden: WardenId,
        chronicle: ChronicleId,
        epoch: Epoch,
        to: Position,
    ) -> Result<Position, CoordError> {
        match self.call(Request::AdvanceShipped { warden, chronicle, epoch, to })? {
            Reply::Position(p) => Ok(p),
            Reply::Err(e) => Err(e),
            r => Err(unexpected(r)),
        }
    }

    fn shipped(&self, chronicle: ChronicleId) -> Result<Position, CoordError> {
        match self.call(Request::Shipped { chronicle })? {
            Reply::Position(p) => Ok(p),
            Reply::Err(e) => Err(e),
            r => Err(unexpected(r)),
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::{conformance, Coordinator};
    use proptest::prelude::*;
    use std::io::Write;
    use taso_core::model::WardenModel;
    use taso_core::record::Payload;

    const A: WardenId = WardenId::new(1);
    const B: WardenId = WardenId::new(2);

    fn chron(n: u8) -> ChronicleId {
        ChronicleId::from_bytes([n; 16])
    }

    struct Env {
        server: Option<Server>,
        dir: tempfile::TempDir,
    }

    impl Env {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let mut e = Self { server: None, dir };
            e.start();
            e
        }
        fn db(&self) -> PathBuf {
            self.dir.path().join("coord.redb")
        }
        fn sock(&self) -> PathBuf {
            self.dir.path().join("coord.sock")
        }
        fn start(&mut self) {
            let coord: Arc<dyn Coord> = Arc::new(Coordinator::open(self.db()).unwrap());
            self.server = Some(Server::spawn(self.sock(), coord).unwrap());
        }
        fn stop(&mut self) {
            if let Some(s) = self.server.take() {
                s.stop();
            }
        }
        fn client(&self) -> RemoteCoord {
            RemoteCoord::with_timeout(self.sock(), Duration::from_secs(5))
        }
    }

    fn record(w: &WardenModel, n: u8) -> Envelope {
        w.build_record(Stream::Fs, Payload::Raw(vec![n; 4])).envelope
    }

    // ── through the socket ──────────────────────────────────────────

    #[test]
    fn calls_round_trip() {
        let e = Env::new();
        let c = e.client();
        let g = c.register(chron(1), A).unwrap();
        assert_eq!((g.lsn, g.hash, g.epoch), (Lsn::new(0), HashVal::GENESIS, Epoch::FIRST));
        let w = WardenModel::resume(A, chron(1), Epoch::FIRST, g, Lsn::new(1));
        let h = c.append(A, &record(&w, 1)).unwrap();
        assert_eq!(h.lsn, Lsn::new(1));
        assert_eq!(c.head(chron(1)).unwrap(), h);
        assert_eq!(c.transfer(chron(1), B).unwrap(), Epoch::new(2));
        let o = c.ownership(chron(1)).unwrap();
        assert_eq!((o.epoch, o.holder, o.sealed_prefix.lsn), (Epoch::new(2), B, Lsn::new(1)));
    }

    #[test]
    fn refusals_arrive_field_for_field() {
        let e = Env::new();
        let c = e.client();
        assert!(matches!(c.head(chron(9)), Err(CoordError::UnknownChronicle(x)) if x == chron(9)));
        c.register(chron(1), A).unwrap();
        assert!(matches!(c.register(chron(1), B), Err(CoordError::AlreadyRegistered(x)) if x == chron(1)));
        let w = WardenModel::new(B, chron(1), Epoch::FIRST);
        assert!(matches!(
            c.append(B, &record(&w, 1)),
            Err(CoordError::NotHolder { warden, holder }) if warden == B && holder == A
        ));
        // A refusal does not close the connection.
        assert_eq!(c.head(chron(1)).unwrap().lsn, Lsn::new(0));
    }

    /// Every refusal survives encode → decode exactly; every failure is
    /// sent as "failed" and arrives with an unknown outcome.
    #[test]
    fn every_error_has_a_wire_form() {
        let h = HashVal::from_bytes([3; 32]);
        let refusals = [
            CoordError::UnknownChronicle(chron(1)),
            CoordError::AlreadyRegistered(chron(2)),
            CoordError::BadHash { lsn: Lsn::new(7) },
            CoordError::NotHolder { warden: A, holder: B },
            CoordError::EpochMismatch { record_epoch: Epoch::new(1), current: Epoch::new(4) },
            CoordError::HeadMismatch { prev: h, anchored: HashVal::GENESIS },
            CoordError::LsnNotNext { lsn: Lsn::new(9), expected: Lsn::new(2) },
            CoordError::ShippedAhead { to: Lsn::new(6), head: Lsn::new(5) },
            CoordError::ShippedConflict { lsn: Lsn::new(5) },
        ];
        for e in refusals {
            let body = Reply::Err(e).encode();
            let Reply::Err(back) = Reply::decode(&body, OkKind::Head).unwrap() else { panic!() };
            assert_eq!(Reply::Err(back).encode(), body);
        }
        let failures = [
            CoordError::Corrupt { chronicle: chron(1), reason: "x" },
            CoordError::Storage(redb::Error::Corrupted("x".into())),
            CoordError::Unavailable(io::Error::other("x")),
        ];
        for e in failures {
            let body = Reply::Err(e).encode();
            assert_eq!(body[0], ST_FAILED);
            let Reply::Err(back) = Reply::decode(&body, OkKind::Head).unwrap() else { panic!() };
            assert!(back.outcome_unknown(), "{back:?}");
        }
    }

    #[test]
    fn requests_round_trip_and_junk_is_rejected() {
        let w = WardenModel::new(A, chron(1), Epoch::FIRST);
        let reqs = [
            Request::Register { chronicle: chron(1), holder: A },
            Request::Append { warden: A, envelope: record(&w, 1) },
            Request::Transfer { chronicle: chron(1), new_holder: B },
            Request::Ownership { chronicle: chron(1) },
            Request::Head { chronicle: chron(1) },
            Request::AdvanceShipped {
                warden: A,
                chronicle: chron(1),
                epoch: Epoch::new(3),
                to: Position { lsn: Lsn::new(4), hash: HashVal::from_bytes([4; 32]) },
            },
            Request::Shipped { chronicle: chron(1) },
            Request::AppendBatch { warden: A, envelopes: vec![record(&w, 1), record(&w, 1)] },
            Request::AppendBatch { warden: A, envelopes: vec![] },
        ];
        for r in reqs.clone() {
            let b = r.encode();
            assert_eq!(Request::decode(&b), Ok(r.clone()));
            assert!(Request::decode(&b[..b.len() - 1]).is_err(), "truncated {r:?}");
            let mut extra = b.clone();
            extra.push(0);
            assert!(Request::decode(&extra).is_err(), "trailing {r:?}");
            let mut v2 = b.clone();
            v2[0] = 2;
            assert!(Request::decode(&v2).is_err(), "version {r:?}");
        }
        let mut bad_stream = reqs[1].encode();
        bad_stream[2 + 8 + 32] = 9; // the envelope's stream byte
        assert_eq!(Request::decode(&bad_stream), Err(Malformed("unknown stream")));
        assert!(Request::decode(&[WIRE_V1, 99]).is_err());
        assert!(Request::decode(&[]).is_err());
        // A batch larger than MAX_BATCH is malformed before it is read.
        let mut huge = vec![WIRE_V1, OP_APPEND_BATCH];
        huge.extend_from_slice(&A.get().to_be_bytes());
        huge.extend_from_slice(&(MAX_BATCH + 1).to_be_bytes());
        assert_eq!(Request::decode(&huge), Err(Malformed("batch too large")));
    }

    /// A batch over the socket: accepted whole, or refused whole with the
    /// coordinator's own refusal.
    #[test]
    fn batches_cross_the_socket() {
        let e = Env::new();
        let c = e.client();
        c.register(chron(1), A).unwrap();
        let w = WardenModel::new(A, chron(1), Epoch::FIRST);
        let first = record(&w, 1);
        let w2 = WardenModel::resume(A, chron(1), Epoch::FIRST, ChronicleHead { lsn: first.lsn, hash: first.hash, epoch: Epoch::FIRST }, first.lsn.next());
        let second = w2.build_record(Stream::Fs, Payload::Raw(vec![2])).envelope;
        let h = c.append_batch(A, &[first, second]).unwrap();
        assert_eq!((h.lsn, h.hash), (Lsn::new(2), second.hash));
        assert!(matches!(c.append_batch(A, &[first]), Err(CoordError::HeadMismatch { .. })));
        assert!(matches!(c.append_batch(A, &[]), Err(CoordError::BadBatch { .. })));
        assert_eq!(c.head(chron(1)).unwrap(), h);
    }

    /// Garbage is answered "bad", the connection closed, the state untouched.
    #[test]
    fn garbage_is_refused_without_touching_state() {
        let e = Env::new();
        let c = e.client();
        c.register(chron(1), A).unwrap();
        let before = c.ownership(chron(1)).unwrap();

        let mut s = UnixStream::connect(e.sock()).unwrap();
        // A transfer request with one byte missing.
        let req = Request::Transfer { chronicle: chron(1), new_holder: B }.encode();
        write_frame(&mut s, &req[..req.len() - 1]).unwrap();
        let reply = read_frame(&mut s).unwrap().unwrap();
        assert_eq!(reply[0], ST_BAD);
        assert_eq!(read_frame(&mut s).unwrap(), None, "server closed the connection");
        // An oversized frame header.
        let mut s = UnixStream::connect(e.sock()).unwrap();
        s.write_all(&u32::MAX.to_be_bytes()).unwrap();
        assert_eq!(read_frame(&mut s).unwrap().unwrap()[0], ST_BAD);

        let after = c.ownership(chron(1)).unwrap();
        assert_eq!((before.epoch, before.holder), (after.epoch, after.holder));
    }

    /// The server goes away: calls fail as unavailable (unknown outcome);
    /// after a restart on the same file the same client carries on, and
    /// the state is intact.
    #[test]
    fn server_restart_is_unavailable_then_reconnects() {
        let mut e = Env::new();
        let c = e.client();
        c.register(chron(1), A).unwrap();
        e.stop();
        let err = c.head(chron(1)).unwrap_err();
        assert!(matches!(err, CoordError::Unavailable(_)) && err.outcome_unknown(), "{err:?}");
        e.start();
        assert_eq!(c.ownership(chron(1)).unwrap().holder, A);
    }

    /// The connection breaks after the server has read the request: the
    /// client cannot know whether it was applied, and says so.
    #[test]
    fn answer_lost_is_unknown_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("mute.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let t = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let got = read_frame(&mut s).unwrap().unwrap();
            drop(s); // read, maybe applied, never answered
            got
        });
        let c = RemoteCoord::with_timeout(&sock, Duration::from_secs(5));
        let w = WardenModel::new(A, chron(1), Epoch::FIRST);
        let env = record(&w, 1);
        let err = c.append(A, &env).unwrap_err();
        assert!(matches!(err, CoordError::Unavailable(_)) && err.outcome_unknown(), "{err:?}");
        assert_eq!(Request::decode(&t.join().unwrap()), Ok(Request::Append { warden: A, envelope: env }));
    }

    /// A server that never answers: the client times out as unavailable.
    /// A coordinator that holds every `head` for `delay` and records how
    /// many it is answering at once.
    struct Slow {
        inner: Coordinator,
        delay: Duration,
        now: std::sync::atomic::AtomicUsize,
        most: std::sync::atomic::AtomicUsize,
    }
    impl Coord for Slow {
        fn register(&self, c: ChronicleId, h: WardenId) -> Result<ChronicleHead, CoordError> {
            self.inner.register(c, h)
        }
        fn append(&self, w: WardenId, e: &Envelope) -> Result<ChronicleHead, CoordError> {
            self.inner.append(w, e)
        }
        fn append_batch(&self, w: WardenId, e: &[Envelope]) -> Result<ChronicleHead, CoordError> {
            self.inner.append_batch(w, e)
        }
        fn transfer(&self, c: ChronicleId, h: WardenId) -> Result<Epoch, CoordError> {
            self.inner.transfer(c, h)
        }
        fn ownership(&self, c: ChronicleId) -> Result<Ownership, CoordError> {
            self.inner.ownership(c)
        }
        fn head(&self, c: ChronicleId) -> Result<ChronicleHead, CoordError> {
            use std::sync::atomic::Ordering::SeqCst;
            let n = self.now.fetch_add(1, SeqCst) + 1;
            self.most.fetch_max(n, SeqCst);
            std::thread::sleep(self.delay);
            self.now.fetch_sub(1, SeqCst);
            self.inner.head(c)
        }
        fn advance_shipped(&self, w: WardenId, c: ChronicleId, e: Epoch, to: Position) -> Result<Position, CoordError> {
            self.inner.advance_shipped(w, c, e, to)
        }
        fn shipped(&self, c: ChronicleId) -> Result<Position, CoordError> {
            self.inner.shipped(c)
        }
    }

    /// Concurrent callers of one client are served concurrently (each on
    /// its own connection), so the server can group their writes; a
    /// connection that answered is reused, not reopened.
    #[test]
    fn concurrent_calls_are_in_flight_together() {
        let dir = tempfile::tempdir().unwrap();
        let slow = Arc::new(Slow {
            inner: Coordinator::open(dir.path().join("c.redb")).unwrap(),
            delay: Duration::from_millis(200),
            now: Default::default(),
            most: Default::default(),
        });
        let _server = Server::spawn(dir.path().join("c.sock"), slow.clone()).unwrap();
        let c = Arc::new(RemoteCoord::with_timeout(dir.path().join("c.sock"), Duration::from_secs(5)));
        c.register(chron(1), A).unwrap();
        let t0 = std::time::Instant::now();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let c = c.clone();
                std::thread::spawn(move || c.head(chron(1)).unwrap())
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let took = t0.elapsed();
        assert_eq!(slow.most.load(std::sync::atomic::Ordering::SeqCst), 8, "all eight at once");
        assert!(took < Duration::from_millis(800), "not one after another: {took:?}");
        let idle = c.idle.lock().unwrap().len();
        assert_eq!(idle, 8, "each connection kept for reuse");
        c.head(chron(1)).unwrap();
        assert_eq!(c.idle.lock().unwrap().len(), 8, "reused, not a ninth");
    }

    #[test]
    fn silent_server_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("silent.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let t = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let _ = read_frame(&mut s);
            std::thread::sleep(Duration::from_millis(500));
        });
        let c = RemoteCoord::with_timeout(&sock, Duration::from_millis(100));
        let err = c.head(chron(1)).unwrap_err();
        assert!(err.outcome_unknown(), "{err:?}");
        t.join().unwrap();
    }

    #[test]
    fn a_live_socket_is_not_taken_over() {
        let e = Env::new();
        let other: Arc<dyn Coord> = Arc::new(Coordinator::open(e.dir.path().join("other.redb")).unwrap());
        let err = Server::spawn(e.sock(), other).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        assert!(e.client().register(chron(1), A).is_ok());
    }

    #[test]
    fn stale_socket_is_replaced_and_stop_cleans_up() {
        let mut e = Env::new();
        e.stop();
        // A socket file nobody answers on.
        let stale = UnixListener::bind(e.sock()).unwrap();
        drop(stale);
        assert!(e.sock().exists());
        e.start();
        assert!(e.client().register(chron(1), A).is_ok());
        e.stop();
        assert!(!e.sock().exists());
        // And the redb file is free again: every handle was dropped.
        Coordinator::open(e.db()).unwrap();
    }

    /// Stopping must not depend on the socket file: someone may have
    /// removed it.  (The first version woke the accept loop by connecting
    /// to it, and hung here.)
    #[test]
    fn stop_does_not_need_the_socket_file() {
        let mut e = Env::new();
        e.client().register(chron(1), A).unwrap();
        std::fs::remove_file(e.sock()).unwrap();
        e.stop();
        Coordinator::open(e.db()).unwrap();
    }

    // ── conformance: the socket coordinator == the model ────────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// `Reopen` stops the server and starts a new one on the same redb
        /// file, so every reopen also proves the file was released.
        #[test]
        fn socket_coordinator_matches_model(ops in conformance::ops()) {
            let mut e = Env::new();
            let mut first = true;
            conformance::run(ops, &mut || {
                if !first {
                    e.stop();
                    e.start();
                }
                first = false;
                Box::new(e.client())
            })?;
        }
    }
}
