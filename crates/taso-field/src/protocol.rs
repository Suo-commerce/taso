//! The Field wire protocol: what a Vessel and its Warden say to each other
//! over the per-Vessel Unix socket (v1.0 §3, v0.4 §7.1).
//!
//! # What crosses, and what cannot
//!
//! The Vessel sends [`Request`]s, the Warden answers each with exactly one
//! [`Reply`], in order.  Four things cross:
//!
//! - **Hello**: protocol version.  The client does *not* say which Vessel
//!   it is; the Warden knows that from which socket it is (each Vessel has
//!   its own, in its own namespace).  There is no identity field to spoof.
//! - **Effect**: `provider`, `operation`, opaque `args`.  There are no
//!   fields for consequence, footprint, retry or class — the Warden's
//!   adapter assigns all of them (v0.4 §7.1), so a tool cannot declare
//!   anything, because the protocol has nowhere to put it.
//! - **Transcript**: one opaque transcript entry, recorded as a Chronicle
//!   record.  A quiescent restart rebuilds the agent from the transcript
//!   (v0.4 §5.4).
//! - **TurnEnd**: the harness's turn boundary and whether it is quiescent
//!   (no open database transaction); the Warden seals there if it may
//!   (v1.0 §3).
//!
//! # Framing and encoding
//!
//! A frame is a big-endian `u32` body length followed by the body.  Bodies
//! larger than [`MAX_FRAME`] are refused before anything is allocated.  A
//! body is a `u8` message tag and its fields: integers little-endian,
//! byte strings and strings as a `u64` length and the bytes, enums as a
//! `u8` tag, options as tag `0`/`1`.  Decoding is strict: unknown tags,
//! non-`0`/`1` bools, invalid UTF-8, truncation and trailing bytes are all
//! refused.

use std::fmt;
use std::io::{self, Read, Write};

/// The protocol version this crate speaks.
pub const VERSION: u16 = 1;

/// Largest frame body accepted, in bytes.
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

// ── Messages ────────────────────────────────────────────────────────

/// Vessel → Warden.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Open the conversation (tag 0).  Must be the first request.
    Hello {
        /// The client's protocol version.
        version: u16,
    },
    /// Ask for an external effect (tag 1).
    Effect {
        /// Client-chosen correlation id, echoed in the reply.  Not an
        /// operation identity: the adapter assigns that.
        call: u64,
        /// Which provider (`"mail"`, `"http"`, `"git"`, …).
        provider: String,
        /// Which operation of that provider.
        operation: String,
        /// The operation's arguments, opaque to the protocol.
        args: Vec<u8>,
    },
    /// Record one transcript entry (tag 2).
    Transcript {
        /// The entry, opaque.
        entry: Vec<u8>,
    },
    /// A turn ended (tag 3).
    TurnEnd {
        /// The harness's turn number.
        turn: u64,
        /// True if the harness has no open database transaction.
        quiescent: bool,
    },
}

/// Warden → Vessel: exactly one per request, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// Answer to `Hello` (tag 0).
    Hello {
        /// The Warden's protocol version.
        version: u16,
        /// The last turn the Chronicle has a Seal for, if any.  A harness
        /// resuming after a restart continues after it.
        last_sealed_turn: Option<u64>,
    },
    /// Answer to `Effect` (tag 1).
    Effect {
        /// The request's correlation id.
        call: u64,
        /// What happened.
        result: EffectResult,
    },
    /// Answer to `Transcript` (tag 2): the entry is durable.
    Recorded {
        /// Its lsn in the Chronicle.
        lsn: u64,
    },
    /// Answer to `TurnEnd` (tag 3).
    TurnEnd {
        /// The turn.
        turn: u64,
        /// The Seal's lsn, or `None` if the Warden did not seal (not
        /// quiescent, or nothing changed).
        sealed: Option<u64>,
    },
    /// The request was refused (tag 4).
    Error {
        /// Why, for programs.
        code: ErrorCode,
        /// Why, for people.
        message: String,
    },
}

/// The result of an effect request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectResult {
    /// The provider confirmed it happened (tag 0).
    Applied {
        /// Provider receipt, opaque.
        receipt: Vec<u8>,
    },
    /// The provider confirmed it did not happen (tag 1).
    NotApplied {
        /// Why.
        reason: String,
    },
    /// It may or may not have happened; the Warden will reconcile it before
    /// granting effect authority again (tag 2).
    Unknown,
    /// Refused before dispatch: no adapter, quota, no effect authority
    /// (tag 3).
    Refused {
        /// Why.
        reason: String,
    },
}

/// Why a request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    /// The first request was not `Hello`, or the version is unsupported.
    BadHello = 0,
    /// The request could not be decoded.
    Malformed = 1,
    /// The Vessel is closed (it has a successor).
    Closed = 2,
    /// The Warden lost ownership of this Vessel.
    Fenced = 3,
    /// Something failed inside the Warden.
    Internal = 4,
}

// ── Errors ──────────────────────────────────────────────────────────

/// Why a frame or body could not be read.
#[derive(Debug)]
pub enum ProtocolError {
    /// The socket failed, or ended in the middle of a frame.
    Io(io::Error),
    /// The frame is larger than [`MAX_FRAME`].
    TooLarge(u32),
    /// The body is not a valid message.
    Malformed {
        /// Byte offset in the body.
        at: usize,
        /// What is wrong.
        why: &'static str,
    },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::TooLarge(n) => write!(f, "frame of {n} bytes exceeds {MAX_FRAME}"),
            Self::Malformed { at, why } => write!(f, "malformed message at byte {at}: {why}"),
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ProtocolError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

// ── Framing ─────────────────────────────────────────────────────────

/// Write one frame and flush.
pub fn write_frame(w: &mut impl Write, body: &[u8]) -> Result<(), ProtocolError> {
    let len = u32::try_from(body.len())
        .ok()
        .filter(|&n| n <= MAX_FRAME)
        .ok_or(ProtocolError::TooLarge(u32::MAX))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(body)?;
    w.flush()?;
    Ok(())
}

/// Read one frame.  `Ok(None)` on a clean end of stream between frames;
/// an end inside a frame is an error.
pub fn read_frame(r: &mut impl Read) -> Result<Option<Vec<u8>>, ProtocolError> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match r.read(&mut len[got..])? {
            0 if got == 0 => return Ok(None),
            0 => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            n => got += n,
        }
    }
    let len = u32::from_be_bytes(len);
    if len > MAX_FRAME {
        return Err(ProtocolError::TooLarge(len));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Send a request.
pub fn send_request(w: &mut impl Write, req: &Request) -> Result<(), ProtocolError> {
    write_frame(w, &req.encode())
}

/// Receive a request; `Ok(None)` when the client closed the socket.
pub fn recv_request(r: &mut impl Read) -> Result<Option<Request>, ProtocolError> {
    read_frame(r)?.map(|b| Request::decode(&b)).transpose()
}

/// Send a reply.
pub fn send_reply(w: &mut impl Write, reply: &Reply) -> Result<(), ProtocolError> {
    write_frame(w, &reply.encode())
}

/// Receive a reply; `Ok(None)` when the Warden closed the socket.
pub fn recv_reply(r: &mut impl Read) -> Result<Option<Reply>, ProtocolError> {
    read_frame(r)?.map(|b| Reply::decode(&b)).transpose()
}

// ── Encoding ────────────────────────────────────────────────────────

#[derive(Default)]
struct Out(Vec<u8>);

impl Out {
    fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(v as u8)
    }
    fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.u64(v.len() as u64);
        self.0.extend_from_slice(v);
        self
    }
    fn str(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }
    fn opt_u64(&mut self, v: Option<u64>) -> &mut Self {
        match v {
            None => self.u8(0),
            Some(x) => self.u8(1).u64(x),
        }
    }
}

impl Request {
    /// The message body.
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Out::default();
        match self {
            Self::Hello { version } => {
                o.u8(0).u16(*version);
            }
            Self::Effect { call, provider, operation, args } => {
                o.u8(1).u64(*call).str(provider).str(operation).bytes(args);
            }
            Self::Transcript { entry } => {
                o.u8(2).bytes(entry);
            }
            Self::TurnEnd { turn, quiescent } => {
                o.u8(3).u64(*turn).bool(*quiescent);
            }
        }
        o.0
    }

    /// Decode a message body, strictly.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut r = In::new(body);
        let req = match r.tag()? {
            0 => Self::Hello { version: r.u16()? },
            1 => Self::Effect {
                call: r.u64()?,
                provider: r.string()?,
                operation: r.string()?,
                args: r.bytes()?,
            },
            2 => Self::Transcript { entry: r.bytes()? },
            3 => Self::TurnEnd { turn: r.u64()?, quiescent: r.bool()? },
            _ => return Err(r.bad_tag("unknown request tag")),
        };
        r.finish()?;
        Ok(req)
    }
}

impl Reply {
    /// The message body.
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Out::default();
        match self {
            Self::Hello { version, last_sealed_turn } => {
                o.u8(0).u16(*version).opt_u64(*last_sealed_turn);
            }
            Self::Effect { call, result } => {
                o.u8(1).u64(*call);
                match result {
                    EffectResult::Applied { receipt } => o.u8(0).bytes(receipt),
                    EffectResult::NotApplied { reason } => o.u8(1).str(reason),
                    EffectResult::Unknown => o.u8(2),
                    EffectResult::Refused { reason } => o.u8(3).str(reason),
                };
            }
            Self::Recorded { lsn } => {
                o.u8(2).u64(*lsn);
            }
            Self::TurnEnd { turn, sealed } => {
                o.u8(3).u64(*turn).opt_u64(*sealed);
            }
            Self::Error { code, message } => {
                o.u8(4).u8(*code as u8).str(message);
            }
        }
        o.0
    }

    /// Decode a message body, strictly.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut r = In::new(body);
        let reply = match r.tag()? {
            0 => Self::Hello { version: r.u16()?, last_sealed_turn: r.opt_u64()? },
            1 => {
                let call = r.u64()?;
                let result = match r.tag()? {
                    0 => EffectResult::Applied { receipt: r.bytes()? },
                    1 => EffectResult::NotApplied { reason: r.string()? },
                    2 => EffectResult::Unknown,
                    3 => EffectResult::Refused { reason: r.string()? },
                    _ => return Err(r.bad_tag("unknown effect result tag")),
                };
                Self::Effect { call, result }
            }
            2 => Self::Recorded { lsn: r.u64()? },
            3 => Self::TurnEnd { turn: r.u64()?, sealed: r.opt_u64()? },
            4 => {
                let code = match r.tag()? {
                    0 => ErrorCode::BadHello,
                    1 => ErrorCode::Malformed,
                    2 => ErrorCode::Closed,
                    3 => ErrorCode::Fenced,
                    4 => ErrorCode::Internal,
                    _ => return Err(r.bad_tag("unknown error code")),
                };
                Self::Error { code, message: r.string()? }
            }
            _ => return Err(r.bad_tag("unknown reply tag")),
        };
        r.finish()?;
        Ok(reply)
    }
}

// ── Decoding ────────────────────────────────────────────────────────

struct In<'a> {
    b: &'a [u8],
    pos: usize,
    /// Offset of the last tag read, for `bad_tag`.
    last_tag: usize,
}

impl<'a> In<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0, last_tag: 0 }
    }

    fn err(&self, at: usize, why: &'static str) -> ProtocolError {
        ProtocolError::Malformed { at, why }
    }

    fn take(&mut self, n: u64) -> Result<&'a [u8], ProtocolError> {
        if n > (self.b.len() - self.pos) as u64 {
            return Err(self.err(self.pos, "truncated"));
        }
        let start = self.pos;
        self.pos += n as usize;
        Ok(&self.b[start..self.pos])
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(a))
    }

    fn tag(&mut self) -> Result<u8, ProtocolError> {
        self.last_tag = self.pos;
        self.u8()
    }

    /// A malformed-tag error at the last tag read.
    fn bad_tag(&self, why: &'static str) -> ProtocolError {
        self.err(self.last_tag, why)
    }

    fn bool(&mut self) -> Result<bool, ProtocolError> {
        match self.tag()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(self.bad_tag("bool is not 0 or 1")),
        }
    }

    fn opt_u64(&mut self) -> Result<Option<u64>, ProtocolError> {
        match self.tag()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(self.bad_tag("option tag is not 0 or 1")),
        }
    }

    fn bytes(&mut self) -> Result<Vec<u8>, ProtocolError> {
        let n = self.u64()?;
        Ok(self.take(n)?.to_vec())
    }

    fn string(&mut self) -> Result<String, ProtocolError> {
        let n = self.u64()?;
        let at = self.pos;
        let raw = self.take(n)?;
        String::from_utf8(raw.to_vec()).map_err(|_| self.err(at, "invalid UTF-8"))
    }

    fn finish(&self) -> Result<(), ProtocolError> {
        if self.pos == self.b.len() {
            Ok(())
        } else {
            Err(self.err(self.pos, "trailing bytes"))
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    fn blob() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..64)
    }

    fn text() -> impl Strategy<Value = String> {
        "\\PC{0,16}"
    }

    fn request() -> impl Strategy<Value = Request> {
        prop_oneof![
            any::<u16>().prop_map(|version| Request::Hello { version }),
            (any::<u64>(), text(), text(), blob()).prop_map(|(call, provider, operation, args)| {
                Request::Effect { call, provider, operation, args }
            }),
            blob().prop_map(|entry| Request::Transcript { entry }),
            (any::<u64>(), any::<bool>()).prop_map(|(turn, quiescent)| Request::TurnEnd { turn, quiescent }),
        ]
    }

    fn reply() -> impl Strategy<Value = Reply> {
        let result = prop_oneof![
            blob().prop_map(|receipt| EffectResult::Applied { receipt }),
            text().prop_map(|reason| EffectResult::NotApplied { reason }),
            Just(EffectResult::Unknown),
            text().prop_map(|reason| EffectResult::Refused { reason }),
        ];
        let code = prop_oneof![
            Just(ErrorCode::BadHello),
            Just(ErrorCode::Malformed),
            Just(ErrorCode::Closed),
            Just(ErrorCode::Fenced),
            Just(ErrorCode::Internal),
        ];
        prop_oneof![
            (any::<u16>(), proptest::option::of(any::<u64>()))
                .prop_map(|(version, last_sealed_turn)| Reply::Hello { version, last_sealed_turn }),
            (any::<u64>(), result).prop_map(|(call, result)| Reply::Effect { call, result }),
            any::<u64>().prop_map(|lsn| Reply::Recorded { lsn }),
            (any::<u64>(), proptest::option::of(any::<u64>()))
                .prop_map(|(turn, sealed)| Reply::TurnEnd { turn, sealed }),
            (code, text()).prop_map(|(code, message)| Reply::Error { code, message }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        #[test]
        fn request_round_trip(req in request()) {
            prop_assert_eq!(Request::decode(&req.encode()).unwrap(), req);
        }

        #[test]
        fn reply_round_trip(rep in reply()) {
            prop_assert_eq!(Reply::decode(&rep.encode()).unwrap(), rep);
        }

        #[test]
        fn truncated_or_extended_bodies_are_refused(
            req in request(),
            pick in any::<prop::sample::Index>(),
            extra in 1u8..=255,
        ) {
            let b = req.encode();
            prop_assert!(Request::decode(&b[..pick.index(b.len())]).is_err());
            let mut longer = b.clone();
            longer.push(extra);
            prop_assert!(Request::decode(&longer).is_err());
        }

        /// Random bodies that decode re-encode to exactly the same bytes.
        #[test]
        fn anything_that_decodes_is_canonical(b in proptest::collection::vec(any::<u8>(), 0..80)) {
            if let Ok(req) = Request::decode(&b) {
                prop_assert_eq!(req.encode(), b.clone());
            }
            if let Ok(rep) = Reply::decode(&b) {
                prop_assert_eq!(rep.encode(), b);
            }
        }

        /// A stream of messages framed back to back reads back in order,
        /// then ends cleanly.
        #[test]
        fn framed_stream_round_trip(reqs in proptest::collection::vec(request(), 0..10)) {
            let mut wire = Vec::new();
            for r in &reqs {
                send_request(&mut wire, r).unwrap();
            }
            let mut cur = Cursor::new(wire);
            for r in &reqs {
                prop_assert_eq!(recv_request(&mut cur).unwrap(), Some(r.clone()));
            }
            prop_assert!(recv_request(&mut cur).unwrap().is_none());
        }
    }

    #[test]
    fn an_effect_request_has_no_place_for_a_declared_class() {
        // The full encoding of an effect request is tag, call, provider,
        // operation, args — nothing else.  A tool's "this is safe" can only
        // ride inside `args`, which the protocol never interprets.
        let req = Request::Effect {
            call: 7,
            provider: "mail".into(),
            operation: "send".into(),
            args: b"{\"consequence\":\"none\"}".to_vec(),
        };
        let b = req.encode();
        assert_eq!(b.len(), 1 + 8 + (8 + 4) + (8 + 4) + (8 + 22));
    }

    #[test]
    fn oversized_frame_is_refused_before_allocation() {
        let mut wire = (MAX_FRAME + 1).to_be_bytes().to_vec();
        wire.extend_from_slice(&[0; 16]);
        assert!(matches!(
            read_frame(&mut Cursor::new(wire)),
            Err(ProtocolError::TooLarge(n)) if n == MAX_FRAME + 1
        ));
        let mut sink = Vec::new();
        let big = vec![0u8; MAX_FRAME as usize + 1];
        assert!(matches!(write_frame(&mut sink, &big), Err(ProtocolError::TooLarge(_))));
        assert!(sink.is_empty(), "nothing written for a refused frame");
    }

    #[test]
    fn end_of_stream_inside_a_frame_is_an_error() {
        // Inside the length prefix.
        assert!(matches!(read_frame(&mut Cursor::new(vec![0, 0])), Err(ProtocolError::Io(_))));
        // Inside the body.
        let mut wire = 10u32.to_be_bytes().to_vec();
        wire.extend_from_slice(&[1, 2, 3]);
        assert!(matches!(read_frame(&mut Cursor::new(wire)), Err(ProtocolError::Io(_))));
        // Clean end between frames.
        assert!(read_frame(&mut Cursor::new(Vec::new())).unwrap().is_none());
    }

    #[test]
    fn strict_refusals_name_the_offset() {
        assert!(matches!(
            Request::decode(&[9]),
            Err(ProtocolError::Malformed { at: 0, why: "unknown request tag" })
        ));
        // TurnEnd with quiescent = 2.
        let mut b = Request::TurnEnd { turn: 1, quiescent: true }.encode();
        *b.last_mut().unwrap() = 2;
        assert!(matches!(
            Request::decode(&b),
            Err(ProtocolError::Malformed { at: 9, why: "bool is not 0 or 1" })
        ));
        // Effect with a non-UTF-8 provider.
        let mut b = Request::Effect { call: 0, provider: "ab".into(), operation: String::new(), args: vec![] }
            .encode();
        b[17] = 0xFF;
        assert!(matches!(
            Request::decode(&b),
            Err(ProtocolError::Malformed { at: 17, why: "invalid UTF-8" })
        ));
        // Reply with an unknown error code.
        let mut b = Reply::Error { code: ErrorCode::Internal, message: String::new() }.encode();
        b[1] = 9;
        assert!(matches!(
            Reply::decode(&b),
            Err(ProtocolError::Malformed { at: 1, why: "unknown error code" })
        ));
        // A huge declared length is refused without allocating.
        let mut b = vec![2];
        b.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(Request::decode(&b), Err(ProtocolError::Malformed { why: "truncated", .. })));
    }
}
