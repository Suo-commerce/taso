//! Length-prefixed framing for Taso's Unix-socket protocols.
//!
//! A frame is a big-endian `u32` body length followed by the body.  Bodies
//! larger than [`MAX_FRAME`] are refused before anything is allocated, on
//! read and on write.  What a body means is each protocol's own business:
//! the Field protocol (`taso-field`) between a Vessel and its Warden, and
//! the coordinator protocol between a Warden and the coordinator.  Both use
//! these two functions, so neither depends on the other.

use std::fmt;
use std::io::{self, Read, Write};

/// Largest frame body accepted, in bytes.
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

/// Why a frame could not be read or written.
#[derive(Debug)]
pub enum FrameError {
    /// The stream failed, or ended in the middle of a frame.
    Io(io::Error),
    /// The frame is larger than [`MAX_FRAME`].  On write, the length is
    /// `u32::MAX` when the body does not even fit a `u32`.
    TooLarge(u32),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::TooLarge(n) => write!(f, "frame of {n} bytes exceeds {MAX_FRAME}"),
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::TooLarge(_) => None,
        }
    }
}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Write one frame and flush.  A body over [`MAX_FRAME`] is refused and
/// nothing is written.
pub fn write_frame(w: &mut impl Write, body: &[u8]) -> Result<(), FrameError> {
    let len = u32::try_from(body.len())
        .ok()
        .filter(|&n| n <= MAX_FRAME)
        .ok_or(FrameError::TooLarge(u32::MAX))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(body)?;
    w.flush()?;
    Ok(())
}

/// Read one frame.  `Ok(None)` on a clean end of stream between frames;
/// an end inside a frame is an error.  An interrupted read is retried:
/// a stopped and continued process gets `EINTR` from a socket read with a
/// timeout even under `SA_RESTART`, and that is not a broken connection.
pub fn read_frame(r: &mut impl Read) -> Result<Option<Vec<u8>>, FrameError> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match r.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    let len = u32::from_be_bytes(len);
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Yields one byte per read, with an `EINTR` before every byte.
    struct Interrupting {
        data: Vec<u8>,
        at: usize,
        interrupt: bool,
    }

    impl Read for Interrupting {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            if self.at == self.data.len() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.data[self.at];
            self.at += 1;
            Ok(1)
        }
    }

    #[test]
    fn round_trip_and_clean_end() {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"hello").unwrap();
        write_frame(&mut wire, b"").unwrap();
        assert_eq!(&wire[..4], &5u32.to_be_bytes(), "big-endian length first");
        let mut r = Cursor::new(wire);
        assert_eq!(read_frame(&mut r).unwrap(), Some(b"hello".to_vec()));
        assert_eq!(read_frame(&mut r).unwrap(), Some(Vec::new()));
        assert_eq!(read_frame(&mut r).unwrap(), None);
    }

    /// The gate-p2 round 12 finding: EINTR is retried, in the length as in
    /// the body.
    #[test]
    fn interrupted_reads_are_retried() {
        let mut framed = Vec::new();
        write_frame(&mut framed, b"hello").unwrap();
        let mut r = Interrupting { data: framed, at: 0, interrupt: false };
        assert_eq!(read_frame(&mut r).unwrap(), Some(b"hello".to_vec()));
        assert_eq!(read_frame(&mut r).unwrap(), None);
    }

    #[test]
    fn oversized_frames_are_refused_before_allocation() {
        let mut wire = (MAX_FRAME + 1).to_be_bytes().to_vec();
        wire.extend_from_slice(&[0; 16]);
        assert!(matches!(read_frame(&mut Cursor::new(wire)), Err(FrameError::TooLarge(n)) if n == MAX_FRAME + 1));
        // Exactly MAX_FRAME is the largest accepted length.
        let mut wire = MAX_FRAME.to_be_bytes().to_vec();
        wire.extend_from_slice(&[0; 3]);
        assert!(matches!(read_frame(&mut Cursor::new(wire)), Err(FrameError::Io(_))), "accepted, then short");
        let mut sink = Vec::new();
        let big = vec![0u8; MAX_FRAME as usize + 1];
        assert!(matches!(write_frame(&mut sink, &big), Err(FrameError::TooLarge(_))));
        assert!(sink.is_empty(), "nothing written for a refused frame");
    }

    /// A writer that remembers whether everything written was flushed.
    #[derive(Default)]
    struct Buffered {
        pending: usize,
        flushed: Vec<u8>,
        held: Vec<u8>,
    }

    impl Write for Buffered {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.held.extend_from_slice(b);
            self.pending += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushed.append(&mut self.held);
            self.pending = 0;
            Ok(())
        }
    }

    /// A frame is on its way when `write_frame` returns: the peer is
    /// waiting for it, and nothing else would flush a buffered stream.
    #[test]
    fn a_written_frame_is_flushed() {
        let mut w = Buffered::default();
        write_frame(&mut w, b"abc").unwrap();
        assert_eq!(w.pending, 0);
        assert_eq!(w.flushed, [&3u32.to_be_bytes()[..], b"abc"].concat());
    }

    #[test]
    fn end_of_stream_inside_a_frame_is_an_error() {
        assert!(matches!(read_frame(&mut Cursor::new(vec![0, 0])), Err(FrameError::Io(_))));
        let mut wire = 10u32.to_be_bytes().to_vec();
        wire.extend_from_slice(&[1, 2, 3]);
        assert!(matches!(read_frame(&mut Cursor::new(wire)), Err(FrameError::Io(_))));
    }
}
