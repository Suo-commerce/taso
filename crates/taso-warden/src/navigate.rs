//! The Navigator on a real log (v0.4 §6, amendment 19).
//!
//! [`taso_core::navigator::navigate`] judges records against a trusted
//! anchor.  Here the records are a Chronicle's frames, decoded, and the
//! anchor is read from the coordinator.  The frames must be the whole log
//! from genesis through the anchored head, jumping only at Gap records:
//! a Vessel's local segments, or what [`crate::pack::Packs::chain`]
//! returns followed by the local records after it.
//!
//! The answer is about records only.  Resuming from a `Consistent` Seal
//! still discharges its obligations first.

use taso_core::envelope::{ChronicleId, Lsn};
use taso_core::navigator::{navigate, Anchor, Mode, Navigation, StateFault};
use taso_core::record::{Payload, Record};

use crate::coordinator::{Coord, CoordError};
use crate::segment::Frame;

/// Judge resuming from the Seal at `seal`, given the Chronicle `id`'s
/// log as `frames` and the coordinator's anchor.  A frame whose payload
/// does not decode breaks the chain there.
pub fn navigate_frames(coord: &dyn Coord, id: ChronicleId, frames: &[Frame], seal: Lsn) -> Result<Navigation, CoordError> {
    let head = coord.head(id)?;
    let anchor = Anchor { chronicle: id, head, ownership: coord.ownership(id)? };
    let mut records = Vec::with_capacity(frames.len());
    for f in frames {
        match Payload::decode(&f.payload) {
            Ok(payload) => records.push(Record { envelope: f.envelope, payload }),
            Err(_) => {
                return Ok(Navigation::Inconsistent(vec![Mode::IncompleteState(StateFault::ChainBroken {
                    lsn: f.envelope.lsn,
                })]))
            }
        }
    }
    Ok(navigate(&records, &anchor, seal, head))
}
