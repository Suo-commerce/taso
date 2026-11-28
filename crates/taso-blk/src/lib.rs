//! The Taso block log: the storage of every Vessel on a node.
//!
//! A block device whose writes go to one append-only log, whose Seal is a
//! frozen layer at a flush point, and whose fork is a parent pointer.
//! ext4 sits on top and never knows.  The Warden is its only user
//! (`taso-warden`'s `blk` module).
//!
//! - [`map`]: which log location holds each block of each branch and Seal.
//! - [`store`]: the append-only log holding the blocks and the map, group
//!   commit on flush, and recovery to the last flush after a crash.
//! - `taso-blkd` (binary): serves branches as ublk block devices.
//! - [`client`]: a client for the daemon's control socket, for the Warden.
//! - [`holders`]: who holds a mount or a block device, for a refusal that
//!   says so.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod holders;
pub mod map;
pub mod store;
