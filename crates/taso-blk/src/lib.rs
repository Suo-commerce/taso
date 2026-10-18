//! Taso block log spike (plan `Taso_plan_blocklog_spike_2026-10-18`).
//!
//! A thin slice of Phase 4 on local storage: a block device whose writes
//! go to a log, whose Seal is a frozen layer at a flush point, and whose
//! fork is a parent pointer.  ext4 sits on top and never knows.
//!
//! - [`map`]: which log location holds each block of each branch and Seal.
//! - [`store`]: the append-only log holding the blocks and the map, group
//!   commit on flush, and recovery to the last flush after a crash.
//! - `taso-blkd` (binary): serves branches as ublk block devices.
//! - [`client`]: a client for the daemon's control socket, for the Warden.
//!
//! Not wired into the Warden.  Judged against the spike's pass and kill
//! criteria; deleted if a kill criterion is hit.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod map;
pub mod store;
