//! Taso Warden.
//!
//! The daemon that owns a Vessel's Chronicle, outside the agent's
//! namespace (v1.0 §8).  Phase 1 starts with the ZFS driver: a Vessel is a
//! dataset and a Seal is a snapshot (v1.0 §1, P1).
//!
//! Normative references: spec v1.0 (build plan) and spec v0.4 (primitives).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod chronicle;
pub mod coordinator;
pub mod coordsrv;
pub mod daemon;
pub mod effects;
pub mod field;
pub mod navigate;
pub mod pack;
pub mod quiesce;
pub mod rebirth;
pub mod runtime;
pub mod s3;
pub mod segment;
pub mod snapbatch;
pub mod source;
pub mod supervisor;
pub mod summary;
pub mod ship;
pub mod timing;
mod bench;
pub mod vessel;
pub mod zfs;
