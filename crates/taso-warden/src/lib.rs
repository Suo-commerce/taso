//! Taso Warden.
//!
//! The daemon that owns a Vessel's Chronicle, outside the agent's
//! namespace (v1.0 §8).  Phase 1 starts with the ZFS driver: a Vessel is a
//! dataset and a Seal is a snapshot (v1.0 §1, P1).
//!
//! Normative references: spec v1.0 (build plan) and spec v0.4 (primitives).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod adoptcopy;
pub mod artifact;
mod bench;
pub mod blk;
pub mod chronicle;
pub mod classify;
pub mod coordinator;
pub mod coordjournal;
pub mod coordsrv;
pub mod coordstore;
pub mod daemon;
pub mod effects;
pub mod field;
pub mod genesis;
pub mod kube;
pub mod ledger;
pub mod navigate;
pub mod pack;
pub mod quiesce;
pub mod rebirth;
pub mod runtime;
pub mod s3;
pub mod segment;
pub mod ship;
pub mod snapbatch;
pub mod source;
pub mod source_kube;
pub mod status_kube;
pub mod storage;
pub mod summary;
pub mod supervisor;
pub mod timing;
pub mod vessel;
pub mod zfs;
