//! Taso Warden.
//!
//! The daemon that owns a Vessel's Chronicle, outside the agent's
//! namespace (v1.0 §8).  A Vessel lives on the block log (`taso-blkd`,
//! [`blk`]): its files are a branch, a Seal is a layer of that branch.
//!
//! Normative references: spec v1.0 (build plan) and spec v0.4 (primitives).

// One named exception, and only one: `blk::fs_freeze_call` (FIFREEZE /
// FITHAW, the Seal's freeze without starting `fsfreeze` - P5, the 50 ms
// line, bite 1).  A test in blk.rs fails if any other `allow` of unsafe
// code appears in this crate.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod artifact;
pub mod attempt;
mod bench;
pub mod blk;
pub mod chronicle;
pub mod classify;
pub mod coordinator;
pub mod coordjournal;
pub mod coordsrv;
pub mod coordstore;
pub mod daemon;
pub mod decidesrv;
pub mod effects;
pub mod explain;
pub mod field;
pub mod finish;
pub mod genesis;
pub mod kube;
pub mod ledger;
pub mod navigate;
pub mod nominate;
pub mod pack;
pub mod policy;
pub mod purge;
pub mod quiesce;
pub mod rebirth;
pub mod runtime;
pub mod s3;
pub mod segment;
pub mod ship;
pub mod source;
pub mod source_kube;
pub mod status_kube;
pub mod storage;
pub mod submit;
pub mod summary;
pub mod supervisor;
pub mod template;
pub mod timing;
pub mod verdict;
pub mod verify;
pub mod vessel;
