//! Taso core.
//!
//! Pure data model and invariants for the Chronicle: records and the hash
//! chain, groups and seals over state streams, the effect ledger (intents,
//! outcomes, barriers, obligations), lineage, and the Navigator. No I/O.
//! Everything here is property-tested against an in-memory model before
//! any runtime exists (spec v1.0 §1, P0).
//!
//! Normative references: spec v1.0 (build plan) and spec v0.4 (primitives).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod adapter;
pub mod canon;
pub mod envelope;
pub mod model;
pub mod record;
