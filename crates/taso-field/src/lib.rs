//! Taso Field.
//!
//! The Field is the only API across a Vessel's boundary (v0.4 §3, v1.0 §3):
//! the agent gets a POSIX filesystem (its dataset) and one Unix socket.
//! Nothing else crosses.  This crate holds the wire protocol both sides
//! speak and the adapter trait the Warden dispatches effects through; the
//! Vessel-side client follows.
//!
//! Normative references: spec v1.0 §3 and v0.4 §7.1.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod adapter;
pub mod protocol;
