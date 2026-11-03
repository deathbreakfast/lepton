//! Emit helpers against an in-memory Spectra, linked as one binary.
//!
//! Every test runs on the one runtime in [`spectra_rt`], so the process-global Spectra sink
//! never outlives the runtime that booted it. `no_spectra_soft` keeps its own binary because
//! it needs Spectra never booted.

mod spectra_rt;

mod emit_auth;
mod emit_email;
mod emit_sms;
