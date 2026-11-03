//! Lepton-smtp integration tests, linked as one binary.
//!
//! `mailpit` skips unless `UF_MAILPIT=1`; `spectra_emit` builds only with the `spectra` feature.
//! `spectra_soft_no_boot` keeps its own binary because it needs Spectra never booted.

mod mailpit;
mod spectra_emit;
