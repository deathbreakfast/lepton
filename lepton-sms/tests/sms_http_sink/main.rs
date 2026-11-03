//! Lepton-sms integration tests, linked as one binary.
//!
//! `http_sink` skips unless `UF_SMS_SINK=1`; `spectra_emit` builds only with the `spectra` feature.

mod http_sink;
mod spectra_emit;
