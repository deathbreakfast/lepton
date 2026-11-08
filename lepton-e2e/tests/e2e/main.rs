//! Lepton-e2e integration tests, one module per area, linked as one binary.
//!
//! Run one area with `cargo test -p lepton-e2e --test e2e <module>::`.

mod ci_e2e;
mod mock_oidc_http;
mod oauth_mock_http;
mod sms_sink_http;
