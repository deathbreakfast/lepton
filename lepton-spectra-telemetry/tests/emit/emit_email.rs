//! Validating email counter emit against an in-memory Spectra backend.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::spectra_rt::{block_on, metric_points, spectra};
use lepton_spectra_telemetry::{record_email_send, EmailSendOutcome};
use spectra::SchemaRegistry;

#[test]
fn email_send_success_with_mem_spectra_happy() {
    block_on(async {
        let _ = spectra();
        let before = metric_points("lepton_email_send").await;
        record_email_send("noop", EmailSendOutcome::Success);
        let after = metric_points("lepton_email_send").await;
        assert!(
            after > before,
            "expected lepton_email_send points to increase (before={before}, after={after})"
        );
    });
}

#[test]
fn email_send_failure_with_mem_spectra_happy() {
    block_on(async {
        let _ = spectra();
        let before = metric_points("lepton_email_send").await;
        record_email_send("smtp", EmailSendOutcome::Failure);
        let after = metric_points("lepton_email_send").await;
        assert!(
            after > before,
            "expected failure emit to persist (before={before}, after={after})"
        );
    });
}

#[test]
fn schemas_register_lepton_email_send_happy() {
    let registry = SchemaRegistry::auto_discover();
    assert!(
        registry.has_schema("lepton_email_send"),
        "lepton_email_send must register via inventory; have {:?}",
        registry.list_schemas()
    );
}
