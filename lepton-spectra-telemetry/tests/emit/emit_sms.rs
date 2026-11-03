//! Validating SMS counter emit against an in-memory Spectra backend.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::spectra_rt::{block_on, metric_points, spectra};
use lepton_spectra_telemetry::{record_sms_send, SmsSendOutcome};
use spectra::SchemaRegistry;

#[test]
fn sms_send_success_with_mem_spectra_happy() {
    block_on(async {
        let _ = spectra();
        let before = metric_points("lepton_sms_send").await;
        record_sms_send("test", SmsSendOutcome::Success);
        let after = metric_points("lepton_sms_send").await;
        assert!(
            after > before,
            "expected lepton_sms_send points to increase (before={before}, after={after})"
        );
    });
}

#[test]
fn sms_send_failure_with_mem_spectra_happy() {
    block_on(async {
        let _ = spectra();
        let before = metric_points("lepton_sms_send").await;
        record_sms_send("twilio", SmsSendOutcome::Failure);
        let after = metric_points("lepton_sms_send").await;
        assert!(
            after > before,
            "expected failure emit to persist (before={before}, after={after})"
        );
    });
}

#[test]
fn schemas_register_lepton_sms_send_happy() {
    let registry = SchemaRegistry::auto_discover();
    assert!(
        registry.has_schema("lepton_sms_send"),
        "lepton_sms_send must register via inventory; have {:?}",
        registry.list_schemas()
    );
}
