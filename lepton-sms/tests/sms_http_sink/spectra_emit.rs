//! SMS adapters emit Spectra counters when `spectra` is enabled.

#![cfg(feature = "spectra")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use lepton_sms::{NoopSmsAdapter, SmsDeliveryService, SmsEnvelope, TestSmsAdapter};
use spectra::{MemEventsBackend, MemMetricsBackend, Spectra};
use spectra_core::{current_emit_ts, MetricsQueryRange};

static SPECTRA: OnceLock<Spectra> = OnceLock::new();

fn spectra() -> &'static Spectra {
    SPECTRA.get_or_init(|| {
        Spectra::builder()
            .metrics_backend(Arc::new(MemMetricsBackend::new()))
            .events_backend(Arc::new(MemEventsBackend::new()))
            .embedded()
            .build()
            .expect("spectra boot")
    })
}

async fn sms_send_points() -> usize {
    tokio::time::sleep(Duration::from_millis(80)).await;
    let now = current_emit_ts();
    spectra()
        .router()
        .query_metrics(MetricsQueryRange {
            metric_name: "lepton_sms_send".into(),
            start: now - chrono::Duration::seconds(30),
            end: now + chrono::Duration::seconds(5),
            label_matchers: vec![],
        })
        .await
        .expect("query")
        .len()
}

#[tokio::test]
async fn test_adapter_send_increments_sms_send_with_mem_spectra_happy() {
    let _ = spectra();
    let before = sms_send_points().await;
    TestSmsAdapter::new()
        .send(&SmsEnvelope {
            to_e164: "+15551234567".into(),
            body: "code".into(),
            otp_code: Some("123456".into()),
        })
        .await
        .expect("test send");
    let after = sms_send_points().await;
    assert!(after > before, "before={before} after={after}");
}

#[tokio::test]
async fn noop_invalid_e164_increments_failure_with_mem_spectra_happy() {
    let _ = spectra();
    let before = sms_send_points().await;
    let err = NoopSmsAdapter
        .send(&SmsEnvelope {
            to_e164: String::new(),
            body: "x".into(),
            otp_code: None,
        })
        .await
        .expect_err("empty e164");
    assert!(err.to_string().contains("invalid_e164"));
    let after = sms_send_points().await;
    assert!(
        after > before,
        "failure must emit (before={before} after={after})"
    );
}
