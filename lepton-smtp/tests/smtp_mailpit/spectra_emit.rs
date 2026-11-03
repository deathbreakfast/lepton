//! Delivery adapters emit Spectra counters when `spectra` is enabled.

#![cfg(feature = "spectra")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use lepton_smtp::{EmailDeliveryService, EmailEnvelope, NoopEmailAdapter};
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

async fn email_send_points() -> usize {
    tokio::time::sleep(Duration::from_millis(80)).await;
    let now = current_emit_ts();
    spectra()
        .router()
        .query_metrics(MetricsQueryRange {
            metric_name: "lepton_email_send".into(),
            start: now - chrono::Duration::seconds(30),
            end: now + chrono::Duration::seconds(5),
            label_matchers: vec![],
        })
        .await
        .expect("query")
        .len()
}

#[tokio::test]
async fn noop_send_increments_email_send_with_mem_spectra_happy() {
    let _ = spectra();
    let before = email_send_points().await;
    NoopEmailAdapter
        .send(&EmailEnvelope {
            to: "ops@example.test".into(),
            subject: "t".into(),
            text_body: "b".into(),
            html_body: "<p>b</p>".into(),
        })
        .await
        .expect("noop send");
    let after = email_send_points().await;
    assert!(after > before, "before={before} after={after}");
}
