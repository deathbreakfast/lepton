//! One tokio runtime and one in-memory Spectra shared by every test in this binary.

#![allow(clippy::expect_used)]

use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use spectra::{MemEventsBackend, MemMetricsBackend, Spectra};
use spectra_core::{current_emit_ts, MetricsQueryRange};
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static SPECTRA: OnceLock<Spectra> = OnceLock::new();

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

/// Runs `fut` to completion on the shared runtime.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    runtime().block_on(fut)
}

/// The in-memory Spectra, booted on the shared runtime the first time it is asked for.
pub fn spectra() -> &'static Spectra {
    SPECTRA.get_or_init(|| {
        let _rt = runtime().enter();
        Spectra::builder()
            .metrics_backend(Arc::new(MemMetricsBackend::new()))
            .events_backend(Arc::new(MemEventsBackend::new()))
            .embedded()
            .build()
            .expect("spectra boot")
    })
}

/// Points stored for `name` in the last 30 seconds, after a short wait for the emit to land.
pub async fn metric_points(name: &str) -> usize {
    tokio::time::sleep(Duration::from_millis(80)).await;
    let now = current_emit_ts();
    spectra()
        .router()
        .query_metrics(MetricsQueryRange {
            metric_name: name.into(),
            start: now - chrono::Duration::seconds(30),
            end: now + chrono::Duration::seconds(5),
            label_matchers: vec![],
        })
        .await
        .expect("query")
        .len()
}
