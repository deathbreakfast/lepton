//! Live HTTP capture against `lepton-sms-sink` on `:8099`.
//!
//! Gated: set `UF_SMS_SINK=1` (and optionally `UF_SMS_SINK_URL`). Without the gate the
//! suite skips so default CI stays green without a running sink process.
//!
//! Start the sink first:
//! ```bash
//! cargo run -p lepton-e2e --bin lepton-sms-sink
//! ./infra/mailpit/sms_sink_smoke.sh
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::time::Duration;

use lepton_sms::{HttpCaptureSmsConfig, SmsEnvelope, SmsServiceBuilder};
use serde::Deserialize;

fn sink_enabled() -> bool {
    matches!(
        std::env::var("UF_SMS_SINK").as_deref(),
        Ok("1" | "true" | "TRUE" | "yes" | "YES")
    ) || std::env::var("UF_SMS_SINK_URL").is_ok()
}

fn sink_url() -> String {
    std::env::var("UF_SMS_SINK_URL").unwrap_or_else(|_| "http://127.0.0.1:8099".to_string())
}

#[derive(Debug, Deserialize)]
struct Captured {
    to_e164: String,
    body: String,
    otp_code: Option<String>,
}

async fn clear_sink(client: &reqwest::Client, base: &str) {
    let res = client
        .delete(format!("{base}/v1/messages"))
        .send()
        .await
        .expect("clear");
    assert!(
        res.status().is_success() || res.status().as_u16() == 204,
        "clear failed: {}",
        res.status()
    );
}

#[tokio::test]
async fn sms_http_sink_records_message_happy() {
    if !sink_enabled() {
        eprintln!("skipping sms_http_sink (set UF_SMS_SINK=1)");
        return;
    }
    let base = sink_url();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    // Probe readiness.
    for _ in 0..40 {
        if client
            .get(format!("{base}/v1/messages"))
            .send()
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    clear_sink(&client, &base).await;

    let marker = format!("sms-sink-marker-{}", uuid_ish());
    let sms = SmsServiceBuilder::new()
        .http_capture(HttpCaptureSmsConfig::new(&base).expect("cfg"))
        .build()
        .expect("build");
    sms.send(&SmsEnvelope {
        to_e164: "+15551234567".into(),
        body: format!("Your verification code is: 654321 ({marker})"),
        otp_code: Some("654321".into()),
    })
    .await
    .expect("send");

    let mut found = None;
    for _ in 0..40 {
        let listed: Vec<Captured> = client
            .get(format!("{base}/v1/messages"))
            .send()
            .await
            .expect("list")
            .json()
            .await
            .expect("json");
        if let Some(m) = listed.into_iter().find(|m| m.body.contains(&marker)) {
            found = Some(m);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let msg = found.expect("message with marker");
    assert_eq!(msg.to_e164, "+15551234567");
    assert_eq!(msg.otp_code.as_deref(), Some("654321"));
}

fn uuid_ish() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    format!("{nanos:x}")
}
