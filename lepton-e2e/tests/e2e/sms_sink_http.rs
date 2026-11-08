//! CI-always HTTP coverage for `lepton_e2e::sms_sink` (ephemeral bind).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lepton_e2e::sms_sink::{
    serve_for_test, CapturedSms, MessageStore, MAX_BODY_BYTES, MAX_STORE_MESSAGES,
};
use serde_json::json;

async fn spawn_sink() -> (
    String,
    Arc<MessageStore>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let store = Arc::new(MessageStore::new());
    let (addr, handle) = serve_for_test(SocketAddr::from(([127, 0, 0, 1], 0)), Arc::clone(&store))
        .await
        .expect("bind");
    // Brief settle for accept loop.
    tokio::time::sleep(Duration::from_millis(20)).await;
    (format!("http://{addr}"), store, handle)
}

#[tokio::test]
async fn sms_sink_post_records_message_happy() {
    let (base, _store, handle) = spawn_sink().await;
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{base}/v1/messages"))
        .json(&json!({
            "to_e164": "+15551234567",
            "body": "Your verification code is: 123456",
            "otp_code": "123456",
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(res.status(), 201);

    let listed: Vec<CapturedSms> = client
        .get(format!("{base}/v1/messages"))
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].to_e164, "+15551234567");
    assert!(listed[0].body.contains("123456"));
    assert_eq!(listed[0].otp_code.as_deref(), Some("123456"));
    handle.abort();
}

#[tokio::test]
async fn sms_sink_post_missing_fields_sad() {
    let (base, _store, handle) = spawn_sink().await;
    let client = reqwest::Client::new();

    let res = client
        .post(format!("{base}/v1/messages"))
        .json(&json!({"body": "x"}))
        .send()
        .await
        .expect("post");
    assert_eq!(res.status(), 400);

    let res = client
        .post(format!("{base}/v1/messages"))
        .json(&json!({"to_e164": "+15551234567"}))
        .send()
        .await
        .expect("post");
    assert_eq!(res.status(), 400);

    handle.abort();
}

#[tokio::test]
async fn sms_sink_post_malformed_json_sad() {
    let (base, _store, handle) = spawn_sink().await;
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{base}/v1/messages"))
        .header("content-type", "application/json")
        .body("{not-json")
        .send()
        .await
        .expect("post");
    assert!(res.status().is_client_error());
    handle.abort();
}

#[tokio::test]
async fn sms_sink_get_lists_in_insert_order_happy() {
    let (base, _store, handle) = spawn_sink().await;
    let client = reqwest::Client::new();
    for body in ["first", "second"] {
        client
            .post(format!("{base}/v1/messages"))
            .json(&json!({"to_e164": "+15551234567", "body": body}))
            .send()
            .await
            .expect("post");
    }
    let listed: Vec<CapturedSms> = client
        .get(format!("{base}/v1/messages"))
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].body, "first");
    assert_eq!(listed[1].body, "second");
    handle.abort();
}

#[tokio::test]
async fn sms_sink_delete_clears_all_happy() {
    let (base, store, handle) = spawn_sink().await;
    let client = reqwest::Client::new();
    client
        .post(format!("{base}/v1/messages"))
        .json(&json!({"to_e164": "+15551234567", "body": "x"}))
        .send()
        .await
        .expect("post");
    assert_eq!(store.len(), 1);

    let res = client
        .delete(format!("{base}/v1/messages"))
        .send()
        .await
        .expect("delete");
    assert_eq!(res.status(), 204);

    let listed: Vec<CapturedSms> = client
        .get(format!("{base}/v1/messages"))
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert!(listed.is_empty());
    handle.abort();
}

#[tokio::test]
async fn sms_sink_rejects_oversize_body_sad() {
    let (base, _store, handle) = spawn_sink().await;
    let client = reqwest::Client::new();
    let huge = "x".repeat(MAX_BODY_BYTES + 1);
    let res = client
        .post(format!("{base}/v1/messages"))
        .header("content-type", "application/json")
        .body(format!(r#"{{"to_e164":"+15551234567","body":"{huge}"}}"#))
        .send()
        .await
        .expect("post");
    assert!(
        res.status().is_client_error(),
        "expected client error for oversize, got {}",
        res.status()
    );
    handle.abort();
}

#[tokio::test]
async fn sms_sink_store_cap_sad() {
    let (base, _store, handle) = spawn_sink().await;
    let client = reqwest::Client::new();
    for i in 0..MAX_STORE_MESSAGES {
        let res = client
            .post(format!("{base}/v1/messages"))
            .json(&json!({"to_e164": "+15551234567", "body": format!("m{i}")}))
            .send()
            .await
            .expect("post");
        assert_eq!(res.status(), 201, "insert {i}");
    }
    let res = client
        .post(format!("{base}/v1/messages"))
        .json(&json!({"to_e164": "+15551234567", "body": "overflow"}))
        .send()
        .await
        .expect("post");
    assert_eq!(res.status(), 507);
    handle.abort();
}

#[test]
fn sms_sink_default_bind_loopback_happy() {
    let addr = lepton_e2e::sms_sink::default_bind_addr();
    assert!(addr.ip().is_loopback());
    assert_eq!(addr.port(), 8099);
}
