//! Live SMTP delivery against Mailpit.
//!
//! Gated: set `UF_MAILPIT=1` (and optionally `UF_MAILPIT_URL`). Without the gate the
//! suite skips so default CI stays green without Docker.
//!
//! Start the sink first:
//! ```bash
//! docker compose -f infra/mailpit/docker-compose.yml up -d
//! ./infra/mailpit/smtp_smoke.sh
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unnested_or_patterns
)]

use std::time::Duration;

use lepton_smtp::{
    password_reset_email_envelope, verification_email_envelope, EmailDriver, EmailServiceBuilder,
    SmtpConfig, VerificationEmailFlow,
};
use serde::Deserialize;

fn mailpit_enabled() -> bool {
    matches!(
        std::env::var("UF_MAILPIT").as_deref(),
        Ok("1" | "true" | "TRUE" | "yes" | "YES")
    ) || std::env::var("UF_MAILPIT_URL").is_ok()
}

fn mailpit_url() -> String {
    std::env::var("UF_MAILPIT_URL").unwrap_or_else(|_| "http://127.0.0.1:8025".to_string())
}

#[derive(Debug, Deserialize)]
struct MessagesResponse {
    total: u64,
    messages: Vec<MessageSummary>,
}

#[derive(Debug, Deserialize)]
struct MessageSummary {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "To")]
    to: Vec<Address>,
    #[serde(rename = "Subject")]
    subject: String,
}

#[derive(Debug, Deserialize)]
struct Address {
    #[serde(rename = "Address")]
    address: String,
}

#[derive(Debug, Deserialize)]
struct MessageDetail {
    #[serde(rename = "Text")]
    text: String,
    #[serde(rename = "HTML")]
    html: String,
}

async fn clear_inbox(client: &reqwest::Client, base: &str) {
    let res = client
        .delete(format!("{base}/api/v1/messages"))
        .send()
        .await
        .expect("clear inbox");
    assert!(
        res.status().is_success(),
        "clear inbox failed: {}",
        res.status()
    );
}

async fn list_messages(client: &reqwest::Client, base: &str) -> MessagesResponse {
    client
        .get(format!("{base}/api/v1/messages"))
        .send()
        .await
        .expect("list messages")
        .error_for_status()
        .expect("list status")
        .json()
        .await
        .expect("list json")
}

async fn get_message(client: &reqwest::Client, base: &str, id: &str) -> MessageDetail {
    client
        .get(format!("{base}/api/v1/message/{id}"))
        .send()
        .await
        .expect("get message")
        .error_for_status()
        .expect("get status")
        .json()
        .await
        .expect("get json")
}

async fn wait_for_total(client: &reqwest::Client, base: &str, want: u64) -> MessagesResponse {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let page = list_messages(client, base).await;
        if page.total >= want {
            return page;
        }
        assert!(
            tokio::time::Instant::now() <= deadline,
            "timed out waiting for {want} messages; had {}",
            page.total
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

#[tokio::test]
async fn smtp_mailpit_delivery_happy_path() {
    if !mailpit_enabled() {
        eprintln!("skipping smtp_mailpit_delivery_happy_path (set UF_MAILPIT=1)");
        return;
    }

    let base = mailpit_url();
    let client = reqwest::Client::new();
    clear_inbox(&client, &base).await;

    let marker = format!("mailpit-marker-{}", uuid_like());
    let recipient = format!("user+{marker}@example.test");

    let service = EmailServiceBuilder::new()
        .smtp(
            SmtpConfig::builder()
                .host("127.0.0.1")
                .port(1025)
                .use_tls(false)
                .from_email("noreply@example.test")
                .from_name("Lepton Auth")
                .build()
                .expect("smtp config"),
        )
        .build()
        .expect("email service");
    assert_eq!(service.driver(), EmailDriver::Smtp);

    let verify_code = format!("{marker}-v");
    let reset_link = format!("http://127.0.0.1:3000/auth/reset/confirm#token={marker}-r");

    let verify_receipt = service
        .send(&verification_email_envelope(
            &recipient,
            &verify_code,
            VerificationEmailFlow::Signup,
        ))
        .await
        .expect("verify send");
    assert_eq!(verify_receipt.provider, "smtp");

    let mut reset_env = password_reset_email_envelope(&recipient, &reset_link);
    reset_env.subject = format!("Reset your password [{marker}]");
    let reset_receipt = service.send(&reset_env).await.expect("reset send");
    assert_eq!(reset_receipt.provider, "smtp");

    let page = wait_for_total(&client, &base, 2).await;
    assert!(page.total >= 2, "expected at least 2 messages");

    let subjects: Vec<_> = page.messages.iter().map(|m| m.subject.as_str()).collect();
    assert!(
        subjects
            .iter()
            .any(|s| s.contains("Your verification code")),
        "missing verify subject: {subjects:?}"
    );
    assert!(
        subjects.iter().any(|s| s.contains(&marker)),
        "missing marker subject: {subjects:?}"
    );

    for msg in &page.messages {
        assert!(
            msg.to.iter().any(|a| a.address == recipient),
            "unexpected recipients for {}: {:?}",
            msg.id,
            msg.to
        );
        let detail = get_message(&client, &base, &msg.id).await;
        let body = format!("{}{}", detail.text, detail.html);
        assert!(
            body.contains(&verify_code) || body.contains("#token=") || body.contains(&marker),
            "body missing verification code/marker for {}",
            msg.id
        );
    }
}

#[tokio::test]
async fn smtp_mailpit_unreachable_sad() {
    if !mailpit_enabled() {
        eprintln!("skipping smtp_mailpit_unreachable_sad (set UF_MAILPIT=1)");
        return;
    }

    let base = mailpit_url();
    let client = reqwest::Client::new();
    clear_inbox(&client, &base).await;
    let before = list_messages(&client, &base).await.total;

    let service = EmailServiceBuilder::new()
        .smtp(
            SmtpConfig::builder()
                .host("127.0.0.1")
                .port(19999)
                .use_tls(false)
                .from_email("noreply@example.test")
                .build()
                .expect("smtp config"),
        )
        .build()
        .expect("email service");

    let err = service
        .send(&verification_email_envelope(
            "nobody@example.test",
            "deadbeef",
            VerificationEmailFlow::Signup,
        ))
        .await
        .expect_err("send to closed port must fail");

    let msg = err.to_string();
    assert!(
        msg.contains("reason_class=") || msg.contains("SMTP") || msg.contains("failed"),
        "unexpected error: {msg}"
    );

    let after = list_messages(&client, &base).await.total;
    assert_eq!(after, before, "failed send must not grow inbox");
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{nanos:x}")
}
