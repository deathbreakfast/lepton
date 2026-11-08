//! Secrets typed on the delivery page never leave the wire types in readable form.
//!
//! Happy: a candidate serializes toward the server and its `Debug` hides the value.
//! Sad: a saved view has no field that can carry a secret, and a view with every
//! secret set shows only status.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use lepton_auth::delivery_settings::{
    DeliverySettingsView, EmailCandidate, EmailDriverChoice, SecretStatus, SmsCandidate, SmsMode,
    WriteOnlySecret,
};

const MARKER: &str = "hunter2-marker-value";

#[test]
fn candidate_debug_hides_secret_but_wire_form_carries_it_happy() {
    let email = EmailCandidate {
        driver: EmailDriverChoice::SendGrid,
        from_email: "ops@example.test".into(),
        test_recipient: "ops@example.test".into(),
        sendgrid_api_key: Some(WriteOnlySecret::new(MARKER)),
        ..EmailCandidate::default()
    };
    let sms = SmsCandidate {
        mode: SmsMode::Verify,
        twilio_api_secret: Some(WriteOnlySecret::new(MARKER)),
        ..SmsCandidate::default()
    };
    assert!(!format!("{email:?}").contains(MARKER));
    assert!(!format!("{sms:?}").contains(MARKER));
    // The secret has to reach the server, so the serialized candidate does carry it.
    assert!(serde_json::to_string(&email).unwrap().contains(MARKER));
    assert!(serde_json::to_string(&sms).unwrap().contains(MARKER));
}

#[test]
fn view_with_every_secret_set_serializes_status_only_sad() {
    let set = SecretStatus {
        is_set: true,
        rotated_at: None,
    };
    let mut view = DeliverySettingsView::default();
    view.email.smtp_password = set.clone();
    view.email.sendgrid_api_key = set.clone();
    view.sms.twilio_api_secret = set.clone();
    view.oauth.google.secret = set.clone();
    view.oauth.github.secret = set;
    let json = serde_json::to_string(&view).unwrap();
    assert!(json.contains("\"is_set\":true"));
    assert!(!json.contains(MARKER));
    let back: DeliverySettingsView = serde_json::from_str(&json).unwrap();
    assert_eq!(back, view);
}

#[test]
fn blank_secret_is_empty_and_invalid_candidate_is_rejected_sad() {
    assert!(WriteOnlySecret::new("   ").is_empty());
    let bad = SmsCandidate {
        mode: SmsMode::Verify,
        twilio_account_sid: "XX123".into(),
        ..SmsCandidate::default()
    };
    assert!(bad.validate().is_err());
}
