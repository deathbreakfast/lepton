//! CI e2e validating signup → email → phone → confirm (+ device / TOTP).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use lepton_auth::devices::{
    confirm_auth_device, issue_device_binding, list_auth_devices, register_auth_device,
    revoke_auth_device, verify_device_binding, AuthDeviceKind, DeviceBindingCookie,
};
use lepton_auth::factor::{FactorChallengeError, FactorChallengeService};
use lepton_auth::oauth::{
    begin_oauth, complete_oauth, OAuthClientConfig, OAuthError, OAuthIntent, OAuthProvider,
};
use lepton_auth::signup_api::ssr::{create_pending_user, SignupRequest};
use lepton_auth::totp::{begin_totp_enroll, confirm_totp_enroll};
use lepton_auth::trust::{confirm_user, primary_email_verified, primary_phone_verified};
use lepton_e2e::boot::{boot_lab, boot_valence};
use lepton_e2e::flow::{
    issue_sms_challenge, run_device_totp_challenge_flow, run_signup_verify_flow,
    verify_email_token, SignupVerifyOpts, TestCodeSource, TestTotpCodeSource,
};
use lepton_e2e::oauth_flow::{
    run_oauth_signup_login_flow, MockOAuthCodeSource, OAuthSignupLoginOpts,
};
use lepton_e2e::parse::totp_secret_from_otpauth_uri;
use lepton_host_adapter::generated::UserProfile;
use lepton_identity::ownership::bare_id_from_record;
use lepton_smtp::{verification_email_envelope_named, VerificationEmailFlow};
use totp_rs::{Algorithm, Secret, TOTP};

#[tokio::test]
async fn ci_e2e_signup_email_phone_confirm_happy() {
    let lab = boot_lab("ci_e2e_happy").await.expect("lab");
    let codes = TestCodeSource::new(Arc::clone(&lab.test_sms));
    let outcome = run_signup_verify_flow(
        &lab.valence,
        &lab.services,
        &codes,
        "Alex Rivera",
        "e2e-happy@example.test",
        "+15555550100",
        "CorrectHorseBattery1!",
        SignupVerifyOpts::default(),
    )
    .await
    .expect("flow");
    assert!(outcome.email_verified);
    assert!(outcome.phone_verified);
    assert!(outcome.confirmed);

    #[cfg(feature = "boson-delivery")]
    {
        use lepton_host_adapter::generated::{
            DeliveryAttempt, DeliveryAttemptChannel, DeliveryAttemptOutcome,
        };
        let rows = DeliveryAttempt::query_used(&lab.valence, valence::use_!("query DeliveryAttempt in lepton-e2e/tests/ci_e2e.rs; Valence persistence for this feature path; typed store; visible to test harness."))
            .await
            .expect("delivery attempts");
        assert!(
            rows.iter().any(|r| {
                *r.channel() == DeliveryAttemptChannel::Sms
                    && *r.outcome() == DeliveryAttemptOutcome::Success
                    && r.intent_kind() == "sms_otp"
            }),
            "expected DeliveryAttempt sms_otp success after durable send"
        );
    }
}

#[tokio::test]
async fn ci_e2e_signup_persists_legal_and_display_name() {
    let valence = boot_valence("ci_e2e_legal_name").await.expect("valence");
    let legal_name = "Alex Rivera";
    let display_name = "Alex";
    let pending = create_pending_user(
        &valence,
        SignupRequest {
            legal_name: legal_name.into(),
            display_name: display_name.into(),
            email: "e2e-legal@example.test".into(),
            password: "CorrectHorseBattery1!".into(),
            confirm: "CorrectHorseBattery1!".into(),
        },
    )
    .await
    .expect("signup");
    assert_eq!(pending.legal_name, legal_name);
    assert_eq!(pending.display_name, display_name);

    let profile = UserProfile::query_used(&valence, valence::use_!("query UserProfile in lepton-e2e/tests/ci_e2e.rs; Valence persistence for this feature path; typed store; visible to test harness."))
        .first()
        .await
        .expect("profile query")
        .expect("profile");
    assert_eq!(profile.legal_name(), legal_name);
    assert_eq!(profile.display_name(), display_name);
    assert_eq!(
        bare_id_from_record(profile.user()),
        bare_id_from_record(&pending.user_id)
    );
}

#[tokio::test]
async fn ci_e2e_signup_rejects_invalid_legal_name() {
    let valence = boot_valence("ci_e2e_legal_name_sad")
        .await
        .expect("valence");
    let err = match create_pending_user(
        &valence,
        SignupRequest {
            legal_name: "Name<script>".into(),
            display_name: "Alex".into(),
            email: "e2e-bad-name@example.test".into(),
            password: "CorrectHorseBattery1!".into(),
            confirm: "CorrectHorseBattery1!".into(),
        },
    )
    .await
    {
        Ok(_) => panic!("invalid legal name should fail"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("invalid characters"));
    assert!(UserProfile::query_used(&valence, valence::use_!("query UserProfile in lepton-e2e/tests/ci_e2e.rs; Valence persistence for this feature path; typed store; visible to test harness."))
        .first()
        .await
        .expect("query")
        .is_none());
}

#[tokio::test]
async fn ci_e2e_sms_otp_rejected() {
    let lab = boot_lab("ci_e2e_sms_sad").await.expect("lab");

    let pending = create_pending_user(
        &lab.valence,
        SignupRequest {
            legal_name: "Casey Sad".into(),
            display_name: "Casey".into(),
            email: "e2e-sad@example.test".into(),
            password: "CorrectHorseBattery1!".into(),
            confirm: "CorrectHorseBattery1!".into(),
        },
    )
    .await
    .expect("signup");

    lab.services
        .email
        .send(&verification_email_envelope_named(
            &pending.email,
            Some(pending.legal_name.as_str()),
            &pending.email_token_id,
            VerificationEmailFlow::Signup,
        ))
        .await
        .expect("email");
    verify_email_token(&lab.valence, &pending.email_token_id)
        .await
        .expect("email verify");

    let challenge_id = issue_sms_challenge(
        &lab.valence,
        &lab.services,
        pending.user_id.clone(),
        "+15555550101",
    )
    .await
    .expect("sms issue");

    let factors = FactorChallengeService::new(Arc::clone(&lab.services));
    let ok = factors
        .verify_sms_otp(&challenge_id, "000000000000", &lab.valence)
        .await
        .expect("verify call");
    assert!(!ok, "wrong OTP must not verify");

    let email_ok = primary_email_verified(&lab.valence, &pending.user_id)
        .await
        .expect("email flag");
    let phone_ok = primary_phone_verified(&lab.valence, &pending.user_id)
        .await
        .expect("phone flag");
    assert!(email_ok);
    assert!(!phone_ok);
    let confirm = confirm_user(&lab.valence, &pending.user_id).await;
    assert!(confirm.is_err(), "confirm blocked without phone");
}

#[tokio::test]
async fn ci_e2e_device_totp_challenge_happy() {
    let lab = boot_lab("ci_e2e_device_totp").await.expect("lab");
    let codes = TestCodeSource::new(Arc::clone(&lab.test_sms));
    let signup = run_signup_verify_flow(
        &lab.valence,
        &lab.services,
        &codes,
        "Alex Rivera",
        "e2e-device-totp@example.test",
        "+15555550110",
        "CorrectHorseBattery1!",
        SignupVerifyOpts::default(),
    )
    .await
    .expect("signup");
    assert!(signup.confirmed);

    let outcome = run_device_totp_challenge_flow(
        &lab.valence,
        &lab.services,
        &signup.user_id,
        "Test Browser",
        "e2e-device-totp@example.test",
        "Lepton Auth",
        &TestTotpCodeSource,
    )
    .await
    .expect("device+totp");
    assert!(outcome.device_trusted);
    assert!(outcome.totp_enabled);
    assert!(outcome.challenge_ok);

    let devices = list_auth_devices(&lab.valence, &signup.user_id)
        .await
        .expect("list");
    let trusted = devices
        .iter()
        .find(|d| d.id == outcome.device_id)
        .expect("device row");
    assert!(trusted.trusted_at.is_some());
}

#[tokio::test]
async fn ci_e2e_device_confirm_rejected() {
    let lab = boot_lab("ci_e2e_device_sad").await.expect("lab");
    let codes = TestCodeSource::new(Arc::clone(&lab.test_sms));
    let signup = run_signup_verify_flow(
        &lab.valence,
        &lab.services,
        &codes,
        "Casey Device Sad",
        "e2e-device-sad@example.test",
        "+15555550111",
        "CorrectHorseBattery1!",
        SignupVerifyOpts::default(),
    )
    .await
    .expect("signup");

    let pending = register_auth_device(
        &lab.valence,
        &signup.user_id,
        AuthDeviceKind::TrustedBrowser,
        "Test Browser",
    )
    .await
    .expect("register");
    let err = confirm_auth_device(
        &lab.valence,
        &signup.user_id,
        &pending.device_id,
        "wrong-code",
    )
    .await
    .expect_err("bad confirm");
    assert_eq!(err.reason_class(), "device_mismatch");
    assert!(!err.to_string().contains("wrong-code"));

    let devices = list_auth_devices(&lab.valence, &signup.user_id)
        .await
        .expect("list");
    let row = devices
        .iter()
        .find(|d| d.id == pending.device_id)
        .expect("device");
    assert!(row.trusted_at.is_none(), "device must stay pending");
}

#[tokio::test]
async fn ci_e2e_totp_enroll_rejected() {
    let lab = boot_lab("ci_e2e_totp_enroll_sad").await.expect("lab");
    let codes = TestCodeSource::new(Arc::clone(&lab.test_sms));
    let signup = run_signup_verify_flow(
        &lab.valence,
        &lab.services,
        &codes,
        "Casey Totp Enroll Sad",
        "e2e-totp-enroll-sad@example.test",
        "+15555550112",
        "CorrectHorseBattery1!",
        SignupVerifyOpts::default(),
    )
    .await
    .expect("signup");

    let pending = begin_totp_enroll(
        &lab.valence,
        &signup.user_id,
        "e2e-totp-enroll-sad@example.test",
        "Lepton Auth",
    )
    .await
    .expect("begin");
    assert!(pending
        .otpauth_uri
        .contains("e2e-totp-enroll-sad%40example.test"));
    assert!(pending.otpauth_uri.contains("issuer=Lepton%20Auth"));
    let err = confirm_totp_enroll(&lab.valence, &signup.user_id, &pending.factor_id, "000000")
        .await
        .expect_err("bad enroll code");
    assert_eq!(err.reason_class(), "mismatch");
    assert!(!err.to_string().contains("000000"));

    let factors = FactorChallengeService::new(Arc::clone(&lab.services));
    let challenge_err = factors
        .verify_totp_code(&lab.valence, &signup.user_id, "000000")
        .await
        .expect_err("factor not enabled");
    assert!(matches!(
        challenge_err,
        FactorChallengeError::TotpUnavailable
    ));
    assert_eq!(challenge_err.reason_class(), "totp_unavailable");
}

#[tokio::test]
async fn ci_e2e_totp_challenge_rejected() {
    let lab = boot_lab("ci_e2e_totp_challenge_sad").await.expect("lab");
    let codes = TestCodeSource::new(Arc::clone(&lab.test_sms));
    let signup = run_signup_verify_flow(
        &lab.valence,
        &lab.services,
        &codes,
        "Casey Totp Challenge Sad",
        "e2e-totp-challenge-sad@example.test",
        "+15555550113",
        "CorrectHorseBattery1!",
        SignupVerifyOpts::default(),
    )
    .await
    .expect("signup");

    let pending = begin_totp_enroll(
        &lab.valence,
        &signup.user_id,
        "e2e-totp-challenge-sad@example.test",
        "Lepton Auth",
    )
    .await
    .expect("begin");
    let secret = totp_secret_from_otpauth_uri(&pending.otpauth_uri).expect("secret");
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret).to_bytes().expect("bytes"),
    )
    .expect("totp");
    let code = totp.generate_current().expect("code");
    confirm_totp_enroll(&lab.valence, &signup.user_id, &pending.factor_id, &code)
        .await
        .expect("enroll");

    let factors = FactorChallengeService::new(Arc::clone(&lab.services));
    let challenge_err = factors
        .verify_totp_code(&lab.valence, &signup.user_id, "000000")
        .await
        .expect_err("wrong challenge");
    assert!(matches!(challenge_err, FactorChallengeError::TotpInvalid));
    assert_eq!(challenge_err.reason_class(), "mismatch");
    let msg = challenge_err.to_string();
    assert!(!msg.contains("000000"));
}

fn mock_oauth_cfg() -> OAuthClientConfig {
    OAuthClientConfig {
        public_base_url: "http://127.0.0.1:8765".into(),
        redirect_path: "/auth/oauth/callback".into(),
        google_client_id: None,
        google_client_secret: None,
        github_client_id: None,
        github_client_secret: None,
        use_mock_provider: true,
        mock_oidc_issuer_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    }
}

#[tokio::test]
async fn ci_e2e_oauth_signup_login_happy() {
    let valence = boot_valence("ci_e2e_oauth_happy").await.expect("valence");
    let cfg = mock_oauth_cfg();
    let outcome = run_oauth_signup_login_flow(
        &valence,
        &cfg,
        OAuthProvider::Google,
        &MockOAuthCodeSource,
        OAuthSignupLoginOpts::default(),
    )
    .await
    .expect("oauth signup+login");
    assert_eq!(outcome.signup_user_id, outcome.login_user_id);
}

#[tokio::test]
async fn ci_e2e_oauth_github_signup_login_happy() {
    let valence = boot_valence("ci_e2e_oauth_github_happy")
        .await
        .expect("valence");
    let cfg = mock_oauth_cfg();
    let outcome = run_oauth_signup_login_flow(
        &valence,
        &cfg,
        OAuthProvider::GitHub,
        &MockOAuthCodeSource,
        OAuthSignupLoginOpts::default(),
    )
    .await
    .expect("oauth github signup+login");
    assert_eq!(outcome.signup_user_id, outcome.login_user_id);
}

#[tokio::test]
async fn ci_e2e_oauth_state_mismatch_sad() {
    let valence = boot_valence("ci_e2e_oauth_state_sad")
        .await
        .expect("valence");
    let cfg = mock_oauth_cfg();
    let start = begin_oauth(&cfg, &valence, OAuthProvider::Google, OAuthIntent::Signup)
        .await
        .expect("begin");
    let err = complete_oauth(
        &cfg,
        &valence,
        OAuthProvider::Google,
        "not-the-real-state",
        "mock-code",
    )
    .await
    .expect_err("state mismatch");
    assert!(matches!(err, OAuthError::State));
    assert_eq!(err.reason_class(), "oauth_state");
    assert!(!err.to_string().contains("mock-code"));
    let _ = start;
}

#[tokio::test]
async fn ci_e2e_device_binding_issue_verify_happy() {
    let lab = boot_lab("ci_e2e_device_binding").await.expect("lab");
    let codes = TestCodeSource::new(Arc::clone(&lab.test_sms));
    let signup = run_signup_verify_flow(
        &lab.valence,
        &lab.services,
        &codes,
        "Bind Device",
        "e2e-bind@example.test",
        "+15555550120",
        "CorrectHorseBattery1!",
        SignupVerifyOpts::default(),
    )
    .await
    .expect("signup");

    let pending = register_auth_device(
        &lab.valence,
        &signup.user_id,
        AuthDeviceKind::TrustedBrowser,
        "Bind browser",
    )
    .await
    .expect("register");
    confirm_auth_device(
        &lab.valence,
        &signup.user_id,
        &pending.device_id,
        &pending.confirm_code,
    )
    .await
    .expect("confirm");

    let cookie = issue_device_binding(&lab.valence, &signup.user_id, &pending.device_id)
        .await
        .expect("issue");
    let parsed = DeviceBindingCookie::parse(&cookie.encode()).expect("parse");
    let device_id = verify_device_binding(&lab.valence, &signup.user_id, &parsed)
        .await
        .expect("verify");
    assert_eq!(device_id, pending.device_id);

    let bad = DeviceBindingCookie {
        device_id: pending.device_id.clone(),
        secret: "wrong-secret".into(),
    };
    let err = verify_device_binding(&lab.valence, &signup.user_id, &bad)
        .await
        .expect_err("bad secret");
    assert_eq!(err.reason_class(), "device_binding");

    revoke_auth_device(&lab.valence, &signup.user_id, &pending.device_id)
        .await
        .expect("revoke");
    let err = verify_device_binding(&lab.valence, &signup.user_id, &cookie)
        .await
        .expect_err("revoked");
    assert!(
        err.reason_class() == "device_revoked" || err.reason_class() == "device_binding",
        "{}",
        err.reason_class()
    );
}

#[tokio::test]
async fn ci_e2e_factor_bound_device_skip_happy() {
    let lab = boot_lab("ci_e2e_factor_bound_skip").await.expect("lab");
    let codes = TestCodeSource::new(Arc::clone(&lab.test_sms));
    let signup = run_signup_verify_flow(
        &lab.valence,
        &lab.services,
        &codes,
        "Factor Skip",
        "e2e-factor-skip@example.test",
        "+15555550121",
        "CorrectHorseBattery1!",
        SignupVerifyOpts::default(),
    )
    .await
    .expect("signup");

    let outcome = run_device_totp_challenge_flow(
        &lab.valence,
        &lab.services,
        &signup.user_id,
        "Skip Browser",
        "e2e-factor-skip@example.test",
        "Lepton Auth",
        &TestTotpCodeSource,
    )
    .await
    .expect("device+totp");

    let factors = FactorChallengeService::new(Arc::clone(&lab.services));
    factors
        .verify_totp_or_bound_device(
            &lab.valence,
            &signup.user_id,
            Some(&outcome.device_id),
            None,
        )
        .await
        .expect("bound device skip");

    let err = factors
        .verify_totp_or_bound_device(&lab.valence, &signup.user_id, None, Some("000000"))
        .await
        .expect_err("bad totp");
    assert!(matches!(err, FactorChallengeError::TotpInvalid));

    revoke_auth_device(&lab.valence, &signup.user_id, &outcome.device_id)
        .await
        .expect("revoke");
    let err = factors
        .verify_totp_or_bound_device(
            &lab.valence,
            &signup.user_id,
            Some(&outcome.device_id),
            None,
        )
        .await
        .expect_err("revoked requires totp");
    assert!(
        matches!(err, FactorChallengeError::TotpInvalid)
            || matches!(err, FactorChallengeError::TotpUnavailable),
        "{err:?}"
    );
}
