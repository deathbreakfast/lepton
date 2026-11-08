//! Integration tests for public auth boundary contracts (password, referer, tokens).
//!
//! These lock the crate surface from outside the library binary. Requires `--features ssr`
//! for token lifecycle / Argon2 verification APIs.

use chrono::{Duration, Utc};
use lepton_auth::account_api::{mask_email_for_display, role_badge_from_roles};
use lepton_auth::paths::{SIGNIN, SIGNUP};
use lepton_auth::routes::{
    parse_referer_from_search, parse_token_from_url_parts, sanitize_referer_path,
};
use lepton_auth::security::{
    password_policy_error_message, password_requirement_results, random_token_part,
    PASSWORD_MIN_LENGTH,
};
use lepton_auth::token_helpers::{
    ensure_token_lifecycle_valid, verify_token_secret, TokenLifecycleError,
};
use lepton_host_adapter::generated::OneTimeTokenLifecycleFields;
use lepton_identity::auth::hash_password;
use valence::RecordId;

struct StubLifecycleToken {
    user: RecordId,
    token_hash: String,
    expires_at: chrono::DateTime<Utc>,
    used_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
}

impl OneTimeTokenLifecycleFields for StubLifecycleToken {
    fn user(&self) -> &RecordId {
        &self.user
    }

    fn token_hash(&self) -> &String {
        &self.token_hash
    }

    fn expires_at(&self) -> &chrono::DateTime<Utc> {
        &self.expires_at
    }

    fn used_at(&self) -> Option<&chrono::DateTime<Utc>> {
        self.used_at.as_ref()
    }

    fn created_at(&self) -> &chrono::DateTime<Utc> {
        &self.created_at
    }
}

fn fresh_token() -> StubLifecycleToken {
    let now = Utc::now();
    StubLifecycleToken {
        user: RecordId::new("user", "integ"),
        token_hash: "unused-in-lifecycle".to_string(),
        expires_at: now + Duration::minutes(30),
        used_at: None,
        created_at: now,
    }
}

#[test]
fn password_policy_strong_password_happy_path() {
    let password = "ValidPass123!";
    assert!(password.chars().count() >= PASSWORD_MIN_LENGTH);
    assert!(password_requirement_results(password)
        .iter()
        .all(|item| item.satisfied));
    assert!(password_policy_error_message(password).is_none());
}

#[test]
fn password_policy_rejects_weak_password_sad() {
    let message =
        password_policy_error_message("short").expect("weak password must produce a policy error");
    assert!(message.contains("Password does not meet requirements"));
    assert!(message.contains("At least 12 characters"));
}

#[test]
fn sanitize_referer_accepts_in_app_path_happy_path() {
    assert_eq!(
        sanitize_referer_path(Some("/counter/high-scores".to_string())),
        "/counter/high-scores"
    );
    assert_eq!(
        parse_referer_from_search("?referer=%2Fdashboard"),
        Some("/dashboard".to_string())
    );
}

#[test]
fn sanitize_referer_rejects_unsafe_paths_sad() {
    assert_eq!(
        sanitize_referer_path(Some("//evil.example".to_string())),
        "/"
    );
    assert_eq!(sanitize_referer_path(Some(SIGNIN.to_string())), "/");
    assert_eq!(sanitize_referer_path(Some(SIGNUP.to_string())), "/");
    assert_eq!(sanitize_referer_path(Some("/api/secret".to_string())), "/");
    assert_eq!(sanitize_referer_path(Some("/api".to_string())), "/");
    assert_eq!(sanitize_referer_path(Some("/auth".to_string())), "/");
    assert_eq!(
        sanitize_referer_path(Some("%2F%2Fevil.example".to_string())),
        "/"
    );
    assert_eq!(sanitize_referer_path(Some("/home".to_string())), "/");
    assert_eq!(sanitize_referer_path(None), "/");
}

#[test]
fn parse_token_from_url_parts_fragment_and_legacy_query() {
    assert_eq!(
        parse_token_from_url_parts("?token=legacy", "#token=preferred"),
        Some("preferred".to_string())
    );
    assert_eq!(
        parse_token_from_url_parts("?token=legacy", ""),
        Some("legacy".to_string())
    );
}

#[test]
fn verify_token_secret_matching_hash_happy_path() {
    let token = "one-time-integ-secret";
    let hash = hash_password(token).expect("hash_password");
    assert!(verify_token_secret(token, &hash).is_ok());
}

#[test]
fn verify_token_secret_mismatch_and_garbage_sad() {
    let hash = hash_password("one-time-integ-secret").expect("hash_password");
    assert!(matches!(
        verify_token_secret("wrong-secret", &hash),
        Err(TokenLifecycleError::Invalid)
    ));
    assert!(matches!(
        verify_token_secret("anything", "not-a-phc-hash"),
        Err(TokenLifecycleError::Invalid)
    ));
}

#[test]
fn ensure_token_lifecycle_valid_fresh_token_happy_path() {
    let token = fresh_token();
    assert!(ensure_token_lifecycle_valid(&token).is_ok());
}

#[test]
fn ensure_token_lifecycle_rejects_used_and_expired_sad() {
    let mut used = fresh_token();
    used.used_at = Some(Utc::now());
    assert!(matches!(
        ensure_token_lifecycle_valid(&used),
        Err(TokenLifecycleError::Used)
    ));
    assert_eq!(
        TokenLifecycleError::Used.message(),
        "Token has already been used"
    );

    let mut expired = fresh_token();
    expired.expires_at = Utc::now() - Duration::minutes(1);
    assert!(matches!(
        ensure_token_lifecycle_valid(&expired),
        Err(TokenLifecycleError::Expired)
    ));
    assert_eq!(TokenLifecycleError::Expired.message(), "Token has expired");
}

#[test]
fn random_token_part_hex_length_happy_path() {
    let part = random_token_part(12);
    assert_eq!(part.len(), 24);
    assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn mask_email_and_role_badge_happy_path() {
    assert_eq!(
        mask_email_for_display("jordan@example.com"),
        "jo****@example.com"
    );
    assert_eq!(
        role_badge_from_roles(&["member".into(), "owner".into()]),
        "owner"
    );
    assert_eq!(
        role_badge_from_roles(&["super_admin".into(), "owner".into()]),
        "super_admin"
    );
}

#[test]
fn mask_email_and_role_badge_fallback_sad() {
    assert_eq!(mask_email_for_display("not-an-email"), "****");
    assert_eq!(mask_email_for_display("@example.com"), "em****@example.com");
    assert_eq!(role_badge_from_roles(&[]), "member");
    assert_eq!(role_badge_from_roles(&["unknown".into()]), "member");
}
