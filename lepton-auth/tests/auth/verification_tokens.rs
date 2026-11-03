//! Valence-backed email verification token issue + consume roundtrip.
//!
//! Uses in-memory Valence with a tolerant unique-index wrapper so
//! `AccountEmail::create` (unique `address`) and token `get` after upsert both work.
//! SQLite rejects Surreal-shaped unique probes (`no such column: VALUE`).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::support;

use chrono::{Duration, Utc};
use lepton_auth::token_helpers::{
    consume_email_verification_token, email_resend_wait_secs, email_verification_challenge_id,
    issue_email_verification_token, issue_phone_verification_token,
    try_consume_phone_verification_token, TokenLifecycleError, EMAIL_OTP_DIGIT_LEN,
    EMAIL_RESEND_COOLDOWN_SECS,
};
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::EmailVerificationToken;
use lepton_identity::generated::{
    Account, AccountEmail, AccountMembership, AccountMembershipRole, AccountPhone, AccountPlan,
    AccountStatus, User as IdentityUser, UserStatus, UserUserType,
};
use valence::Model;

use support::system_valence;

async fn seed_user(
    valence: &valence::Valence,
) -> (valence::RecordId, valence::RecordId, valence::RecordId) {
    let password_hash = hash_password("CorrectHorseBattery1!").expect("hash");
    let now = Utc::now();
    let user = IdentityUser::new(
        Some(UserUserType::Person),
        Some(password_hash),
        Some(UserStatus::Active),
        None,
        None,
        None,
        None,
        None,
        now,
        now,
    )
    .expect("user");
    let created = IdentityUser::create(user, valence, valence::use_!("**Test:** Fixture **Identity User** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await.expect("create");
    let user_id = created.id().cloned().expect("id");

    let account = Account::new(
        "token-user@example.test".to_string(),
        user_id.clone(),
        Some(AccountPlan::Free),
        Some(AccountStatus::Active),
        None,
        None,
        now,
        now,
    )
    .expect("account");
    let account_created = Account::create(account, valence, valence::use_!("**Test:** Fixture **Account** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("create account");
    let account_id = account_created.id().cloned().expect("account id");

    let membership = AccountMembership::new(
        account_id.clone(),
        user_id.clone(),
        AccountMembershipRole::Owner,
        now,
        now,
    )
    .expect("membership");
    AccountMembership::create(membership, valence, valence::use_!("**Test:** Fixture **Account Membership** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("create membership");

    let email = AccountEmail::new(
        account_id.clone(),
        "token-user@example.test".to_string(),
        None,
        now,
        now,
    )
    .expect("email");
    let email_created = AccountEmail::create(email, valence, valence::use_!("**Test:** Fixture **Account Email** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("email create");
    let email_id = email_created.id().cloned().expect("email id");
    (user_id, email_id, account_id)
}

/// Misses before the fifth locks the token (mirrors `attempt_throttle::MAX_FAILED_ATTEMPTS`).
const LOCKOUT_MISSES: i64 = 5;

fn wrong_code(right: &str) -> String {
    let wrong = if right == "000000" {
        "111111"
    } else {
        "000000"
    };
    wrong.to_string()
}

async fn consume(
    valence: &valence::Valence,
    user: &valence::RecordId,
    code: &str,
) -> Result<EmailVerificationToken, TokenLifecycleError> {
    consume_email_verification_token(valence, user, code)
        .await
        .expect("store")
}

async fn stored_token(
    valence: &valence::Valence,
    user: &valence::RecordId,
) -> EmailVerificationToken {
    EmailVerificationToken::get(&email_verification_challenge_id(user), valence, valence::use_!(r#"**Test:** Fixture **Email Verification Token** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("get")
        .expect("token exists")
}

#[tokio::test]
async fn issue_and_consume_one_time_token_happy_path() {
    let valence = system_valence("verification_tokens_happy").await;
    let (user, email, _) = seed_user(&valence).await;
    let code = issue_email_verification_token(&valence, user.clone(), email)
        .await
        .expect("issue");
    assert_eq!(code.len(), EMAIL_OTP_DIGIT_LEN);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    assert!(consume(&valence, &user, &code).await.is_ok());
    // Single use: the same code is refused the second time.
    assert_eq!(
        consume(&valence, &user, &code).await.unwrap_err(),
        TokenLifecycleError::Used
    );
}

#[tokio::test]
async fn consume_without_issued_token_is_invalid() {
    let valence = system_valence("verification_tokens_miss").await;
    let (user, _, _) = seed_user(&valence).await;
    assert_eq!(
        consume(&valence, &user, "123456").await.unwrap_err(),
        TokenLifecycleError::Invalid
    );
}

#[tokio::test]
async fn wrong_code_counts_then_locks_on_fifth_miss() {
    let valence = system_valence("verification_tokens_lockout").await;
    let (user, email, _) = seed_user(&valence).await;
    let code = issue_email_verification_token(&valence, user.clone(), email)
        .await
        .expect("issue");
    let bad = wrong_code(&code);

    for expected in 1..LOCKOUT_MISSES {
        assert_eq!(
            consume(&valence, &user, &bad).await.unwrap_err(),
            TokenLifecycleError::Invalid
        );
        assert_eq!(
            stored_token(&valence, &user)
                .await
                .failed_attempts()
                .copied(),
            Some(expected)
        );
    }
    assert_eq!(
        consume(&valence, &user, &bad).await.unwrap_err(),
        TokenLifecycleError::Locked
    );
    // Locked: even the right code is refused.
    assert_eq!(
        consume(&valence, &user, &code).await.unwrap_err(),
        TokenLifecycleError::Locked
    );
}

#[tokio::test]
async fn lockout_ends_and_right_code_then_works() {
    let valence = system_valence("verification_tokens_lock_expiry").await;
    let (user, email, _) = seed_user(&valence).await;
    let code = issue_email_verification_token(&valence, user.clone(), email)
        .await
        .expect("issue");
    let bad = wrong_code(&code);
    for _ in 0..LOCKOUT_MISSES {
        let _ = consume(&valence, &user, &bad).await;
    }
    stored_token(&valence, &user)
        .await
        .get_mutable(&valence, valence::use_!(r#"**Test:** Fixture **Email Verification Token** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .set_locked_until(Utc::now() - Duration::seconds(1))
        .expect("set")
        .commit()
        .await
        .expect("commit");
    assert!(consume(&valence, &user, &code).await.is_ok());
}

#[tokio::test]
async fn reissue_keeps_a_running_lockout_but_clears_old_misses() {
    let valence = system_valence("verification_tokens_reissue").await;
    let (user, email, _) = seed_user(&valence).await;
    let code = issue_email_verification_token(&valence, user.clone(), email.clone())
        .await
        .expect("issue");
    let bad = wrong_code(&code);
    let _ = consume(&valence, &user, &bad).await;
    let fresh = issue_email_verification_token(&valence, user.clone(), email.clone())
        .await
        .expect("reissue");
    assert_eq!(stored_token(&valence, &user).await.failed_attempts(), None);
    // The old code no longer works once a new one replaced it (unless the draw repeats).
    if fresh != code {
        assert_eq!(
            consume(&valence, &user, &code).await.unwrap_err(),
            TokenLifecycleError::Invalid
        );
    }
    let bad = wrong_code(&fresh);
    for _ in 0..LOCKOUT_MISSES {
        let _ = consume(&valence, &user, &bad).await;
    }
    let newest = issue_email_verification_token(&valence, user.clone(), email)
        .await
        .expect("reissue while locked");
    assert_eq!(
        consume(&valence, &user, &newest).await.unwrap_err(),
        TokenLifecycleError::Locked
    );
}

#[tokio::test]
async fn expired_code_is_refused() {
    let valence = system_valence("verification_tokens_expired").await;
    let (user, email, _) = seed_user(&valence).await;
    let code = issue_email_verification_token(&valence, user.clone(), email)
        .await
        .expect("issue");
    stored_token(&valence, &user)
        .await
        .get_mutable(&valence, valence::use_!(r#"**Test:** Fixture **Email Verification Token** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .set_expires_at(Utc::now() - Duration::seconds(1))
        .expect("set")
        .commit()
        .await
        .expect("commit");
    assert_eq!(
        consume(&valence, &user, &code).await.unwrap_err(),
        TokenLifecycleError::Expired
    );
}

#[tokio::test]
async fn resend_waits_out_the_cooldown() {
    let valence = system_valence("verification_tokens_resend").await;
    let (user, email, _) = seed_user(&valence).await;
    assert_eq!(
        email_resend_wait_secs(&valence, &user).await.expect("wait"),
        None
    );
    issue_email_verification_token(&valence, user.clone(), email)
        .await
        .expect("issue");
    let wait = email_resend_wait_secs(&valence, &user)
        .await
        .expect("wait")
        .expect("inside cooldown");
    assert!((1..=EMAIL_RESEND_COOLDOWN_SECS).contains(&wait));
    stored_token(&valence, &user)
        .await
        .get_mutable(&valence, valence::use_!(r#"**Test:** Fixture **Email Verification Token** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .set_created_at(Utc::now() - Duration::seconds(EMAIL_RESEND_COOLDOWN_SECS + 1))
        .expect("set")
        .commit()
        .await
        .expect("commit");
    assert_eq!(
        email_resend_wait_secs(&valence, &user).await.expect("wait"),
        None
    );
}

async fn seed_user_with_phone(
    valence: &valence::Valence,
) -> (valence::RecordId, valence::RecordId) {
    let (user_id, _, account_id) = seed_user(valence).await;
    let now = Utc::now();
    let phone =
        AccountPhone::new(account_id, "+15551234567".to_string(), None, now, now).expect("phone");
    let created = AccountPhone::create(phone, valence, valence::use_!("**Test:** Fixture **Account Phone** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("phone create");
    let phone_id = created.id().cloned().expect("phone id");
    (user_id, phone_id)
}

#[tokio::test]
async fn issue_and_consume_phone_otp_six_digits_happy() {
    let valence = system_valence("verification_tokens_phone").await;
    let (user, phone_id) = seed_user_with_phone(&valence).await;
    let issued = issue_phone_verification_token(&valence, user, phone_id)
        .await
        .expect("issue");
    assert_eq!(issued.otp_code.len(), 6);
    assert!(issued.otp_code.chars().all(|c| c.is_ascii_digit()));

    let consumed =
        try_consume_phone_verification_token(&issued.challenge_id, &issued.otp_code, &valence)
            .await
            .expect("consume");
    assert!(consumed.is_some());

    let again =
        try_consume_phone_verification_token(&issued.challenge_id, &issued.otp_code, &valence)
            .await
            .expect("second consume");
    assert!(again.is_none());
}
