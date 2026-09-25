//! Valence-backed email verification token issue + consume roundtrip.
//!
//! Uses in-memory Valence with a tolerant unique-index wrapper so
//! `AccountEmail::create` (unique `address`) and token `get` after upsert both work.
//! SQLite rejects Surreal-shaped unique probes (`no such column: VALUE`).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_auth::token_helpers::{
    issue_email_verification_token, issue_phone_verification_token,
    try_consume_phone_verification_token,
};
use lepton_host_adapter::auth::hash_password;
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
    let created = IdentityUser::create(user, valence, valence::use_!(r#"**Test:** Fixture **Identity User** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#)).await.expect("create");
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
    let account_created = Account::create(account, valence, valence::use_!(r#"**Test:** Fixture **Account** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
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
    AccountMembership::create(membership, valence, valence::use_!(r#"**Test:** Fixture **Account Membership** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
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
    let email_created = AccountEmail::create(email, valence, valence::use_!(r#"**Test:** Fixture **Account Email** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("email create");
    let email_id = email_created.id().cloned().expect("email id");
    (user_id, email_id, account_id)
}

#[tokio::test]
async fn issue_and_consume_one_time_token_happy_path() {
    let valence = system_valence("verification_tokens_happy").await;
    let (user, email, _) = seed_user(&valence).await;
    let token_id = issue_email_verification_token(&valence, user, email)
        .await
        .expect("issue");
    let consumed =
        lepton_auth::token_helpers::try_consume_email_verification_token(&token_id, &valence)
            .await
            .expect("consume");
    assert!(consumed);
}

#[tokio::test]
async fn consume_unknown_token_returns_false() {
    let valence = system_valence("verification_tokens_miss").await;
    let consumed = lepton_auth::token_helpers::try_consume_email_verification_token(
        "missing-token-id",
        &valence,
    )
    .await
    .expect("consume");
    assert!(!consumed);
}

async fn seed_user_with_phone(
    valence: &valence::Valence,
) -> (valence::RecordId, valence::RecordId) {
    let (user_id, _, account_id) = seed_user(valence).await;
    let now = Utc::now();
    let phone =
        AccountPhone::new(account_id, "+15551234567".to_string(), None, now, now).expect("phone");
    let created = AccountPhone::create(phone, valence, valence::use_!(r#"**Test:** Fixture **Account Phone** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
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
