//! Builder integration tests against in-memory Valence (TM-1, TM-2, TM-5).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use lepton_e2e::boot::boot_valence;
use lepton_host_adapter::generated::{AccountEmail, User as IdentityUser};
use lepton_identity::ownership::bare_id_from_record;
use lepton_test_support::builder::{TestUserBuilder, HARNESS_TOTP_SECRET};
use lepton_test_support::SeedError;
use valence::Model;

#[tokio::test]
async fn builder_verified_email_happy() {
    let v = boot_valence("builder_verified").await.expect("boot");
    let user = TestUserBuilder::new()
        .email("verified@example.test")
        .password("CorrectHorseBattery1!")
        .verified_email()
        .build(&v)
        .await
        .expect("build");

    let email = AccountEmail::get(&bare_id_from_record(&user.email_id), &v, valence::use_!(r"**Test:** Fixture **Account Email** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get email")
        .expect("email row");
    assert!(email.verified_at().is_some());

    let identity = IdentityUser::get(&bare_id_from_record(&user.user_id), &v, valence::use_!(r"**Test:** Fixture **Identity User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get user")
        .expect("user row");
    assert!(identity.primary_email().is_some());
    assert_eq!(user.email, "verified@example.test");
    assert!(user.reset_token.is_none());
    assert!(user.totp_secret.is_none());
}

#[tokio::test]
async fn builder_unverified_email_happy() {
    let v = boot_valence("builder_unverified").await.expect("boot");
    let user = TestUserBuilder::new()
        .email("pending@example.test")
        .unverified_email()
        .build(&v)
        .await
        .expect("build");
    let email = AccountEmail::get(&bare_id_from_record(&user.email_id), &v, valence::use_!(r"**Test:** Fixture **Account Email** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get email")
        .expect("email row");
    assert!(email.verified_at().is_none());
}

#[tokio::test]
async fn builder_phone_confirm_totp_reset_happy() {
    let v = boot_valence("builder_variants").await.expect("boot");

    let ready = TestUserBuilder::new()
        .email("ready@example.test")
        .verified_email()
        .with_verified_phone()
        .build(&v)
        .await
        .expect("ready");
    assert!(ready.user_id.to_string().contains(':') || !ready.user_id.to_string().is_empty());

    let done = TestUserBuilder::new()
        .email("done@example.test")
        .verified_email()
        .with_verified_phone()
        .confirmed()
        .build(&v)
        .await
        .expect("confirmed");
    assert!(done.reset_token.is_none());

    let totp = TestUserBuilder::new()
        .email("totp@example.test")
        .verified_email()
        .with_totp()
        .build(&v)
        .await
        .expect("totp");
    assert_eq!(totp.totp_secret.as_deref(), Some(HARNESS_TOTP_SECRET));

    let reset = TestUserBuilder::new()
        .email("reset@example.test")
        .verified_email()
        .with_reset_token()
        .build(&v)
        .await
        .expect("reset");
    assert!(reset.reset_token.as_ref().is_some_and(|t| t.len() >= 8));
}

#[tokio::test]
async fn builder_empty_email_sad() {
    let v = boot_valence("builder_empty_email").await.expect("boot");
    let err = TestUserBuilder::new()
        .email("   ")
        .verified_email()
        .build(&v)
        .await
        .expect_err("empty email");
    assert!(matches!(
        err,
        SeedError::InvalidInput {
            reason: "empty_email"
        }
    ));
}

#[tokio::test]
async fn builder_confirm_without_phone_sad() {
    let v = boot_valence("builder_confirm_sad").await.expect("boot");
    let err = TestUserBuilder::new()
        .email("nophone@example.test")
        .verified_email()
        .confirmed()
        .build(&v)
        .await
        .expect_err("confirm needs phone");
    assert!(matches!(
        err,
        SeedError::InvalidInput {
            reason: "confirm_requires_verified_email_and_phone"
        }
    ));
}
