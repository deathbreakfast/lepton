//! `backfill_email_display_names` resets public display names that contain an email address.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::support;

use chrono::Utc;
use lepton_host_adapter::generated::{User, UserProfile, UserStatus, UserUserType};
use lepton_identity::ownership::bare_id_from_record;
use lepton_identity::profiles::{backfill_email_display_names, DEFAULT_DISPLAY_NAME};
use support::{system_valence, user_valence};
use valence::{Error, Model};

/// Seed a user and a profile with `display_name`; returns (user bare id, profile bare id).
async fn seed_profile(valence: &valence::Valence, display_name: &str) -> (String, String) {
    let now = Utc::now();
    let user = User::new(
        Some(UserUserType::Person),
        None,
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
    let user = User::create(
        user,
        valence,
        valence::use_!(
            r"**Test:** the display name backfill suite seeds a **user** to own a profile."
        ),
    )
    .await
    .expect("create user");
    let user_id = user.id().cloned().expect("user id");
    let profile = UserProfile::new(
        user_id.clone(),
        "Legal Name".to_string(),
        display_name.to_string(),
        now,
        now,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("profile");
    let profile = UserProfile::create(profile, valence, valence::use_!(r"**Test:** the display name backfill suite seeds a **profile** with a chosen display name."))
        .await
        .expect("create profile");
    (
        bare_id_from_record(&user_id),
        bare_id_from_record(profile.id().expect("profile id")),
    )
}

async fn display_name(valence: &valence::Valence, profile: &str) -> String {
    UserProfile::get(profile, valence, valence::use_!(r"**Test:** the display name backfill suite **reloads a profile** to check its display name."))
        .await
        .expect("get profile")
        .expect("profile row")
        .display_name()
        .clone()
}

#[tokio::test]
async fn backfill_resets_email_display_names_happy_path() {
    let sys = system_valence("display_name_backfill").await;
    let (_, leaked) = seed_profile(&sys, "alice@example.com").await;
    let (_, chosen) = seed_profile(&sys, "Pat").await;

    assert_eq!(
        backfill_email_display_names(&sys).await.expect("backfill"),
        1
    );
    assert_eq!(display_name(&sys, &leaked).await, DEFAULT_DISPLAY_NAME);
    assert_eq!(display_name(&sys, &chosen).await, "Pat");

    // Nothing left to change on a second run.
    assert_eq!(backfill_email_display_names(&sys).await.expect("rerun"), 0);
}

#[tokio::test]
async fn backfill_as_signed_in_user_is_refused_sad() {
    let sys = system_valence("display_name_backfill_user").await;
    let (_, alice_profile) = seed_profile(&sys, "alice@example.com").await;
    let (bob, _) = seed_profile(&sys, "Bob").await;

    let bob_v = user_valence(&sys, &bob);
    let err = backfill_email_display_names(&bob_v)
        .await
        .expect_err("a user handle must not rewrite another user's profile");
    assert!(matches!(err, Error::Privacy(_)), "got {err:?}");
    assert_eq!(
        display_name(&sys, &alice_profile).await,
        "alice@example.com"
    );
}
