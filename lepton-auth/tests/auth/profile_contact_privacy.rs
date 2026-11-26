//! `UserProfile` contact fields: owner-only by default, readable by signed-in users only
//! when the owner shares that field, and erased with the user.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::support;

use crate::service_users_support;

use chrono::Utc;
use lepton_auth::identity_delete::delete_user;
use lepton_host_adapter::generated::{
    UserProfile, UserProfileChatHandleShare, UserProfileContactEmailShare,
    UserProfileContactPhoneShare,
};
use lepton_identity::ownership::bare_id_from_record;
use service_users_support::seed_user;
use support::{system_valence, user_valence};
use valence::{Actor, Model, RecordId, Valence};

const EMAIL: &str = "alice@example.test";
const PHONE: &str = "+15555550123";
const HANDLE: &str = "@alice:chat.example.test";

/// **Test:** `owner` and `peer` users, and a profile for `owner` that the owner fills in
/// with all three contact fields, sharing only the email with signed-in users.
async fn seed_profile(sys: &Valence, owner: &str, peer: &str) -> String {
    seed_user(sys, owner).await;
    seed_user(sys, peer).await;
    let now = Utc::now();
    let profile = UserProfile::new(
        RecordId::new("user", owner),
        "Alice Example".into(),
        "Alice".into(),
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
    let profile = UserProfile::create(profile, sys, valence::use_!(r"**Test:** Fixture **User Profile** save for `tests` so the suite can check who reads the contact fields. CI and developers running the suite only."))
        .await
        .expect("create profile");
    let profile_bare = bare_id_from_record(profile.id().expect("profile id"));

    let owner_v = user_valence(sys, owner);
    let own = load(&owner_v, &profile_bare)
        .await
        .expect("owner reads own profile");
    own.get_mutable(&owner_v, valence::use_!(r"**Test:** Fixture **User Profile** edit for `tests` where the owner adds contact details and shares only the email. CI and developers running the suite only."))
        .set_contact_email(EMAIL.into())
        .expect("email")
        .set_contact_email_share(UserProfileContactEmailShare::SignedIn)
        .expect("email share")
        .set_contact_phone(PHONE.into())
        .expect("phone")
        .set_contact_phone_share(UserProfileContactPhoneShare::Owner)
        .expect("phone share")
        .set_chat_handle(HANDLE.into())
        .expect("chat handle")
        .commit()
        .await
        .expect("owner saves contact fields");
    profile_bare
}

async fn load(v: &Valence, profile_bare: &str) -> Option<UserProfile> {
    UserProfile::get(profile_bare, v, valence::use_!(r"**Test:** Fixture **User Profile** load for `tests` so the suite can assert which contact fields each reader gets back. CI and developers running the suite only."))
        .await
        .expect("get profile")
}

#[tokio::test]
async fn owner_reads_every_contact_field_happy() {
    let sys = system_valence("profile_contact_owner").await;
    let profile = seed_profile(&sys, "contact-alice", "contact-bob").await;

    let row = load(&user_valence(&sys, "contact-alice"), &profile)
        .await
        .expect("owner reads profile");
    assert_eq!(row.contact_email().map(String::as_str), Some(EMAIL));
    assert_eq!(row.contact_phone().map(String::as_str), Some(PHONE));
    assert_eq!(row.chat_handle().map(String::as_str), Some(HANDLE));
    assert_eq!(
        row.contact_email_share(),
        Some(&UserProfileContactEmailShare::SignedIn)
    );
    assert_eq!(row.chat_handle_share(), None, "unset means owner only");
}

#[tokio::test]
async fn signed_in_reader_gets_only_shared_fields_happy() {
    let sys = system_valence("profile_contact_reader").await;
    let profile = seed_profile(&sys, "contact-alice", "contact-bob").await;

    let row = load(&user_valence(&sys, "contact-bob"), &profile)
        .await
        .expect("signed-in user reads the profile");
    assert_eq!(row.display_name(), "Alice");
    assert_eq!(
        row.contact_email().map(String::as_str),
        Some(EMAIL),
        "shared with signed-in users"
    );
    assert_eq!(row.contact_phone(), None, "share setting is owner");
    assert_eq!(row.chat_handle(), None, "never shared");
    assert_eq!(
        row.contact_email_share(),
        None,
        "share settings are owner-only"
    );
}

#[tokio::test]
async fn unsharing_hides_the_field_again_sad() {
    let sys = system_valence("profile_contact_unshare").await;
    let profile = seed_profile(&sys, "contact-alice", "contact-bob").await;
    let owner_v = user_valence(&sys, "contact-alice");

    load(&owner_v, &profile)
        .await
        .expect("owner reads profile")
        .get_mutable(&owner_v, valence::use_!(r"**Test:** Fixture **User Profile** edit for `tests` where the owner stops sharing the contact email. CI and developers running the suite only."))
        .set_contact_email_share(UserProfileContactEmailShare::Owner)
        .expect("email share")
        .commit()
        .await
        .expect("owner unshares email");

    let row = load(&user_valence(&sys, "contact-bob"), &profile)
        .await
        .expect("signed-in user reads the profile");
    assert_eq!(row.contact_email(), None);
}

#[tokio::test]
async fn non_user_readers_get_no_contact_fields_sad() {
    let sys = system_valence("profile_contact_non_user").await;
    let profile = seed_profile(&sys, "contact-alice", "contact-bob").await;

    for actor in [
        Actor::ServiceUser {
            service_name: "svc:00000000-0000-4000-8000-000000000000".into(),
        },
        Actor::ServiceUser {
            service_name: "cron".into(),
        },
        Actor::Anonymous,
    ] {
        let v = sys.with_actor(actor.clone());
        let row = UserProfile::get(&profile, &v, valence::use_!(r"**Test:** Fixture **User Profile** load for `tests` so the suite can assert service users and anonymous callers get no contact fields. CI and developers running the suite only.")).await;
        if let Ok(Some(row)) = row {
            assert_eq!(row.contact_email(), None, "{actor:?}");
            assert_eq!(row.contact_phone(), None, "{actor:?}");
            assert_eq!(row.chat_handle(), None, "{actor:?}");
        }
    }
}

#[tokio::test]
async fn share_settings_apply_per_field_happy() {
    let sys = system_valence("profile_contact_per_field").await;
    let profile = seed_profile(&sys, "contact-alice", "contact-bob").await;
    let owner_v = user_valence(&sys, "contact-alice");

    load(&owner_v, &profile)
        .await
        .expect("owner reads profile")
        .get_mutable(&owner_v, valence::use_!(r"**Test:** Fixture **User Profile** edit for `tests` where the owner shares the chat handle and stops sharing the email. CI and developers running the suite only."))
        .set_contact_email_share(UserProfileContactEmailShare::Owner)
        .expect("email share")
        .set_chat_handle_share(UserProfileChatHandleShare::SignedIn)
        .expect("chat handle share")
        .commit()
        .await
        .expect("owner changes share settings");

    let row = load(&user_valence(&sys, "contact-bob"), &profile)
        .await
        .expect("signed-in user reads the profile");
    assert_eq!(row.contact_email(), None);
    assert_eq!(row.contact_phone(), None);
    assert_eq!(row.chat_handle().map(String::as_str), Some(HANDLE));
}

#[tokio::test]
async fn contact_fields_erased_with_the_user_happy() {
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    let sys = system_valence("profile_contact_erase").await;
    let profile = seed_profile(&sys, "contact-alice", "contact-bob").await;

    delete_user(&sys, &RecordId::new("user", "contact-alice"))
        .await
        .expect("erase alice");

    let backend = sys.backend_for_table("user_profile").expect("backend");
    let stored = valence::get_record(backend.as_ref(), "user_profile", &profile, valence::use_!(r"**Test:** Fixture raw read of a **User Profile** row for `tests` so the suite can assert contact details are gone after the user is erased, independent of privacy. CI and developers running the suite only."))
        .await
        .expect("raw read");
    assert!(
        stored.is_none(),
        "profile row and its contact fields are removed"
    );
}
