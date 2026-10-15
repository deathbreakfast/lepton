//! Bot lifecycle: create, handle clashes, edit, suspend, resume, delete
//! (TM-B1, TM-B3, TM-B4 gate error, TM-B5 creator, TM-B7).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/bots.rs"]
mod bots_support;

use bots_support::{install_test_gate, seed_bot, seed_user, stored_bot, stored_bot_count};
use lepton_auth::bots::{
    create_bot, delete_bot, get_bot, list_my_bots, resume_bot, suggest_bot_handle, suspend_bot,
    update_bot, BotError, BotProfileUpdate, NewBot,
};
use lepton_host_adapter::generated::{BotOwnerKind, BotStatus};
use support::{system_valence, user_valence};

fn setup() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
}

const fn new_bot(handle: &str) -> NewBot<'_> {
    NewBot {
        handle,
        display_name: "Spectra agent",
        description: Some("Reads metrics"),
    }
}

#[tokio::test]
async fn create_bot_creator_happy() {
    setup();
    let sys = system_valence("bots_create").await;
    seed_user(&sys, "maker-alice").await;
    let alice = user_valence(&sys, "maker-alice");

    let bot = create_bot(&alice, new_bot("Spectra-Bot"))
        .await
        .expect("create");

    assert_eq!(bot.handle(), "spectra-bot");
    assert_eq!(bot.handle_key(), "spectrabot");
    assert_eq!(bot.display_name(), "Spectra agent");
    assert_eq!(bot.description().map(String::as_str), Some("Reads metrics"));
    assert_eq!(bot.status(), &BotStatus::Active);
    assert_eq!(bot.owner_kind(), &BotOwnerKind::User);
    assert!(bot.suspended_at().is_none());
    assert_eq!(bot.created_at(), bot.updated_at());
    let owner = bot.user().expect("owner").id().to_string();
    assert!(owner.ends_with("maker-alice"), "{owner}");
    let creator = bot.created_by().expect("creator").id().to_string();
    assert!(creator.ends_with("maker-alice"), "{creator}");
    assert_eq!(stored_bot_count(&sys, "maker-alice").await, 1);
}

#[tokio::test]
async fn bot_schema_round_trip_happy() {
    setup();
    let sys = system_valence("bots_round_trip").await;
    let (alice, id, created) = seed_bot(&sys, "maker-alice", "round-trip-bot").await;

    let loaded = get_bot(&alice, &id).await.expect("owner reads");
    assert_eq!(loaded.handle(), created.handle());
    assert_eq!(loaded.display_name(), created.display_name());
    assert_eq!(loaded.status(), &BotStatus::Active);
    assert_eq!(
        loaded.created_at().timestamp(),
        created.created_at().timestamp()
    );
    let raw = stored_bot(&sys, &id).await.expect("stored");
    assert_eq!(raw["status"], "active");
    assert_eq!(raw["owner_kind"], "user");
}

#[tokio::test]
async fn create_bot_handle_clash_returns_suggestion_sad() {
    setup();
    let sys = system_valence("bots_clash").await;
    let (alice, _, _) = seed_bot(&sys, "maker-alice", "spectra-bot").await;

    let err = create_bot(&alice, new_bot("SpectraBot"))
        .await
        .expect_err("clash");
    let BotError::HandleTaken { suggestion } = err else {
        panic!("expected HandleTaken, got {err:?}");
    };
    assert_eq!(suggestion.expect("suggestion").as_str(), "spectra-2-bot");
    assert_eq!(
        stored_bot_count(&sys, "maker-alice").await,
        1,
        "no second row"
    );

    create_bot(&alice, new_bot("spectra-2-bot"))
        .await
        .expect("suggestion is free");
}

#[tokio::test]
async fn create_bot_handle_clash_across_owners_sad() {
    setup();
    let sys = system_valence("bots_clash_owners").await;
    seed_bot(&sys, "maker-alice", "shared-bot").await;
    seed_user(&sys, "maker-bob").await;
    let bob = user_valence(&sys, "maker-bob");

    let err = create_bot(&bob, new_bot("shared-bot"))
        .await
        .expect_err("clash");
    assert!(
        matches!(
            err,
            BotError::HandleTaken {
                suggestion: Some(_)
            }
        ),
        "{err:?}"
    );
    assert_eq!(stored_bot_count(&sys, "maker-bob").await, 0);
}

#[tokio::test]
async fn suggest_bot_handle_happy() {
    setup();
    let sys = system_valence("bots_suggest").await;
    let (alice, _, _) = seed_bot(&sys, "maker-alice", "spectra-bot").await;

    let taken = suggest_bot_handle(&alice, "Spectra Bot")
        .await
        .expect("suggest");
    assert_eq!(taken.as_str(), "spectra-2-bot");
    let free = suggest_bot_handle(&alice, "Magnon reader")
        .await
        .expect("suggest");
    assert_eq!(free.as_str(), "magnon-reader-bot");
}

#[tokio::test]
async fn create_bot_invalid_input_sad() {
    setup();
    let sys = system_valence("bots_invalid").await;
    seed_user(&sys, "maker-alice").await;
    let alice = user_valence(&sys, "maker-alice");

    let err = create_bot(&alice, new_bot("sean"))
        .await
        .expect_err("no suffix");
    assert_eq!(err.reason_class(), "handle");
    let err = create_bot(&alice, new_bot("support-bot"))
        .await
        .expect_err("reserved");
    assert_eq!(err.reason_class(), "handle");
    let err = create_bot(
        &alice,
        NewBot {
            handle: "ok-bot",
            display_name: "  ",
            description: None,
        },
    )
    .await
    .expect_err("empty name");
    assert!(matches!(
        err,
        BotError::InvalidProfile {
            field: "display_name"
        }
    ));
    assert!(!err.to_string().contains("ok-bot"), "no input echo: {err}");
    assert_eq!(stored_bot_count(&sys, "maker-alice").await, 0);
}

#[tokio::test]
async fn create_bot_not_permitted_sad() {
    setup();
    let sys = system_valence("bots_not_permitted").await;
    seed_user(&sys, "plain-carol").await;
    let carol = user_valence(&sys, "plain-carol");

    let err = create_bot(&carol, new_bot("carol-bot"))
        .await
        .expect_err("gate says no");
    assert!(matches!(err, BotError::CreateNotPermitted), "{err:?}");
    assert_eq!(stored_bot_count(&sys, "plain-carol").await, 0);
}

#[tokio::test]
async fn gate_error_maps_to_gate_sad() {
    setup();
    let sys = system_valence("bots_gate_error").await;
    seed_user(&sys, "gatefail-dan").await;
    let dan = user_valence(&sys, "gatefail-dan");

    let err = create_bot(&dan, new_bot("dan-bot"))
        .await
        .expect_err("gate fails");
    assert!(
        matches!(err, BotError::Gate(e) if e.reason_class == "store"),
        "{err:?}"
    );
    assert_eq!(stored_bot_count(&sys, "gatefail-dan").await, 0);
}

#[tokio::test]
async fn update_bot_owner_happy() {
    setup();
    let sys = system_valence("bots_update").await;
    let (alice, id, created) = seed_bot(&sys, "maker-alice", "edit-me-bot").await;

    let updated = update_bot(
        &alice,
        &id,
        BotProfileUpdate {
            display_name: Some(" Spectra reader "),
            description: Some(None),
        },
    )
    .await
    .expect("owner edits");

    assert_eq!(updated.display_name(), "Spectra reader");
    assert!(updated.description().is_none());
    assert_eq!(updated.handle(), created.handle());
    assert_eq!(updated.status(), &BotStatus::Active);
    assert!(updated.updated_at() >= created.updated_at());
    let raw = stored_bot(&sys, &id).await.expect("stored");
    assert_eq!(raw["display_name"], "Spectra reader");
    assert_eq!(raw["handle"], "edit-me-bot");
}

#[tokio::test]
async fn update_bot_invalid_profile_sad() {
    setup();
    let sys = system_valence("bots_update_invalid").await;
    let (alice, id, _) = seed_bot(&sys, "maker-alice", "edit-bad-bot").await;

    let long = "x".repeat(501);
    let err = update_bot(
        &alice,
        &id,
        BotProfileUpdate {
            display_name: None,
            description: Some(Some(&long)),
        },
    )
    .await
    .expect_err("too long");
    assert!(matches!(
        err,
        BotError::InvalidProfile {
            field: "description"
        }
    ));
    let raw = stored_bot(&sys, &id).await.expect("stored");
    assert_eq!(raw["description"], "Fixture", "unchanged");
}

#[tokio::test]
async fn suspend_resume_owner_happy() {
    setup();
    let sys = system_valence("bots_suspend").await;
    let (alice, id, _) = seed_bot(&sys, "maker-alice", "pause-bot").await;

    let suspended = suspend_bot(&alice, &id).await.expect("suspend");
    assert_eq!(suspended.status(), &BotStatus::Suspended);
    assert!(suspended.suspended_at().is_some());
    assert_eq!(
        stored_bot(&sys, &id).await.expect("row")["status"],
        "suspended"
    );

    let resumed = resume_bot(&alice, &id).await.expect("resume");
    assert_eq!(resumed.status(), &BotStatus::Active);
    assert!(resumed.suspended_at().is_none());
    assert_eq!(
        stored_bot(&sys, &id).await.expect("row")["status"],
        "active"
    );
}

#[tokio::test]
async fn suspend_twice_sad() {
    setup();
    let sys = system_valence("bots_suspend_twice").await;
    let (alice, id, _) = seed_bot(&sys, "maker-alice", "twice-bot").await;
    suspend_bot(&alice, &id).await.expect("first suspend");
    let before = stored_bot(&sys, &id).await.expect("row");

    let err = suspend_bot(&alice, &id)
        .await
        .expect_err("already suspended");
    assert!(matches!(
        err,
        BotError::InvalidTransition {
            from: BotStatus::Suspended
        }
    ));
    assert_eq!(
        stored_bot(&sys, &id).await.expect("row")["updated_at"],
        before["updated_at"]
    );

    let err = resume_bot(&alice, &id).await;
    assert!(err.is_ok());
    let err = resume_bot(&alice, &id).await.expect_err("already active");
    assert!(matches!(
        err,
        BotError::InvalidTransition {
            from: BotStatus::Active
        }
    ));
}

#[tokio::test]
async fn delete_bot_owner_happy() {
    setup();
    let sys = system_valence("bots_delete").await;
    let (alice, id, _) = seed_bot(&sys, "maker-alice", "gone-bot").await;
    let (_, keep, _) = seed_bot(&sys, "maker-alice", "kept-bot").await;

    delete_bot(&alice, &id).await.expect("owner deletes");

    assert!(matches!(
        get_bot(&alice, &id).await,
        Err(BotError::NotFound)
    ));
    let listed = list_my_bots(&alice).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].handle(), "kept-bot");
    get_bot(&alice, &keep).await.expect("other bot untouched");
}

#[tokio::test]
async fn super_user_manage_any_happy() {
    setup();
    let sys = system_valence("bots_super").await;
    let (_, id, _) = seed_bot(&sys, "maker-alice", "managed-bot").await;
    seed_user(&sys, "super-sam").await;
    let sam = user_valence(&sys, "super-sam");

    get_bot(&sam, &id).await.expect("super user reads");
    let suspended = suspend_bot(&sam, &id).await.expect("super user suspends");
    assert_eq!(suspended.status(), &BotStatus::Suspended);
    assert!(
        suspended
            .user()
            .expect("owner")
            .id()
            .ends_with("maker-alice"),
        "owner unchanged"
    );
    delete_bot(&sam, &id).await.expect("super user deletes");
    let alice = user_valence(&sys, "maker-alice");
    assert!(matches!(
        get_bot(&alice, &id).await,
        Err(BotError::NotFound)
    ));
}

#[tokio::test]
async fn list_my_bots_happy() {
    setup();
    let sys = system_valence("bots_list").await;
    let (alice, _, _) = seed_bot(&sys, "maker-alice", "first-bot").await;
    create_bot(&alice, new_bot("second-bot"))
        .await
        .expect("second");

    let handles: Vec<String> = list_my_bots(&alice)
        .await
        .expect("list")
        .iter()
        .map(|b| b.handle().clone())
        .collect();
    assert_eq!(handles, ["first-bot", "second-bot"]);
}
