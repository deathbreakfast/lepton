//! Per-owner bot limit (`lepton_bot_quota_01`).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/bots.rs"]
mod bots_support;

use bots_support::{install_test_gate, seed_user, stored_bot_count};
use lepton_auth::bots::{
    create_bot, delete_bot, suspend_bot, BotError, NewBot, MAX_BOTS_PER_OWNER,
};
use lepton_identity::bots::BotId;
use support::{system_valence, user_valence};
use valence::Valence;

fn setup() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
}

/// Create `count` bots for the caller and return their ids.
async fn fill(v: &Valence, prefix: &str, count: usize) -> Vec<BotId> {
    let mut ids = Vec::with_capacity(count);
    for n in 0..count {
        let handle = format!("{prefix}-{n}-bot");
        let bot = create_bot(
            v,
            NewBot {
                handle: &handle,
                display_name: "Quota bot",
                description: None,
            },
        )
        .await
        .expect("create below the limit");
        ids.push(BotId::parse(bot.id().expect("saved").id()).expect("bot id"));
    }
    ids
}

const fn one_more(handle: &str) -> NewBot<'_> {
    NewBot {
        handle,
        display_name: "One too many",
        description: None,
    }
}

#[tokio::test]
async fn tm_bot_quota_reached_sad() {
    setup();
    let sys = system_valence("bots_quota_reached").await;
    seed_user(&sys, "maker-quota").await;
    let owner = user_valence(&sys, "maker-quota");
    fill(&owner, "full", MAX_BOTS_PER_OWNER).await;

    let err = create_bot(&owner, one_more("extra-bot"))
        .await
        .expect_err("over the limit");

    assert!(
        matches!(err, BotError::QuotaReached { limit } if limit == MAX_BOTS_PER_OWNER),
        "{err:?}"
    );
    assert_eq!(err.reason_class(), "quota");
    assert_eq!(
        stored_bot_count(&sys, "maker-quota").await,
        MAX_BOTS_PER_OWNER
    );
}

#[tokio::test]
async fn tm_bot_quota_counts_suspended_sad() {
    setup();
    let sys = system_valence("bots_quota_suspended").await;
    seed_user(&sys, "maker-paused").await;
    let owner = user_valence(&sys, "maker-paused");
    let ids = fill(&owner, "paused", MAX_BOTS_PER_OWNER).await;
    suspend_bot(&owner, &ids[0]).await.expect("suspend");

    let err = create_bot(&owner, one_more("extra-bot"))
        .await
        .expect_err("suspended bots still count");

    assert!(matches!(err, BotError::QuotaReached { .. }), "{err:?}");
    assert_eq!(
        stored_bot_count(&sys, "maker-paused").await,
        MAX_BOTS_PER_OWNER
    );
}

#[tokio::test]
async fn tm_bot_quota_ignores_deleted_happy() {
    setup();
    let sys = system_valence("bots_quota_deleted").await;
    seed_user(&sys, "maker-freed").await;
    let owner = user_valence(&sys, "maker-freed");
    let ids = fill(&owner, "freed", MAX_BOTS_PER_OWNER).await;
    delete_bot(&owner, &ids[0]).await.expect("delete");

    let bot = create_bot(&owner, one_more("replacement-bot"))
        .await
        .expect("a deleted bot frees its slot");

    assert_eq!(bot.handle(), "replacement-bot");
}

#[tokio::test]
async fn tm_bot_quota_is_per_owner_happy() {
    setup();
    let sys = system_valence("bots_quota_per_owner").await;
    seed_user(&sys, "maker-busy").await;
    seed_user(&sys, "maker-other").await;
    let busy = user_valence(&sys, "maker-busy");
    let other = user_valence(&sys, "maker-other");
    fill(&busy, "busy", MAX_BOTS_PER_OWNER).await;

    create_bot(&other, one_more("other-bot"))
        .await
        .expect("another owner is not affected");

    assert_eq!(stored_bot_count(&sys, "maker-other").await, 1);
}
