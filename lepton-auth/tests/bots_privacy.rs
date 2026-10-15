//! Bot privacy: the create gate holds at the Valence layer, owners cannot be
//! changed, peers see nothing, and bots never manage themselves
//! (TM-B5, TM-B6, TM-B8).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/bots.rs"]
mod bots_support;

use bots_support::{install_test_gate, seed_bot, seed_user, stored_bot, stored_bot_count};
use chrono::Utc;
use lepton_auth::bots::{
    create_bot, delete_bot, get_bot, list_my_bots, suspend_bot, update_bot, BotError,
    BotProfileUpdate, NewBot,
};
use lepton_host_adapter::generated::{Bot, BotOwnerKind, BotStatus};
use lepton_identity::bots::BotId;
use valence::{Actor, Model, RecordId, Valence};

use support::{system_valence, user_valence};

fn setup() {
    install_test_gate();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
}

fn row(owner: &str, creator: &str, handle: &str) -> Bot {
    let now = Utc::now();
    Bot::new(
        Some(RecordId::new("user", owner)),
        BotOwnerKind::User,
        Some(RecordId::new("user", creator)),
        handle.to_string(),
        handle.replace('-', ""),
        "Direct".to_string(),
        None,
        BotStatus::Active,
        None,
        now,
        now,
    )
    .expect("row")
}

async fn direct_upsert(v: &Valence, id: &BotId, data: Bot) -> valence::Result<Bot> {
    Bot::upsert(id.as_str(), data, v, valence::use_!(r"**Test:** Direct **Bot** save for `bots_privacy` so the suite can prove privacy rules hold without the service layer. CI and developers running the suite only.")).await
}

// --- TM-B5: create gate enforced in Valence --------------------------------

#[tokio::test]
async fn bot_create_direct_model_non_creator_sad() {
    setup();
    let sys = system_valence("bots_direct_create").await;
    seed_user(&sys, "plain-carol").await;
    let carol = user_valence(&sys, "plain-carol");
    let id = BotId::new_v4();

    let err = direct_upsert(&carol, &id, row("plain-carol", "plain-carol", "carol-bot"))
        .await
        .expect_err("gate refuses at the model layer");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert!(stored_bot(&sys, &id).await.is_none());
}

#[tokio::test]
async fn bot_create_direct_model_creator_happy() {
    setup();
    let sys = system_valence("bots_direct_create_ok").await;
    seed_user(&sys, "maker-alice").await;
    let alice = user_valence(&sys, "maker-alice");
    let id = BotId::new_v4();

    direct_upsert(&alice, &id, row("maker-alice", "maker-alice", "direct-bot"))
        .await
        .expect("creator passes the rule");
    assert!(stored_bot(&sys, &id).await.is_some());
}

#[tokio::test]
async fn bot_create_for_other_owner_sad() {
    setup();
    let sys = system_valence("bots_other_owner").await;
    seed_user(&sys, "maker-alice").await;
    seed_user(&sys, "maker-bob").await;
    let alice = user_valence(&sys, "maker-alice");

    for data in [
        row("maker-bob", "maker-alice", "for-bob-bot"),
        row("maker-alice", "maker-bob", "framed-bot"),
    ] {
        let id = BotId::new_v4();
        let err = direct_upsert(&alice, &id, data)
            .await
            .expect_err("not own bot");
        assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
        assert!(stored_bot(&sys, &id).await.is_none());
    }
}

#[tokio::test]
async fn bot_create_missing_owner_sad() {
    setup();
    let sys = system_valence("bots_no_owner").await;
    seed_user(&sys, "maker-alice").await;
    let alice = user_valence(&sys, "maker-alice");
    let now = Utc::now();
    let ownerless = Bot::new(
        None,
        BotOwnerKind::User,
        Some(RecordId::new("user", "maker-alice")),
        "orphan-bot".into(),
        "orphanbot".into(),
        "Orphan".into(),
        None,
        BotStatus::Active,
        None,
        now,
        now,
    )
    .expect("row");
    let id = BotId::new_v4();

    let err = direct_upsert(&alice, &id, ownerless)
        .await
        .expect_err("owner required");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert!(stored_bot(&sys, &id).await.is_none());
}

// --- TM-B6: identity is immutable -------------------------------------------

async fn reassign(v: &Valence, id: &BotId, to: &str) -> valence::Result<Bot> {
    let bot = Bot::get(id.as_str(), v, valence::use_!(r"**Test:** Load a **Bot** for `bots_privacy` owner-change attempts. CI and developers running the suite only."))
        .await?
        .ok_or_else(|| valence::Error::NotFound("bot".into()))?;
    bot.get_mutable(v, valence::use_!(r"**Test:** Attempt to change a **Bot** owner for `bots_privacy` so the suite can prove it is refused. CI and developers running the suite only."))
        .set_user(RecordId::new("user", to))?
        .commit()
        .await
}

#[tokio::test]
async fn bot_owner_takeover_via_commit_sad() {
    setup();
    let sys = system_valence("bots_takeover_commit").await;
    let (_, id, _) = seed_bot(&sys, "maker-alice", "victim-bot").await;
    seed_user(&sys, "maker-mallory").await;
    let mallory = user_valence(&sys, "maker-mallory");

    // Mallory loads the row through System's eyes (a forged in-memory copy) and
    // tries to commit herself as owner.
    let copy = Bot::get(id.as_str(), &sys, valence::use_!(r"**Test:** Fixture load of a **Bot** to forge an attacker's in-memory copy for `bots_privacy`. CI and developers running the suite only."))
        .await
        .expect("get")
        .expect("row");
    let err = copy
        .get_mutable(&mallory, valence::use_!(r"**Test:** Attacker owner change on a **Bot** for `bots_privacy`. CI and developers running the suite only."))
        .set_user(RecordId::new("user", "maker-mallory"))
        .expect("set")
        .commit()
        .await
        .expect_err("takeover refused");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    let raw = stored_bot(&sys, &id).await.expect("row");
    assert!(raw["user"].to_string().contains("maker-alice"), "{raw}");
}

#[tokio::test]
async fn bot_owner_takeover_via_model_update_sad() {
    setup();
    let sys = system_valence("bots_takeover_update").await;
    let (_, id, _) = seed_bot(&sys, "maker-alice", "victim2-bot").await;
    seed_user(&sys, "maker-mallory").await;
    let mallory = user_valence(&sys, "maker-mallory");

    // Plain `Model::update` skips the stored-row check when the caller cannot
    // read the row; BOT_IDENTITY_IMMUTABLE re-reads it and blocks.
    let forged = row("maker-mallory", "maker-mallory", "victim2-bot");
    let err = Bot::update(id.as_str(), forged, &mallory, valence::use_!(r"**Test:** Attacker replace of a **Bot** via plain update for `bots_privacy`. CI and developers running the suite only."))
        .await
        .expect_err("takeover refused");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    let raw = stored_bot(&sys, &id).await.expect("row");
    assert!(raw["user"].to_string().contains("maker-alice"), "{raw}");
    assert_eq!(raw["display_name"], "Test bot");
}

#[tokio::test]
async fn bot_give_away_sad() {
    setup();
    let sys = system_valence("bots_give_away").await;
    let (alice, id, _) = seed_bot(&sys, "maker-alice", "gift-bot").await;
    seed_user(&sys, "maker-bob").await;

    let err = reassign(&alice, &id, "maker-bob")
        .await
        .expect_err("give away refused");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert!(stored_bot(&sys, &id).await.expect("row")["user"]
        .to_string()
        .contains("maker-alice"));
}

#[tokio::test]
async fn super_user_cannot_reassign_owner_sad() {
    setup();
    let sys = system_valence("bots_super_reassign").await;
    let (_, id, _) = seed_bot(&sys, "maker-alice", "keep-owner-bot").await;
    seed_user(&sys, "super-sam").await;
    let sam = user_valence(&sys, "super-sam");

    let err = reassign(&sam, &id, "super-sam")
        .await
        .expect_err("reassign refused");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    // Even System cannot rename or reassign: the rule is always_block.
    let err = reassign(&sys, &id, "super-sam")
        .await
        .expect_err("System refused too");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert!(stored_bot(&sys, &id).await.expect("row")["user"]
        .to_string()
        .contains("maker-alice"));
}

#[tokio::test]
async fn bot_handle_change_sad() {
    setup();
    let sys = system_valence("bots_handle_change").await;
    let (alice, id, _) = seed_bot(&sys, "maker-alice", "stable-bot").await;

    let bot = get_bot(&alice, &id).await.expect("get");
    let err = bot
        .get_mutable(&alice, valence::use_!(r"**Test:** Attempt to rename a **Bot** for `bots_privacy`. CI and developers running the suite only."))
        .set_handle("renamed-bot".into())
        .expect("set")
        .commit()
        .await
        .expect_err("rename refused");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert_eq!(
        stored_bot(&sys, &id).await.expect("row")["handle"],
        "stable-bot"
    );
}

// --- TM-B8: isolation -------------------------------------------------------

#[tokio::test]
async fn peer_read_bot_not_found_sad() {
    setup();
    let sys = system_valence("bots_peer_read").await;
    let (_, id, _) = seed_bot(&sys, "maker-alice", "private-bot").await;
    seed_user(&sys, "maker-bob").await;
    let bob = user_valence(&sys, "maker-bob");

    assert!(matches!(get_bot(&bob, &id).await, Err(BotError::NotFound)));
    let direct = Bot::get(id.as_str(), &bob, valence::use_!(r"**Test:** Peer read of a **Bot** for `bots_privacy`. CI and developers running the suite only."))
        .await
        .expect("get");
    assert!(direct.is_none());
}

#[tokio::test]
async fn peer_list_excludes_others_sad() {
    setup();
    let sys = system_valence("bots_peer_list").await;
    seed_bot(&sys, "maker-alice", "alices-bot").await;
    let (bob, _, _) = seed_bot(&sys, "maker-bob", "bobs-bot").await;

    let listed = list_my_bots(&bob).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].handle(), "bobs-bot");
    let all = Bot::query(&bob, valence::use_!(r"**Test:** Peer query over every **Bot** for `bots_privacy`. CI and developers running the suite only."))
        .await
        .expect("query");
    assert!(all.iter().all(|b| b.handle() != "alices-bot"));
}

#[tokio::test]
async fn peer_suspend_delete_not_found_sad() {
    setup();
    let sys = system_valence("bots_peer_write").await;
    let (_, id, _) = seed_bot(&sys, "maker-alice", "untouchable-bot").await;
    seed_user(&sys, "maker-bob").await;
    let bob = user_valence(&sys, "maker-bob");

    assert!(matches!(
        suspend_bot(&bob, &id).await,
        Err(BotError::NotFound)
    ));
    assert!(matches!(
        update_bot(
            &bob,
            &id,
            BotProfileUpdate {
                display_name: Some("Mine"),
                description: None
            }
        )
        .await,
        Err(BotError::NotFound)
    ));
    assert!(matches!(
        delete_bot(&bob, &id).await,
        Err(BotError::NotFound)
    ));
    let raw = stored_bot(&sys, &id).await.expect("row");
    assert_eq!(raw["status"], "active");
    assert_eq!(raw["display_name"], "Test bot");
    assert_eq!(stored_bot_count(&sys, "maker-alice").await, 1);
}

#[tokio::test]
async fn bot_actor_cannot_read_or_manage_itself_sad() {
    setup();
    let sys = system_valence("bots_self").await;
    let (_, id, _) = seed_bot(&sys, "maker-alice", "self-bot").await;
    let as_bot = sys.with_actor(id.actor());

    assert!(matches!(
        get_bot(&as_bot, &id).await,
        Err(BotError::NotAUser)
    ));
    assert!(matches!(
        suspend_bot(&as_bot, &id).await,
        Err(BotError::NotAUser)
    ));
    assert!(matches!(
        delete_bot(&as_bot, &id).await,
        Err(BotError::NotAUser)
    ));
    assert!(matches!(
        create_bot(
            &as_bot,
            NewBot {
                handle: "child-bot",
                display_name: "Child",
                description: None
            }
        )
        .await,
        Err(BotError::NotAUser)
    ));

    let direct = Bot::get(id.as_str(), &as_bot, valence::use_!(r"**Test:** A bot reading its own **Bot** row for `bots_privacy`. CI and developers running the suite only."))
        .await
        .expect("get");
    assert!(direct.is_none(), "a bot cannot read itself in B1");
    let err = Bot::delete(id.as_str(), &as_bot, valence::use_!(r"**Test:** A bot deleting its own **Bot** row for `bots_privacy`. CI and developers running the suite only."))
        .await
        .expect_err("bot cannot delete itself");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert_eq!(
        stored_bot(&sys, &id).await.expect("row")["status"],
        "active"
    );
}

#[tokio::test]
async fn infra_service_user_denied_sad() {
    setup();
    let sys = system_valence("bots_infra").await;
    let (_, id, _) = seed_bot(&sys, "maker-alice", "infra-target-bot").await;
    let cron = sys.with_actor(Actor::ServiceUser {
        service_name: "cron".into(),
    });

    assert!(matches!(get_bot(&cron, &id).await, Err(BotError::NotAUser)));
    let direct = Bot::get(id.as_str(), &cron, valence::use_!(r"**Test:** An infrastructure service user reading a **Bot** for `bots_privacy`. CI and developers running the suite only."))
        .await
        .expect("get");
    assert!(direct.is_none());
    let new_id = BotId::new_v4();
    let err = direct_upsert(
        &cron,
        &new_id,
        row("maker-alice", "maker-alice", "cron-bot"),
    )
    .await
    .expect_err("service user cannot create");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
}

#[tokio::test]
async fn anonymous_denied_sad() {
    setup();
    let sys = system_valence("bots_anon").await;
    let (_, id, _) = seed_bot(&sys, "maker-alice", "anon-target-bot").await;
    let anon = sys.with_actor(Actor::Anonymous);

    assert!(matches!(get_bot(&anon, &id).await, Err(BotError::NotAUser)));
    assert!(matches!(list_my_bots(&anon).await, Err(BotError::NotAUser)));
    let direct = Bot::get(id.as_str(), &anon, valence::use_!(r"**Test:** Anonymous read of a **Bot** for `bots_privacy`. CI and developers running the suite only."))
        .await
        .expect("get");
    assert!(direct.is_none());
}
