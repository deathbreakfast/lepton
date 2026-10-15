//! With no `BotGate` installed, nobody can create bots, at the service or the
//! model layer (TM-B4). Its own binary, because the gate is process-wide.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/bots.rs"]
mod bots_support;

use bots_support::{seed_user, stored_bot, stored_bot_count};
use chrono::Utc;
use lepton_auth::bots::{create_bot, suggest_bot_handle, BotError, NewBot};
use lepton_host_adapter::generated::{Bot, BotOwnerKind, BotStatus};
use lepton_identity::bots::{installed_bot_gate, BotId};
use valence::{Model, RecordId};

use support::{system_valence, user_valence};

#[tokio::test]
async fn create_without_gate_sad() {
    assert!(
        installed_bot_gate().is_none(),
        "this binary never installs a gate"
    );
    let sys = system_valence("bots_unwired").await;
    seed_user(&sys, "maker-alice").await;
    let alice = user_valence(&sys, "maker-alice");

    let err = create_bot(
        &alice,
        NewBot {
            handle: "lonely-bot",
            display_name: "Lonely",
            description: None,
        },
    )
    .await
    .expect_err("no gate");
    assert!(matches!(err, BotError::GateNotInstalled), "{err:?}");
    assert!(matches!(
        suggest_bot_handle(&alice, "lonely").await,
        Err(BotError::GateNotInstalled)
    ));
    assert_eq!(stored_bot_count(&sys, "maker-alice").await, 0);

    // The model layer refuses too: the create rule fails closed.
    let now = Utc::now();
    let owner = RecordId::new("user", "maker-alice");
    let row = Bot::new(
        Some(owner.clone()),
        BotOwnerKind::User,
        Some(owner),
        "lonely-bot".into(),
        "lonelybot".into(),
        "Lonely".into(),
        None,
        BotStatus::Active,
        None,
        now,
        now,
    )
    .expect("row");
    let id = BotId::new_v4();
    let err = Bot::upsert(id.as_str(), row, &alice, valence::use_!(r"**Test:** Direct **Bot** save with no gate installed for `bots_gate_unwired`. CI and developers running the suite only."))
        .await
        .expect_err("rule fails closed");
    assert!(matches!(err, valence::Error::Privacy(_)), "{err:?}");
    assert!(stored_bot(&sys, &id).await.is_none());
}
