//! Bot test fixtures: a prefix-based `BotGate` and seeded users and bots.

#![allow(dead_code, clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Once};

use async_trait::async_trait;
use chrono::Utc;
use lepton_auth::bots::{create_bot, NewBot};
use lepton_host_adapter::generated::{Bot, User, UserStatus, UserUserType};
use lepton_identity::bots::{install_bot_gate, BotGate, BotGateError, BotId};
use valence::{Model, Valence};

use crate::support::user_valence;

/// Users whose id starts with this may create bots.
pub const MAKER: &str = "maker";
/// Users whose id starts with this may create bots and manage every bot.
pub const SUPER: &str = "super";
/// The gate errors for users whose id starts with this.
pub const GATE_FAILS: &str = "gatefail";

/// Decides from the user id prefix, so parallel tests share one installed gate.
struct PrefixGate;

fn user_id(v: &Valence) -> String {
    let id = v.actor().user_id().unwrap_or_default();
    id.split_once(':').map_or(id, |(_, bare)| bare).to_string()
}

#[async_trait]
impl BotGate for PrefixGate {
    async fn may_create_bot(&self, v: &Valence) -> Result<bool, BotGateError> {
        let id = user_id(v);
        if id.starts_with(GATE_FAILS) {
            return Err(BotGateError {
                reason_class: "store",
            });
        }
        Ok(id.starts_with(MAKER) || id.starts_with(SUPER))
    }

    async fn may_manage_any_bot(&self, v: &Valence) -> Result<bool, BotGateError> {
        let id = user_id(v);
        if id.starts_with(GATE_FAILS) {
            return Err(BotGateError {
                reason_class: "store",
            });
        }
        Ok(id.starts_with(SUPER))
    }
}

/// Install [`PrefixGate`] once per test binary.
pub fn install_test_gate() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        install_bot_gate(Arc::new(PrefixGate)).expect("first gate install in this binary");
    });
}

/// **Test:** seed an active person user with a chosen id (System fixture only).
pub async fn seed_user(system: &Valence, id: &str) {
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
    User::upsert(id, user, system, valence::use_!(r"**Test:** Fixture **User** save for `bots` tests so the suite can create bots owned by a known user id. CI and developers running the suite only."))
        .await
        .expect("seed user");
}

/// Seed `owner` and create one bot through the service as that owner.
pub async fn seed_bot(system: &Valence, owner: &str, handle: &str) -> (Valence, BotId, Bot) {
    seed_user(system, owner).await;
    let owner_v = user_valence(system, owner);
    let bot = create_bot(
        &owner_v,
        NewBot {
            handle,
            display_name: "Test bot",
            description: Some("Fixture"),
        },
    )
    .await
    .expect("owner creates bot");
    let id = BotId::parse(bot.id().expect("id").id()).expect("bot id");
    (owner_v, id, bot)
}

/// **Test:** raw stored row, bypassing privacy, to assert what actually persisted.
pub async fn stored_bot(system: &Valence, id: &BotId) -> Option<serde_json::Value> {
    let backend = system.backend_for_table("bot").expect("backend");
    valence::get_record(backend.as_ref(), "bot", id.as_str(), valence::use_!(r"**Test:** Fixture read of a **bot** row for `bots` tests so the suite can assert what was stored, independent of privacy. CI and developers running the suite only."))
        .await
        .expect("raw read")
}

/// **Test:** number of stored `bot` rows owned by `owner`.
pub async fn stored_bot_count(system: &Valence, owner: &str) -> usize {
    Bot::get_from_user_id(owner, system, valence::use_!(r"**Test:** Fixture count of **bots** per owner for `bots` tests so the suite can assert creates and deletes. CI and developers running the suite only."))
        .await
        .expect("count")
        .len()
}
