//! Valence privacy rules for the `bot` table.
//!
//! Every rule refuses any actor that is not `Actor::User`, so a bot (an
//! `Actor::ServiceUser`) can never create or manage bots, including itself, and
//! infrastructure service users gain nothing. System keeps its usual access
//! through `OWNER_BY_USER_FIELD`.

use std::any::Any;
use std::sync::Once;

use async_trait::async_trait;
use serde_json::Value;
use valence::privacy_policies::owner::check_owner_by_field;
use valence::{Actor, ActorContext, PolicyEvaluator, PrivacyOperation, Result, Valence};

use super::gate::installed_bot_gate;

const BOT_TABLE: &str = "bot";

/// Fields that never change after a bot is created.
const IMMUTABLE_FIELDS: &[&str] = &["user", "owner_kind", "created_by", "handle", "handle_key"];

/// `create` rule: the caller owns the new bot and the host's
/// [`BotGate`](super::BotGate) allows it to create bots.
///
/// The new row must name the caller in both `user` and `created_by` and carry
/// `owner_kind = "user"`, so nobody creates a bot on someone else's behalf.
pub const BOT_CREATE_GATE: BotCreateGateRule = BotCreateGateRule;

/// `read` / `update` / `delete` rule: the host's [`BotGate`](super::BotGate)
/// lets the caller manage any bot (super users).
pub const BOT_MANAGE_ANY: BotManageAnyRule = BotManageAnyRule;

/// `update` `always_block` rule: blocks any change to the owner, creator,
/// owner kind, or handle.
///
/// Valence checks an update against both the stored and the proposed row. This
/// rule re-reads the stored row from the backend rather than trusting the
/// caller's copy, so it also holds for update paths that skip the stored-row
/// check. A row that cannot be read back is blocked.
pub const BOT_IDENTITY_IMMUTABLE: BotIdentityImmutableRule = BotIdentityImmutableRule;

/// See [`BOT_CREATE_GATE`].
#[derive(Debug, Clone, Copy)]
pub struct BotCreateGateRule;

/// See [`BOT_MANAGE_ANY`].
#[derive(Debug, Clone, Copy)]
pub struct BotManageAnyRule;

/// See [`BOT_IDENTITY_IMMUTABLE`].
#[derive(Debug, Clone, Copy)]
pub struct BotIdentityImmutableRule;

/// The calling user, or `None` for every other kind of actor.
fn user_actor(actor: &dyn ActorContext) -> Option<Actor> {
    let parsed: Actor = serde_json::from_value(actor.actor_json().clone()).ok()?;
    parsed.is_user().then_some(parsed)
}

fn warn_gate_missing() {
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            target: "lepton.bot",
            rule = "bot_gate",
            "no BotGate installed; bot creation and manage-any are refused"
        );
    });
}

#[async_trait]
impl PolicyEvaluator for BotCreateGateRule {
    fn name(&self) -> &'static str {
        "lepton::BOT_CREATE_GATE"
    }

    fn description(&self) -> Option<&'static str> {
        Some("Caller creates a bot it owns and the host's BotGate allows bot creation")
    }

    async fn evaluate(
        &self,
        op: PrivacyOperation,
        record: &Value,
        actor: &dyn ActorContext,
        v: &Valence,
    ) -> Result<bool> {
        if !matches!(op, PrivacyOperation::Create) {
            return Ok(false);
        }
        let Some(user) = user_actor(actor) else {
            return Ok(false);
        };
        let owns = check_owner_by_field(record, &user, "user")
            && check_owner_by_field(record, &user, "created_by")
            && record.get("owner_kind").and_then(Value::as_str) == Some("user");
        if !owns {
            return Ok(false);
        }
        let Some(gate) = installed_bot_gate() else {
            warn_gate_missing();
            return Ok(false);
        };
        Ok(gate.may_create_bot(v).await.unwrap_or(false))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[async_trait]
impl PolicyEvaluator for BotManageAnyRule {
    fn name(&self) -> &'static str {
        "lepton::BOT_MANAGE_ANY"
    }

    fn description(&self) -> Option<&'static str> {
        Some("The host's BotGate lets the caller manage every bot (super users)")
    }

    async fn evaluate(
        &self,
        op: PrivacyOperation,
        _record: &Value,
        actor: &dyn ActorContext,
        v: &Valence,
    ) -> Result<bool> {
        if matches!(op, PrivacyOperation::Create) || user_actor(actor).is_none() {
            return Ok(false);
        }
        let Some(gate) = installed_bot_gate() else {
            warn_gate_missing();
            return Ok(false);
        };
        Ok(gate.may_manage_any_bot(v).await.unwrap_or(false))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[async_trait]
impl PolicyEvaluator for BotIdentityImmutableRule {
    fn name(&self) -> &'static str {
        "lepton::BOT_IDENTITY_IMMUTABLE"
    }

    fn description(&self) -> Option<&'static str> {
        Some("Blocks any update that changes a bot's owner, creator, owner kind, or handle")
    }

    async fn evaluate(
        &self,
        op: PrivacyOperation,
        record: &Value,
        _actor: &dyn ActorContext,
        v: &Valence,
    ) -> Result<bool> {
        if !matches!(op, PrivacyOperation::Update) {
            return Ok(false);
        }
        let Some(id) = record.get("id").and_then(ref_id) else {
            return Ok(true);
        };
        let backend = v.backend_for_table(BOT_TABLE)?;
        let stored = valence::get_record(
            backend.as_ref(),
            BOT_TABLE,
            &id,
            valence::use_!(r"Before anyone saves a change to a **bot account**, we **read the bot's stored owner and handle** to make sure the change does not **reassign the bot to someone else** or **rename it**. Only the owner link, owner kind, creator, and handle are compared; nothing is shown to anyone, and the check blocks the save when they differ."),
        )
        .await?;
        let Some(stored) = stored else {
            return Ok(true);
        };
        Ok(identity_changed(record, &stored))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Bare id from a string (`table:id` or `id`), `{ "id": "…" }`, or
/// `{ "id": { "String": "…" } }`; the shapes Valence uses for record links.
fn ref_id(value: &Value) -> Option<String> {
    let text = match value {
        Value::String(s) => s.as_str(),
        Value::Object(obj) => match obj.get("id")? {
            Value::String(s) => s.as_str(),
            Value::Object(inner) => inner.get("String")?.as_str()?,
            _ => return None,
        },
        _ => return None,
    };
    let bare = text.split_once(':').map_or(text, |(_, id)| id).trim();
    (!bare.is_empty()).then(|| bare.to_string())
}

fn identity_changed(proposed: &Value, stored: &Value) -> bool {
    IMMUTABLE_FIELDS.iter().any(|field| {
        let read = |row: &Value| row.get(*field).and_then(ref_id);
        read(proposed) != read(stored)
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn ref_id_shapes_happy() {
        assert_eq!(ref_id(&json!("user:alice")), Some("alice".into()));
        assert_eq!(ref_id(&json!("alice")), Some("alice".into()));
        assert_eq!(
            ref_id(&json!({"tb": "user", "id": "alice"})),
            Some("alice".into())
        );
        assert_eq!(
            ref_id(&json!({"id": {"String": "user:alice"}})),
            Some("alice".into())
        );
        assert_eq!(ref_id(&json!(null)), None);
        assert_eq!(ref_id(&json!("")), None);
    }

    #[test]
    fn identity_unchanged_happy() {
        let stored = json!({"user": "user:a", "owner_kind": "user", "created_by": {"id": "a"}, "handle": "x-bot", "handle_key": "xbot", "display_name": "Old"});
        let proposed = json!({"user": {"tb": "user", "id": "a"}, "owner_kind": "user", "created_by": "user:a", "handle": "x-bot", "handle_key": "xbot", "display_name": "New"});
        assert!(!identity_changed(&proposed, &stored));
    }

    #[test]
    fn identity_changed_sad() {
        let stored = json!({"user": "user:a", "owner_kind": "user", "created_by": "user:a", "handle": "x-bot", "handle_key": "xbot"});
        for (field, value) in [
            ("user", json!("user:b")),
            ("user", json!(null)),
            ("created_by", json!("user:b")),
            ("handle", json!("y-bot")),
            ("handle_key", json!("ybot")),
            ("owner_kind", json!("team")),
        ] {
            let mut proposed = stored.clone();
            proposed[field] = value;
            assert!(identity_changed(&proposed, &stored), "{field}");
        }
    }
}
