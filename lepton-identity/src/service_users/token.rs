//! Privacy rules for the `service_user_token` table.
//!
//! The token string, its check, and the personal token kind live in [`crate::tokens`]. These
//! rules decide who may create and change a service user's token rows.

use std::any::Any;

use async_trait::async_trait;
use serde_json::Value;
use valence::{Actor, ActorContext, PolicyEvaluator, PrivacyOperation, Result, Valence};

use super::id::ServiceUserId;
use super::resolve::active_service_user_owner;
use super::rules::{ref_id, user_actor, SERVICE_USER_TABLE};
use crate::device_signin::SIGNED_IN_DEVICE_TABLE;
use crate::tokens::{
    changed_other_than, fields_changed, parse_time, revoke_undone, scopes_from_json,
};
use valence::privacy_policies::owner::check_owner_by_field;

const TOKEN_TABLE: &str = "service_user_token";

/// Fields that never change after a token is created.
const TOKEN_IMMUTABLE_FIELDS: &[&str] = &[
    "user",
    "service_user",
    "token_hash",
    "scopes",
    "kind",
    "device_id",
    "expires_at",
    "created_at",
];

/// `create` rule: the caller owns both the token row and the service user it acts as.
///
/// The service user's owner is read from its stored row, so nobody mints a token for a service
/// user they do not own.
pub const SERVICE_USER_TOKEN_CREATE: ServiceUserTokenCreateRule = ServiceUserTokenCreateRule;

/// `update` `always_block` rule: a token's owner, service user, hash, scopes, kind, device and
/// expiry never change.
///
/// Nor does `revoked_at` once it is set, so nobody (the owner included) can undo a manage-any
/// user's revoke. Revoking sets `revoked_at`; each use sets `last_used_at`.
pub const SERVICE_USER_TOKEN_IMMUTABLE: ServiceUserTokenImmutableRule =
    ServiceUserTokenImmutableRule;

/// `update` `allow` rule: a service user records its own token's last use, nothing else.
///
/// The bearer layer writes `last_used_at` as the token's own
/// actor, so recording a use needs no System handle.
pub const SERVICE_USER_TOKEN_TOUCH: ServiceUserTokenTouchRule = ServiceUserTokenTouchRule;

/// `create` rule: a service user creates the device token its owner approved for one of its
/// devices, and nothing else.
///
/// The token must be `kind = device`, act as the caller, and name a `signed_in_device` whose
/// stored row acts as the caller, has the same owner, is waiting for a token
/// (`status = issue_pending`), and carries the same scopes. Its expiry is no later than the
/// device's lifetime from now, and the service user must be active. This is how a device
/// collects its token without Lepton ever storing the plaintext, and without a System handle.
pub const SERVICE_USER_DEVICE_TOKEN_CREATE: ServiceUserDeviceTokenCreateRule =
    ServiceUserDeviceTokenCreateRule;

/// See [`SERVICE_USER_TOKEN_CREATE`].
#[derive(Debug, Clone, Copy)]
pub struct ServiceUserTokenCreateRule;

/// See [`SERVICE_USER_DEVICE_TOKEN_CREATE`].
#[derive(Debug, Clone, Copy)]
pub struct ServiceUserDeviceTokenCreateRule;

/// See [`SERVICE_USER_TOKEN_IMMUTABLE`].
#[derive(Debug, Clone, Copy)]
pub struct ServiceUserTokenImmutableRule;

/// See [`SERVICE_USER_TOKEN_TOUCH`].
#[derive(Debug, Clone, Copy)]
pub struct ServiceUserTokenTouchRule;

#[async_trait]
impl PolicyEvaluator for ServiceUserTokenCreateRule {
    fn name(&self) -> &'static str {
        "lepton::SERVICE_USER_TOKEN_CREATE"
    }

    fn description(&self) -> Option<&'static str> {
        Some("Caller creates an access token for a service user it owns")
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
        if !check_owner_by_field(record, &user, "user") {
            return Ok(false);
        }
        let Some(service_user) = record.get("service_user").and_then(ref_id) else {
            return Ok(false);
        };
        let backend = v.backend_for_table(SERVICE_USER_TABLE)?;
        let stored = valence::get_record(
            backend.as_ref(),
            SERVICE_USER_TABLE,
            &service_user,
            valence::use_!(r"Before a **service user access token** is saved, we **read the service user's stored owner** to make sure the person creating the token owns that service user. Nothing is shown to anyone; the check blocks the save when the owner differs."),
        )
        .await?;
        Ok(stored.is_some_and(|row| check_owner_by_field(&row, &user, "user")))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Both rows carry the same non-empty scopes, compared as scope lists rather than raw JSON.
fn same_scopes(device: Option<&Value>, token: Option<&Value>) -> bool {
    let device = scopes_from_json(device);
    !device.is_empty() && device == scopes_from_json(token)
}

/// Slack on the device token's expiry check, for the time between minting and the check.
const EXPIRY_SLACK_SECS: i64 = 300;

#[async_trait]
impl PolicyEvaluator for ServiceUserDeviceTokenCreateRule {
    fn name(&self) -> &'static str {
        "lepton::SERVICE_USER_DEVICE_TOKEN_CREATE"
    }

    fn description(&self) -> Option<&'static str> {
        Some("A service user creates the device token its owner approved for one of its devices")
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
        let Ok(actor) = serde_json::from_value(actor.actor_json().clone()) else {
            return Ok(false);
        };
        let Some(caller) = ServiceUserId::from_actor(&actor) else {
            return Ok(false);
        };
        let acts_as_caller =
            record.get("service_user").and_then(ref_id).as_deref() == Some(caller.as_str());
        if !acts_as_caller || record.get("kind").and_then(Value::as_str) != Some("device") {
            return Ok(false);
        }
        let Some(device_id) = record.get("device_id").and_then(Value::as_str) else {
            return Ok(false);
        };
        let backend = v.backend_for_table(SIGNED_IN_DEVICE_TABLE)?;
        let device = valence::get_record(
            backend.as_ref(),
            SIGNED_IN_DEVICE_TABLE,
            device_id,
            valence::use_!(r"When a **device collects the token** its owner approved, we **read the stored device record** to check that it acts as this service user, belongs to the same owner, is waiting for a token, and has the same API scopes and lifetime. Nothing is shown to anyone; the check only allows or blocks the new token."),
        )
        .await?;
        let Some(device) = device else {
            return Ok(false);
        };
        let matches_device = device.get("service_user").and_then(ref_id).as_deref()
            == Some(caller.as_str())
            && device.get("user").and_then(ref_id).is_some()
            && device.get("user").and_then(ref_id) == record.get("user").and_then(ref_id)
            && device.get("status").and_then(Value::as_str) == Some("issue_pending")
            && same_scopes(device.get("scopes"), record.get("scopes"));
        if !matches_device {
            return Ok(false);
        }
        let Some(days) = device.get("lifetime_days").and_then(Value::as_i64) else {
            return Ok(false);
        };
        let latest = chrono::Utc::now()
            + chrono::Duration::days(days)
            + chrono::Duration::seconds(EXPIRY_SLACK_SECS);
        if record
            .get("expires_at")
            .and_then(parse_time)
            .is_none_or(|at| at > latest)
        {
            return Ok(false);
        }
        let Some(Actor::User { user_id }) = active_service_user_owner(caller.as_str(), v).await
        else {
            return Ok(false);
        };
        Ok(record.get("user").and_then(ref_id).as_deref() == Some(user_id.as_str()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[async_trait]
impl PolicyEvaluator for ServiceUserTokenImmutableRule {
    fn name(&self) -> &'static str {
        "lepton::SERVICE_USER_TOKEN_IMMUTABLE"
    }

    fn description(&self) -> Option<&'static str> {
        Some("Blocks any update that changes a token's owner, service user, secret hash, scopes, kind, device, or expiry, or undoes its revoke")
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
        let backend = v.backend_for_table(TOKEN_TABLE)?;
        let stored = valence::get_record(
            backend.as_ref(),
            TOKEN_TABLE,
            &id,
            valence::use_!(r"Before anyone saves a change to a **service user access token**, we **read the stored owner, service user, and secret hash** to make sure the change does not **repoint the token** or **swap its secret**. Nothing is shown to anyone; the check blocks the save when they differ."),
        )
        .await?;
        let Some(stored) = stored else {
            return Ok(true);
        };
        Ok(fields_changed(TOKEN_IMMUTABLE_FIELDS, record, &stored)
            || revoke_undone(record, &stored))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[async_trait]
impl PolicyEvaluator for ServiceUserTokenTouchRule {
    fn name(&self) -> &'static str {
        "lepton::SERVICE_USER_TOKEN_TOUCH"
    }

    fn description(&self) -> Option<&'static str> {
        Some("A service user records when its own token was last used, and changes nothing else")
    }

    async fn evaluate(
        &self,
        op: PrivacyOperation,
        record: &Value,
        actor: &dyn ActorContext,
        v: &Valence,
    ) -> Result<bool> {
        if !matches!(op, PrivacyOperation::Update) {
            return Ok(false);
        }
        let Ok(actor) = serde_json::from_value(actor.actor_json().clone()) else {
            return Ok(false);
        };
        let Some(caller) = ServiceUserId::from_actor(&actor) else {
            return Ok(false);
        };
        let Some(id) = record.get("id").and_then(ref_id) else {
            return Ok(false);
        };
        let backend = v.backend_for_table(TOKEN_TABLE)?;
        let stored = valence::get_record(
            backend.as_ref(),
            TOKEN_TABLE,
            &id,
            valence::use_!(r"When a **service user** calls in with its access token, we **read the token's stored service user** so it can record **when the token was last used**. The owner sees that time on the service user's page; nothing else about the token can change this way."),
        )
        .await?;
        let Some(stored) = stored else {
            return Ok(false);
        };
        let own = stored.get("service_user").and_then(ref_id).as_deref() == Some(caller.as_str());
        Ok(own && !changed_other_than("last_used_at", record, &stored))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn same_scopes_happy() {
        let stored = json!(["magnon:read", "spectra:read"]);
        assert!(same_scopes(Some(&stored), Some(&stored.clone())));
    }

    #[test]
    fn different_or_missing_scopes_sad() {
        let stored = json!(["magnon:read"]);
        assert!(!same_scopes(
            Some(&stored),
            Some(&json!(["magnon:read", "magnon:write"]))
        ));
        assert!(!same_scopes(Some(&stored), None));
        assert!(!same_scopes(Some(&json!([])), Some(&json!([]))));
    }
}
