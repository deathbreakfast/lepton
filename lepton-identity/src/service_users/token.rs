//! Privacy rules for the `service_user_token` table.
//!
//! The token string, its check, and the personal token kind live in [`crate::tokens`]. These
//! rules decide who may create and change a service user's token rows.

use std::any::Any;

use async_trait::async_trait;
use serde_json::Value;
use valence::{ActorContext, PolicyEvaluator, PrivacyOperation, Result, Valence};

use super::id::ServiceUserId;
use super::rules::{ref_id, user_actor, SERVICE_USER_TABLE};
use crate::tokens::{changed_other_than, fields_changed};
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

/// `update` `always_block` rule: blocks any change to the owner, service user, secret hash,
/// scopes, kind, device, or expiry. Revoking sets `revoked_at`; each use sets `last_used_at`.
pub const SERVICE_USER_TOKEN_IMMUTABLE: ServiceUserTokenImmutableRule =
    ServiceUserTokenImmutableRule;

/// `update` `allow` rule: a service user records its own token's last use, nothing else.
///
/// The bearer layer writes `last_used_at` as the token's own
/// actor, so recording a use needs no System handle.
pub const SERVICE_USER_TOKEN_TOUCH: ServiceUserTokenTouchRule = ServiceUserTokenTouchRule;

/// See [`SERVICE_USER_TOKEN_CREATE`].
#[derive(Debug, Clone, Copy)]
pub struct ServiceUserTokenCreateRule;

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

#[async_trait]
impl PolicyEvaluator for ServiceUserTokenImmutableRule {
    fn name(&self) -> &'static str {
        "lepton::SERVICE_USER_TOKEN_IMMUTABLE"
    }

    fn description(&self) -> Option<&'static str> {
        Some("Blocks any update that changes a token's owner, service user, secret hash, scopes, kind, device, or expiry")
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
        Ok(fields_changed(TOKEN_IMMUTABLE_FIELDS, record, &stored))
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
