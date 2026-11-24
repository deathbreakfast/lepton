//! Privacy rules for the `personal_token` table.

use std::any::Any;

use async_trait::async_trait;
use serde_json::Value;
use valence::{ActorContext, PolicyEvaluator, PrivacyOperation, Result, Valence};

use super::fields_changed;
use crate::service_users::ref_id;

pub(super) const PERSONAL_TOKEN_TABLE: &str = "personal_token";

/// Fields that never change after a personal token is created.
const PERSONAL_TOKEN_IMMUTABLE_FIELDS: &[&str] =
    &["user", "token_hash", "scopes", "expires_at", "created_at"];

/// `update` `always_block` rule: blocks any change to a personal token's owner, secret hash,
/// scopes, or expiry. Revoking sets `revoked_at`; each use sets `last_used_at`.
pub const PERSONAL_TOKEN_IMMUTABLE: PersonalTokenImmutableRule = PersonalTokenImmutableRule;

/// See [`PERSONAL_TOKEN_IMMUTABLE`].
#[derive(Debug, Clone, Copy)]
pub struct PersonalTokenImmutableRule;

#[async_trait]
impl PolicyEvaluator for PersonalTokenImmutableRule {
    fn name(&self) -> &'static str {
        "lepton::PERSONAL_TOKEN_IMMUTABLE"
    }

    fn description(&self) -> Option<&'static str> {
        Some("Blocks any update that changes a personal token's owner, secret hash, scopes, or expiry")
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
        let backend = v.backend_for_table(PERSONAL_TOKEN_TABLE)?;
        let stored = valence::get_record(
            backend.as_ref(),
            PERSONAL_TOKEN_TABLE,
            &id,
            valence::use_!(r"Before anyone saves a change to a **personal access token**, we **read the stored owner, secret hash, scopes, and expiry** to make sure the change does not **hand the token to someone else**, **widen what it can call**, or **swap its secret**. Nothing is shown to anyone; the check blocks the save when they differ."),
        )
        .await?;
        let Some(stored) = stored else {
            return Ok(true);
        };
        Ok(fields_changed(
            PERSONAL_TOKEN_IMMUTABLE_FIELDS,
            record,
            &stored,
        ))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
