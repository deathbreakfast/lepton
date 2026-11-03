//! Update rules that keep protected `User` and `Account` fields system-only to write.
//!
//! The session actor can edit its own profile rows, but status, plan, verification stamps, and
//! the password hash change only under System (signup, verification, billing, password
//! reset). Valence hands an update rule just the row as it will be saved, so a sync rule
//! cannot tell a change from an unchanged value. These rules re-read the stored row with a raw
//! backend read, like [`SERVICE_USER_IDENTITY_IMMUTABLE`](crate::service_users::SERVICE_USER_IDENTITY_IMMUTABLE),
//! and block the save when a protected field differs.
//!
//! Wire them in `update.block`, with `SYSTEM_ONLY` in `update.always_allow` so System writes
//! skip them. A row that cannot be read back is blocked.
//!
//! # `password_hash`
//!
//! `User.password_hash` is also system-only to read, so the session actor's copy of the row
//! holds `None` there. A proposed `None` therefore means "not touched", and a sparse update
//! never includes the field. Any non-null value that differs from the stored hash is blocked.
//! To verify the caller's current password, use [`stored_password_hash`].

use std::any::Any;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use valence::{ActorContext, PolicyEvaluator, PrivacyOperation, Result, Valence};

use crate::service_users::ref_id;

const USER_TABLE: &str = "user";
const ACCOUNT_TABLE: &str = "account";

/// `User` fields only System may change.
const USER_PROTECTED: &[&str] = &[
    "status",
    "user_type",
    "confirmed_at",
    "id_verified_at",
    "password_hash",
];

/// `Account` fields only System may change.
const ACCOUNT_PROTECTED: &[&str] = &["plan", "status"];

/// `User` update `block` rule: refuses a change to `status`, `user_type`, `confirmed_at`,
/// `id_verified_at`, or `password_hash`.
pub const USER_PROTECTED_FIELDS: ProtectedFieldsRule = ProtectedFieldsRule {
    name: "lepton::USER_PROTECTED_FIELDS",
    table: USER_TABLE,
    fields: USER_PROTECTED,
};

/// `Account` update `block` rule: refuses a change to `plan` or `status`.
pub const ACCOUNT_PROTECTED_FIELDS: ProtectedFieldsRule = ProtectedFieldsRule {
    name: "lepton::ACCOUNT_PROTECTED_FIELDS",
    table: ACCOUNT_TABLE,
    fields: ACCOUNT_PROTECTED,
};

/// See [`USER_PROTECTED_FIELDS`] and [`ACCOUNT_PROTECTED_FIELDS`].
#[derive(Debug, Clone, Copy)]
pub struct ProtectedFieldsRule {
    name: &'static str,
    table: &'static str,
    fields: &'static [&'static str],
}

/// A field value with `null` and absent treated alike and timestamps compared as instants.
fn normalized(value: Option<&Value>) -> Value {
    match value {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(s)) => DateTime::parse_from_rfc3339(s).map_or_else(
            |_| Value::String(s.clone()),
            |at| Value::String(at.with_timezone(&Utc).to_rfc3339()),
        ),
        Some(other) => other.clone(),
    }
}

/// True when `proposed` changes one of `fields` relative to `stored`.
///
/// `password_hash` is the exception: a null proposed value means the viewer could not read it.
fn protected_changed(fields: &[&str], proposed: &Value, stored: &Value) -> bool {
    fields.iter().any(|field| {
        let new = normalized(proposed.get(*field));
        if *field == "password_hash" && new.is_null() {
            return false;
        }
        new != normalized(stored.get(*field))
    })
}

#[async_trait]
impl PolicyEvaluator for ProtectedFieldsRule {
    fn name(&self) -> &'static str {
        self.name
    }

    fn description(&self) -> Option<&'static str> {
        Some("Blocks an update that changes a field only System may write")
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
        let backend = v.backend_for_table(self.table)?;
        let stored = valence::get_record(
            backend.as_ref(),
            self.table,
            &id,
            valence::use_!(r"Before anyone saves a change to an **account or user**, we **read the stored status, plan, verification stamps, and password hash** to make sure the change does not **alter a field only the platform may set**. The stored values are only compared with the new ones; nothing is shown to anyone, and the check blocks the save when they differ."),
        )
        .await?;
        let Some(stored) = stored else {
            return Ok(true);
        };
        Ok(protected_changed(self.fields, record, &stored))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// The stored password hash of `user_id`, read from the backend without field privacy.
///
/// This is a documented exception under the no-actor-elevation rule. The operation is
/// "verify the signed-in user's own current password" (change password, email change, TOTP
/// and device enrolment). Field read policies cannot express it: `password_hash` is
/// system-only to read, so the session actor's `User` holds `None`. The caller does not
/// switch actors. It must pass the id of the authenticated session user and never an id taken
/// from request input, and it must only compare the hash, never return or log it.
pub async fn stored_password_hash(valence: &Valence, user_id: &str) -> Result<Option<String>> {
    let bare = user_id.split_once(':').map_or(user_id, |(_, id)| id);
    let backend = valence.backend_for_table(USER_TABLE)?;
    let row = valence::get_record(
        backend.as_ref(),
        USER_TABLE,
        bare,
        valence::use_!(r"In **lepton auth**, we **read the signed-in user's stored password hash** to check the **current password** they typed before a sensitive change. The hash is only compared and is never shown to anyone."),
    )
    .await?;
    Ok(row
        .as_ref()
        .and_then(|r| r.get("password_hash"))
        .and_then(Value::as_str)
        .filter(|h| !h.trim().is_empty())
        .map(str::to_owned))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn unchanged_happy() {
        let stored =
            json!({"status": "active", "confirmed_at": "2026-01-01T00:00:00Z", "plan": null});
        let proposed = json!({"status": "active", "confirmed_at": "2026-01-01T00:00:00+00:00"});
        assert!(!protected_changed(
            &["status", "confirmed_at", "plan"],
            &proposed,
            &stored
        ));
    }

    #[test]
    fn each_changed_field_sad() {
        let stored = json!({"status": "active", "user_type": "person", "confirmed_at": "2026-01-01T00:00:00Z", "id_verified_at": null, "password_hash": "h"});
        for (field, value) in [
            ("status", json!("disabled")),
            ("user_type", json!("service")),
            ("confirmed_at", json!("2026-02-01T00:00:00Z")),
            ("id_verified_at", json!("2026-02-01T00:00:00Z")),
            ("password_hash", json!("other")),
        ] {
            let mut proposed = stored.clone();
            proposed[field] = value;
            assert!(
                protected_changed(USER_PROTECTED, &proposed, &stored),
                "{field}"
            );
        }
    }

    #[test]
    fn cleared_field_sad() {
        let stored = json!({"status": "active", "plan": "free"});
        assert!(protected_changed(
            &["status"],
            &json!({"status": null}),
            &stored
        ));
        assert!(protected_changed(&["plan"], &json!({}), &stored));
    }

    #[test]
    fn hidden_password_hash_is_not_a_change_happy() {
        let stored = json!({"password_hash": "h"});
        assert!(!protected_changed(
            &["password_hash"],
            &json!({"password_hash": null}),
            &stored
        ));
        assert!(!protected_changed(&["password_hash"], &json!({}), &stored));
    }
}
