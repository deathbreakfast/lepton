//! Privacy rules for the `device_authorization` and `signed_in_device` tables.

use std::any::Any;

use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use valence::privacy_policies::owner::check_owner_by_field;
use valence::{Actor, ActorContext, PolicyEvaluator, PrivacyOperation, Result, Valence};

use super::{DEVICE_AUTHORIZATION_TABLE, SIGNED_IN_DEVICE_TABLE};
use crate::service_users::{ref_id, user_actor, ServiceUserId};
use crate::tokens::{changed_outside, fields_changed, parse_time};

const SERVICE_USER_TABLE: &str = "service_user_account";

/// Request fields nobody changes while approving or denying.
const AUTH_IMMUTABLE_FIELDS: &[&str] = &[
    "device_code_hash",
    "user_code",
    "device_name",
    "client",
    "asked_from",
    "user_agent",
    "scopes",
    "expires_at",
    "created_at",
];

/// Device fields that never change after it signs in.
const DEVICE_IMMUTABLE_FIELDS: &[&str] = &[
    "user",
    "client",
    "asked_from",
    "user_agent",
    "device_code_hash",
    "scopes",
    "lifetime_days",
    "signed_in_at",
];

/// Device fields the service user it acts as may write when it collects a token.
const DEVICE_TOUCH_FIELDS: &[&str] = &["token", "status", "last_seen_at", "signed_in_until"];

/// `read` rule: a signed-in person reads a pending, unexpired device request.
///
/// The approval page looks a request up by the user code the person typed, so anyone signed in
/// may read pending requests. Once decided, only the approver reads it (`OWNER_BY_USER_FIELD`).
pub const DEVICE_AUTH_PENDING_READ: DeviceAuthPendingReadRule = DeviceAuthPendingReadRule;

/// `update` rule: a signed-in person approves or denies a pending, unexpired request once,
/// naming themselves as the approver, and changes nothing else.
pub const DEVICE_AUTH_DECIDE: DeviceAuthDecideRule = DeviceAuthDecideRule;

/// `create` rule: the caller signs a device in as a service user they own.
///
/// The row names the caller as `user`, starts with no token and `status = issue_pending`, and
/// the service user's stored owner is the caller, so nobody signs a device in as someone
/// else's service user, manage-any users included.
pub const SIGNED_IN_DEVICE_CREATE: SignedInDeviceCreateRule = SignedInDeviceCreateRule;

/// `read` rule: a service user reads the devices that act as it.
pub const SIGNED_IN_DEVICE_SELF: SignedInDeviceSelfRule = SignedInDeviceSelfRule;

/// `update` rule: the service user a device acts as records the token it was just issued.
///
/// It may set `token`, `last_seen_at` and `signed_in_until`, and move `status` from
/// `issue_pending` to `signed_in`, and only while a token is pending. Nothing else changes.
pub const SIGNED_IN_DEVICE_SELF_TOUCH: SignedInDeviceSelfTouchRule = SignedInDeviceSelfTouchRule;

/// `update` `always_block` rule: a device's owner, client, origin, code, scopes and lifetime
/// never change, and it only moves to a service user its owner also owns.
pub const SIGNED_IN_DEVICE_IMMUTABLE: SignedInDeviceImmutableRule = SignedInDeviceImmutableRule;

/// See [`DEVICE_AUTH_PENDING_READ`].
#[derive(Debug, Clone, Copy)]
pub struct DeviceAuthPendingReadRule;

/// See [`DEVICE_AUTH_DECIDE`].
#[derive(Debug, Clone, Copy)]
pub struct DeviceAuthDecideRule;

/// See [`SIGNED_IN_DEVICE_CREATE`].
#[derive(Debug, Clone, Copy)]
pub struct SignedInDeviceCreateRule;

/// See [`SIGNED_IN_DEVICE_SELF`].
#[derive(Debug, Clone, Copy)]
pub struct SignedInDeviceSelfRule;

/// See [`SIGNED_IN_DEVICE_SELF_TOUCH`].
#[derive(Debug, Clone, Copy)]
pub struct SignedInDeviceSelfTouchRule;

/// See [`SIGNED_IN_DEVICE_IMMUTABLE`].
#[derive(Debug, Clone, Copy)]
pub struct SignedInDeviceImmutableRule;

fn str_field<'a>(row: &'a Value, field: &str) -> Option<&'a str> {
    row.get(field).and_then(Value::as_str)
}

fn is_absent(row: &Value, field: &str) -> bool {
    row.get(field).is_none_or(Value::is_null)
}

/// A pending request that has not expired.
fn is_open(row: &Value) -> bool {
    str_field(row, "status") == Some("pending")
        && is_absent(row, "user")
        && row
            .get("expires_at")
            .and_then(parse_time)
            .is_some_and(|at| at > Utc::now())
}

fn service_user_actor(actor: &dyn ActorContext) -> Option<ServiceUserId> {
    let parsed: Actor = serde_json::from_value(actor.actor_json().clone()).ok()?;
    ServiceUserId::from_actor(&parsed)
}

async fn stored_row(v: &Valence, table: &str, id: &str) -> Result<Option<Value>> {
    let backend = v.backend_for_table(table)?;
    valence::get_record(
        backend.as_ref(),
        table,
        id,
        valence::use_!(r"Before a **device sign-in request or signed-in device** is changed, we **read the stored row** to check who owns it and what the change touches. Nothing is shown to anyone; the check only allows or blocks the change."),
    )
    .await
}

async fn service_user_owner(v: &Valence, service_user: &str) -> Result<Option<String>> {
    let backend = v.backend_for_table(SERVICE_USER_TABLE)?;
    let stored = valence::get_record(
        backend.as_ref(),
        SERVICE_USER_TABLE,
        service_user,
        valence::use_!(r"Before a **device** is signed in or moved, we **read the service user's stored owner** to make sure the person doing it owns that service user. Nothing is shown to anyone; the check blocks the change when the owner differs."),
    )
    .await?;
    Ok(stored.and_then(|row| row.get("user").and_then(ref_id)))
}

#[async_trait]
impl PolicyEvaluator for DeviceAuthPendingReadRule {
    fn name(&self) -> &'static str {
        "lepton::DEVICE_AUTH_PENDING_READ"
    }

    fn description(&self) -> Option<&'static str> {
        Some("A signed-in person reads a pending, unexpired device sign-in request")
    }

    async fn evaluate(
        &self,
        op: PrivacyOperation,
        record: &Value,
        actor: &dyn ActorContext,
        _v: &Valence,
    ) -> Result<bool> {
        Ok(matches!(op, PrivacyOperation::Read) && user_actor(actor).is_some() && is_open(record))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[async_trait]
impl PolicyEvaluator for DeviceAuthDecideRule {
    fn name(&self) -> &'static str {
        "lepton::DEVICE_AUTH_DECIDE"
    }

    fn description(&self) -> Option<&'static str> {
        Some("A signed-in person approves or denies a pending device sign-in request once, as themselves")
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
        let Some(user) = user_actor(actor) else {
            return Ok(false);
        };
        let Some(id) = record.get("id").and_then(ref_id) else {
            return Ok(false);
        };
        let Some(stored) = stored_row(v, DEVICE_AUTHORIZATION_TABLE, &id).await? else {
            return Ok(false);
        };
        if !is_open(&stored) || fields_changed(AUTH_IMMUTABLE_FIELDS, record, &stored) {
            return Ok(false);
        }
        // Valence checks the stored row and the proposed row; the stored one is unchanged.
        let unchanged = str_field(record, "status") == Some("pending") && is_absent(record, "user");
        let decided = matches!(str_field(record, "status"), Some("approved" | "denied"))
            && check_owner_by_field(record, &user, "user");
        Ok(unchanged || decided)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[async_trait]
impl PolicyEvaluator for SignedInDeviceCreateRule {
    fn name(&self) -> &'static str {
        "lepton::SIGNED_IN_DEVICE_CREATE"
    }

    fn description(&self) -> Option<&'static str> {
        Some("Caller signs a device in as a service user it owns")
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
        if !check_owner_by_field(record, &user, "user")
            || str_field(record, "status") != Some("issue_pending")
            || !is_absent(record, "token")
        {
            return Ok(false);
        }
        let Some(service_user) = record.get("service_user").and_then(ref_id) else {
            return Ok(false);
        };
        let owner = service_user_owner(v, &service_user).await?;
        Ok(owner.is_some() && owner == record.get("user").and_then(ref_id))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[async_trait]
impl PolicyEvaluator for SignedInDeviceSelfRule {
    fn name(&self) -> &'static str {
        "lepton::SIGNED_IN_DEVICE_SELF"
    }

    fn description(&self) -> Option<&'static str> {
        Some("A service user reads the devices that act as it")
    }

    async fn evaluate(
        &self,
        op: PrivacyOperation,
        record: &Value,
        actor: &dyn ActorContext,
        _v: &Valence,
    ) -> Result<bool> {
        if !matches!(op, PrivacyOperation::Read) {
            return Ok(false);
        }
        let Some(caller) = service_user_actor(actor) else {
            return Ok(false);
        };
        Ok(record.get("service_user").and_then(ref_id).as_deref() == Some(caller.as_str()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[async_trait]
impl PolicyEvaluator for SignedInDeviceSelfTouchRule {
    fn name(&self) -> &'static str {
        "lepton::SIGNED_IN_DEVICE_SELF_TOUCH"
    }

    fn description(&self) -> Option<&'static str> {
        Some("The service user a device acts as records the token it was just issued, and changes nothing else")
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
        let Some(caller) = service_user_actor(actor) else {
            return Ok(false);
        };
        let Some(id) = record.get("id").and_then(ref_id) else {
            return Ok(false);
        };
        let Some(stored) = stored_row(v, SIGNED_IN_DEVICE_TABLE, &id).await? else {
            return Ok(false);
        };
        let own = stored.get("service_user").and_then(ref_id).as_deref() == Some(caller.as_str());
        if !own || changed_outside(DEVICE_TOUCH_FIELDS, record, &stored) {
            return Ok(false);
        }
        if !fields_changed(&["token", "status"], record, &stored) {
            return Ok(true);
        }
        Ok(str_field(&stored, "status") == Some("issue_pending")
            && str_field(record, "status") == Some("signed_in"))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[async_trait]
impl PolicyEvaluator for SignedInDeviceImmutableRule {
    fn name(&self) -> &'static str {
        "lepton::SIGNED_IN_DEVICE_IMMUTABLE"
    }

    fn description(&self) -> Option<&'static str> {
        Some("Blocks any update that changes a device's owner, client, origin, code, scopes or lifetime, or moves it to a service user its owner doesn't own")
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
        let Some(stored) = stored_row(v, SIGNED_IN_DEVICE_TABLE, &id).await? else {
            return Ok(true);
        };
        if fields_changed(DEVICE_IMMUTABLE_FIELDS, record, &stored) {
            return Ok(true);
        }
        if !fields_changed(&["service_user"], record, &stored) {
            return Ok(false);
        }
        let Some(target) = record.get("service_user").and_then(ref_id) else {
            return Ok(true);
        };
        let owner = service_user_owner(v, &target).await?;
        Ok(owner.is_none() || owner != stored.get("user").and_then(ref_id))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use serde_json::json;

    use super::*;

    fn pending(expires_in: Duration) -> Value {
        json!({
            "id": "a",
            "status": "pending",
            "expires_at": (Utc::now() + expires_in).to_rfc3339(),
        })
    }

    #[test]
    fn open_request_happy() {
        assert!(is_open(&pending(Duration::minutes(5))));
    }

    #[test]
    fn closed_requests_sad() {
        assert!(!is_open(&pending(Duration::minutes(-1))));
        let mut decided = pending(Duration::minutes(5));
        decided["status"] = json!("approved");
        assert!(!is_open(&decided));
        let mut claimed = pending(Duration::minutes(5));
        claimed["user"] = json!("user:mei");
        assert!(!is_open(&claimed));
    }
}
