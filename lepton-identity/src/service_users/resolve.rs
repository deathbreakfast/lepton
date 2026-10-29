//! The owner behind an active registered service user.

use serde_json::Value;
use valence::ownership::OwnershipService;
use valence::{Actor, Valence};

use super::id::ServiceUserId;
use super::rules::ref_id;

const SERVICE_USER_TABLE: &str = "service_user_account";

/// The owner of the registered service user named by `raw`, when that service user
/// can act right now.
///
/// `raw` is a service user id, bare (`<uuid>`) or as the actor's service name
/// (`svc:<uuid>`). The answer is `Some(Actor::User { .. })` for the owning user only when
/// the id is canonical, the row exists, its status is `active`, and it is not pending
/// deletion. Everything else is `None`: built-in service names such as `cron`, the
/// retired `bot:<uuid>` form, unknown ids, suspended or deleted service users, and
/// store errors.
///
/// The row is read from the backend directly, so the answer does not depend on who is
/// asking. Callers decide what the owner may reach; [`SERVICE_USER_ACTIVE`] is the
/// ready-made Valence rule for tables owned through a `user` field.
///
/// [`SERVICE_USER_ACTIVE`]: super::SERVICE_USER_ACTIVE
pub async fn active_service_user_owner(raw: &str, v: &Valence) -> Option<Actor> {
    let id = ServiceUserId::parse(raw).ok()?;
    let backend = v.backend_for_table(SERVICE_USER_TABLE).ok()?;
    let row = valence::get_record(
        backend.as_ref(),
        SERVICE_USER_TABLE,
        id.as_str(),
        valence::use_!(r"When a **service user** acts, we **read its owner and status** to check that it is still active and to find the person it acts for. Nothing is shown to anyone; a suspended or deleted service user gets no access."),
    )
    .await
    .ok()??;
    OwnershipService::pending_deletion_gate(SERVICE_USER_TABLE, id.as_str(), v)
        .await
        .ok()?;
    owner_from_active_row(&row)
}

/// The owning user of a stored service user row whose status is `active`.
fn owner_from_active_row(row: &Value) -> Option<Actor> {
    if row.get("status").and_then(Value::as_str) != Some("active") {
        return None;
    }
    let user_id = ref_id(row.get("user")?)?;
    Some(Actor::User { user_id })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn owner(user_id: &str) -> Actor {
        Actor::User {
            user_id: user_id.into(),
        }
    }

    #[test]
    fn owner_from_active_row_happy() {
        let string_link = json!({"status": "active", "user": "user:alice"});
        assert_eq!(owner_from_active_row(&string_link), Some(owner("alice")));
        let record_link = json!({"status": "active", "user": {"tb": "user", "id": "alice"}});
        assert_eq!(owner_from_active_row(&record_link), Some(owner("alice")));
    }

    #[test]
    fn owner_from_suspended_row_sad() {
        let row = json!({"status": "suspended", "user": "user:alice"});
        assert_eq!(owner_from_active_row(&row), None);
    }

    #[test]
    fn owner_from_row_without_owner_sad() {
        for row in [
            json!({"status": "active"}),
            json!({"status": "active", "user": null}),
            json!({"status": "active", "user": ""}),
            json!({"user": "user:alice"}),
        ] {
            assert_eq!(owner_from_active_row(&row), None, "{row}");
        }
    }
}
