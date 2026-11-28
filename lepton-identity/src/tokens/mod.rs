//! Lepton access tokens: one model for people and for service users.
//!
//! A token lets a tool, an agent or a device call a host's APIs without a browser session.
//! There are two kinds, and both work the same way:
//!
//! - A **personal token** acts as its person. It lives in the `personal_token` table
//!   ([`generated::PersonalToken`](crate::generated::PersonalToken)), owned by that person.
//! - A **service user token** acts as its service user. It lives in the
//!   `service_user_token` table ([`generated::ServiceUserToken`](crate::generated::ServiceUserToken))
//!   and is made by hand on the service user's page or issued to a device.
//!
//! Every token is `lptk_<token id>_<secret>` ([`LeptonToken`]), shown once. Lepton stores
//! only a SHA-256 hash of the secret, with a label, the [`ApiScope`]s it may call, an expiry
//! 30 or 90 days out ([`TokenLifetime`]), when it was last used, and a revoke time.
//!
//! A request needs two things. The token must carry the scope for the API it calls, and the
//! person or service user must be allowed the action: for a service user that means its
//! Gauge groups, for a person their own permissions. A scope never grants anything by itself.
//!
//! [`verify_bearer_token`] turns a presented token into a [`VerifiedToken`]: who it acts as
//! ([`TokenPrincipal`]) and its scopes. `lepton_host_adapter::bearer_middleware` calls it on
//! each request, and `lepton_host_adapter::require_scope` refuses a route the token has no
//! scope for. Minting, listing and revoking are in `lepton_auth::tokens` (personal) and
//! `lepton_auth::service_users` (service user).
//!
//! # Privacy
//!
//! | Actor | Personal tokens | Service user tokens |
//! |-------|-----------------|---------------------|
//! | The person | read, create, revoke their own | read, create, revoke for service users they own |
//! | Gate's manage-any user | nothing | read and revoke |
//! | A service user | nothing | record its own token's last use; create the device token its owner approved |
//! | Anyone else | nothing | nothing |
//!
//! Nobody can change a token's owner, secret hash, scopes or expiry after it is created.
//! Deleting a person deletes their personal tokens; deleting a service user or its owner
//! deletes its tokens.

mod personal;
mod scope;
mod secret;
mod verify;

use serde_json::Value;

use crate::service_users::ref_id;

pub use personal::{PersonalTokenImmutableRule, PERSONAL_TOKEN_IMMUTABLE};
pub use scope::{
    scopes_from_json, scopes_to_json, ApiScope, InvalidApiScope, TokenLifetime, MAX_SCOPE_LEN,
};
pub(crate) use secret::constant_time_eq;
pub use secret::{hash_token_secret, LeptonToken, TokenParseError, TOKEN_PREFIX};
pub(crate) use verify::parse_time;
pub use verify::{record_token_use, verify_bearer_token, TokenPrincipal, VerifiedToken};

/// Token fields that hold a record link. They compare by bare id, since a proposed row may
/// spell a link differently from the stored one.
const LINK_FIELDS: &[&str] = &["user", "service_user"];

/// A stored field reduced to what matters when comparing a proposed row with the stored one:
/// record links compare by bare id, everything else by value, and null equals absent.
#[derive(PartialEq)]
enum Compared<'a> {
    Absent,
    Link(String),
    Raw(&'a Value),
}

fn compared<'a>(field: &str, value: Option<&'a Value>) -> Compared<'a> {
    match value {
        None | Some(Value::Null) => Compared::Absent,
        Some(v) if LINK_FIELDS.contains(&field) => {
            ref_id(v).map_or(Compared::Raw(v), Compared::Link)
        }
        Some(v) => Compared::Raw(v),
    }
}

/// Whether any of `fields` differs between a proposed row and the stored row.
pub(crate) fn fields_changed(fields: &[&str], proposed: &Value, stored: &Value) -> bool {
    fields
        .iter()
        .any(|f| compared(f, proposed.get(*f)) != compared(f, stored.get(*f)))
}

/// Whether the update clears or moves a revoke that is already stored. Revoking (empty to a
/// time) is allowed; nobody, the owner included, can bring a revoked token back.
pub(crate) fn revoke_undone(proposed: &Value, stored: &Value) -> bool {
    let field = "revoked_at";
    let before = compared(field, stored.get(field));
    before != Compared::Absent && compared(field, proposed.get(field)) != before
}

/// Whether any field other than `allowed` (and the row key) differs between the two rows.
pub(crate) fn changed_other_than(allowed: &str, proposed: &Value, stored: &Value) -> bool {
    changed_outside(&[allowed], proposed, stored)
}

/// Whether any field outside `allowed` (and the row key) differs between the two rows.
pub(crate) fn changed_outside(allowed: &[&str], proposed: &Value, stored: &Value) -> bool {
    let keys = |row: &Value| {
        row.as_object()
            .map_or_default(|o| o.keys().cloned().collect::<Vec<_>>())
    };
    let mut fields = keys(proposed);
    fields.extend(keys(stored));
    fields.retain(|f| !allowed.contains(&f.as_str()) && f != "id");
    let fields: Vec<&str> = fields.iter().map(String::as_str).collect();
    fields_changed(&fields, proposed, stored)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn fields_changed_normalizes_links_and_nulls() {
        let stored = json!({"user": "user:a", "scopes": ["magnon:read"], "expires_at": 10, "revoked_at": null});
        let same =
            json!({"user": {"tb": "user", "id": "a"}, "scopes": ["magnon:read"], "expires_at": 10});
        let fields = ["user", "scopes", "expires_at", "revoked_at"];
        assert!(!fields_changed(&fields, &same, &stored));
        for (field, value) in [
            ("user", json!("user:b")),
            ("scopes", json!(["magnon:read", "magnon:write"])),
            ("scopes", json!([])),
            ("expires_at", json!(11)),
            ("revoked_at", json!(5)),
        ] {
            let mut proposed = same.clone();
            proposed[field] = value;
            assert!(fields_changed(&fields, &proposed, &stored), "{field}");
        }
    }

    #[test]
    fn revoke_is_one_way() {
        let live = json!({"revoked_at": null});
        let revoked = json!({"revoked_at": 50});
        assert!(!revoke_undone(&revoked, &live), "revoking is allowed");
        assert!(
            !revoke_undone(&revoked, &revoked),
            "keeping the revoke is allowed"
        );
        assert!(revoke_undone(&live, &revoked), "clearing is refused");
        assert!(
            revoke_undone(&json!({}), &revoked),
            "dropping the field is refused"
        );
        assert!(
            revoke_undone(&json!({"revoked_at": 60}), &revoked),
            "moving is refused"
        );
    }

    #[test]
    fn changed_other_than_allows_one_field() {
        let stored = json!({"id": "t", "label": "ci", "last_used_at": null, "revoked_at": null});
        let touch = json!({"id": "service_user_token:t", "label": "ci", "last_used_at": 99});
        assert!(!changed_other_than("last_used_at", &touch, &stored));
        let revoke = json!({"id": "t", "label": "ci", "last_used_at": 99, "revoked_at": 99});
        assert!(changed_other_than("last_used_at", &revoke, &stored));
        let relabel = json!({"id": "t", "label": "x", "last_used_at": 99});
        assert!(changed_other_than("last_used_at", &relabel, &stored));
        let relabel = json!({"id": "t", "label": "a:ci", "last_used_at": 99});
        assert!(changed_other_than("last_used_at", &relabel, &stored));
    }
}
