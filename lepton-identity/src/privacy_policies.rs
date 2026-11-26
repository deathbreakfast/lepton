//! Valence privacy rules for identity tables.
//!
//! The stock `OWNER_BY_USER_FIELD` reads a `user` field, which File rows lack: the trait
//! records the uploader in `uploaded_by`. [`OWNER_BY_UPLOADED_BY`] matches the session user
//! against that field instead.
//!
//! The `user_profile` contact fields (`contact_email`, `contact_phone`, `chat_handle`) are
//! owner-only unless the owner shares them. Each has a `<field>_share` setting next to it,
//! and the matching rule here ([`CONTACT_EMAIL_SHARED`], [`CONTACT_PHONE_SHARED`],
//! [`CHAT_HANDLE_SHARED`]) lets a signed-in user read the value only when that setting is
//! `"signed_in"`. The schema lists each rule beside `OWNER_BY_USER_FIELD`, so the owner and
//! System always read their own values.

use valence::privacy_policies::owner::check_owner_by_field;
use valence::{Actor, PrivacyRule};

fn owner_by_uploaded_by_check(record: &serde_json::Value, viewer: &Actor) -> bool {
    check_owner_by_field(record, viewer, "uploaded_by")
}

/// Owner match via the `uploaded_by` field (File-trait rows such as `profile_photo`).
///
/// System passes, as it does for `OWNER_BY_USER_FIELD`.
pub const OWNER_BY_UPLOADED_BY: PrivacyRule = PrivacyRule {
    name: "lepton_owner_by_uploaded_by",
    description: Some("Owner check via \"uploaded_by\" field"),
    check: owner_by_uploaded_by_check,
};

/// Share setting value that lets every signed-in user read a contact field.
pub const SHARE_WITH_SIGNED_IN: &str = "signed_in";

/// A signed-in user (`Actor::User`) reading a field whose `share_field` is `"signed_in"`.
///
/// Service users, anonymous callers, and an unset or `"owner"` setting are refused.
fn shared_with_signed_in(record: &serde_json::Value, viewer: &Actor, share_field: &str) -> bool {
    viewer.is_user()
        && record.get(share_field).and_then(serde_json::Value::as_str) == Some(SHARE_WITH_SIGNED_IN)
}

fn contact_email_shared_check(record: &serde_json::Value, viewer: &Actor) -> bool {
    shared_with_signed_in(record, viewer, "contact_email_share")
}

fn contact_phone_shared_check(record: &serde_json::Value, viewer: &Actor) -> bool {
    shared_with_signed_in(record, viewer, "contact_phone_share")
}

fn chat_handle_shared_check(record: &serde_json::Value, viewer: &Actor) -> bool {
    shared_with_signed_in(record, viewer, "chat_handle_share")
}

/// Signed-in users read `user_profile.contact_email` when `contact_email_share` is `"signed_in"`.
pub const CONTACT_EMAIL_SHARED: PrivacyRule = PrivacyRule {
    name: "lepton_contact_email_shared",
    description: Some("Signed-in user reads a contact email its owner shared with signed-in users"),
    check: contact_email_shared_check,
};

/// Signed-in users read `user_profile.contact_phone` when `contact_phone_share` is `"signed_in"`.
pub const CONTACT_PHONE_SHARED: PrivacyRule = PrivacyRule {
    name: "lepton_contact_phone_shared",
    description: Some("Signed-in user reads a contact phone its owner shared with signed-in users"),
    check: contact_phone_shared_check,
};

/// Signed-in users read `user_profile.chat_handle` when `chat_handle_share` is `"signed_in"`.
pub const CHAT_HANDLE_SHARED: PrivacyRule = PrivacyRule {
    name: "lepton_chat_handle_shared",
    description: Some("Signed-in user reads a chat handle its owner shared with signed-in users"),
    check: chat_handle_shared_check,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn user(id: &str) -> Actor {
        Actor::User { user_id: id.into() }
    }

    #[test]
    fn uploader_matches() {
        let record = serde_json::json!({ "uploaded_by": "user:alice" });
        assert!(owner_by_uploaded_by_check(&record, &user("alice")));
    }

    #[test]
    fn other_user_denied() {
        let record = serde_json::json!({ "uploaded_by": "user:alice" });
        assert!(!owner_by_uploaded_by_check(&record, &user("bob")));
    }

    #[test]
    fn record_without_uploaded_by_denied() {
        let record = serde_json::json!({ "user": "user:alice" });
        assert!(!owner_by_uploaded_by_check(&record, &user("alice")));
    }

    #[test]
    fn system_allowed() {
        let record = serde_json::json!({ "uploaded_by": "user:alice" });
        assert!(owner_by_uploaded_by_check(
            &record,
            &Actor::System {
                operation: "test".into()
            }
        ));
    }

    #[test]
    fn shared_contact_field_signed_in_user_allowed() {
        let record =
            serde_json::json!({ "user": "user:alice", "contact_email_share": "signed_in" });
        assert!(contact_email_shared_check(&record, &user("bob")));
    }

    #[test]
    fn unshared_contact_field_denied() {
        for record in [
            serde_json::json!({ "user": "user:alice" }),
            serde_json::json!({ "user": "user:alice", "contact_phone_share": null }),
            serde_json::json!({ "user": "user:alice", "contact_phone_share": "owner" }),
        ] {
            assert!(
                !contact_phone_shared_check(&record, &user("bob")),
                "{record}"
            );
        }
    }

    #[test]
    fn share_setting_applies_to_its_own_field_only() {
        let record =
            serde_json::json!({ "user": "user:alice", "contact_email_share": "signed_in" });
        assert!(!contact_phone_shared_check(&record, &user("bob")));
        assert!(!chat_handle_shared_check(&record, &user("bob")));
    }

    #[test]
    fn shared_contact_field_non_user_actor_denied() {
        let record = serde_json::json!({ "user": "user:alice", "chat_handle_share": "signed_in" });
        for viewer in [
            Actor::ServiceUser {
                service_name: "svc:00000000-0000-4000-8000-000000000000".into(),
            },
            Actor::Anonymous,
        ] {
            assert!(!chat_handle_shared_check(&record, &viewer), "{viewer:?}");
        }
    }
}
