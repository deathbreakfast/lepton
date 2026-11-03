//! Valence privacy rules for identity tables that use the File trait.
//!
//! The stock `OWNER_BY_USER_FIELD` reads a `user` field, which File rows lack: the trait
//! records the uploader in `uploaded_by`. [`OWNER_BY_UPLOADED_BY`] matches the session user
//! against that field instead.

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
}
