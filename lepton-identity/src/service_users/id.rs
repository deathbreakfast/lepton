//! Service user ids and their Valence actor encoding.

use std::fmt;

use valence::Actor;

/// `service_name` prefix that marks an [`Actor::ServiceUser`] as a registered
/// service user.
///
/// A registered service user acts as
/// `Actor::ServiceUser { service_name: "svc:<id>" }`. Any other service name is
/// a built-in service user that the host asserts, such as `cron`, with no row,
/// owner, or tokens.
pub const SERVICE_USER_PREFIX: &str = "svc:";

/// Prefix registered service users carried before they were renamed from bots.
/// Still reserved so a host can never assert it as a built-in name.
const LEGACY_BOT_PREFIX: &str = "bot:";

/// Whether `service_name` sits in the registered namespace (`svc:`, or the
/// retired `bot:`).
///
/// Host code that asserts a built-in service user must never use such a name,
/// and code that maps an untrusted label to a built-in service user must refuse
/// it. A `true` answer does not mean the name belongs to a live service user:
/// only [`ServiceUserId::from_actor`] plus a row lookup decides that, and it
/// never accepts the retired `bot:` form.
///
/// # Examples
///
/// ```
/// use lepton_identity::service_users::is_managed_service_name;
///
/// assert!(is_managed_service_name("svc:7c9e6679-7425-40de-944b-e07fc1f90ae7"));
/// assert!(is_managed_service_name("bot:7c9e6679-7425-40de-944b-e07fc1f90ae7"));
/// assert!(!is_managed_service_name("cron"));
/// ```
#[must_use]
pub fn is_managed_service_name(service_name: &str) -> bool {
    service_name.starts_with(SERVICE_USER_PREFIX) || service_name.starts_with(LEGACY_BOT_PREFIX)
}

/// Stable identity of a service user: a lowercase, hyphenated UUID.
///
/// The id is the service user's identity everywhere: the `service_user_account` row primary
/// key, the actor's `service_name`, and audit rows. Handles can collide; ids cannot.
///
/// # Examples
///
/// ```
/// use lepton_identity::service_users::ServiceUserId;
/// use valence::Actor;
///
/// let id = ServiceUserId::new_v4();
/// let actor = id.actor();
/// assert_eq!(ServiceUserId::from_actor(&actor), Some(id.clone()));
///
/// // A built-in service user has no id.
/// let cron = Actor::ServiceUser { service_name: "cron".into() };
/// assert_eq!(ServiceUserId::from_actor(&cron), None);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceUserId(String);

/// Returned by [`ServiceUserId::parse`] when the text is not a canonical service user id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidServiceUserId;

impl fmt::Display for InvalidServiceUserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("reason_class=service_user_id: not a lowercase hyphenated UUID")
    }
}

impl std::error::Error for InvalidServiceUserId {}

impl ServiceUserId {
    /// Mint a fresh random id for a new service user.
    #[must_use]
    pub fn new_v4() -> Self {
        Self(uuid::Uuid::new_v4().hyphenated().to_string())
    }

    /// Parse a service user id, accepting a bare UUID or a `svc:<uuid>` record id.
    ///
    /// Only the canonical form is accepted: lowercase and hyphenated.
    ///
    /// # Errors
    ///
    /// [`InvalidServiceUserId`] when the text is not a canonical UUID.
    pub fn parse(text: &str) -> Result<Self, InvalidServiceUserId> {
        let bare = text.strip_prefix(SERVICE_USER_PREFIX).unwrap_or(text);
        let parsed = uuid::Uuid::parse_str(bare).map_err(|_| InvalidServiceUserId)?;
        let canonical = parsed.hyphenated().to_string();
        if canonical == bare {
            Ok(Self(canonical))
        } else {
            Err(InvalidServiceUserId)
        }
    }

    /// The bare UUID text, as stored in the `service_user.id` column.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The Valence actor this service user acts as.
    #[must_use]
    pub fn actor(&self) -> Actor {
        Actor::ServiceUser {
            service_name: format!("{SERVICE_USER_PREFIX}{}", self.0),
        }
    }

    /// The registered service user behind `actor`, or `None` for users, System,
    /// anonymous actors, built-in service users, the retired `bot:<uuid>` form,
    /// and any name that is not exactly `svc:<canonical uuid>`.
    #[must_use]
    pub fn from_actor(actor: &Actor) -> Option<Self> {
        let Actor::ServiceUser { service_name } = actor else {
            return None;
        };
        let bare = service_name.strip_prefix(SERVICE_USER_PREFIX)?;
        // `parse` would also accept a second `svc:` prefix; reject it here.
        if bare.starts_with(SERVICE_USER_PREFIX) {
            return None;
        }
        Self::parse(bare).ok()
    }
}

impl fmt::Display for ServiceUserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const UUID: &str = "1b4e28ba-2fa1-41d2-883f-0016d3cca427";

    #[test]
    fn service_user_id_actor_round_trip_happy() {
        let id = ServiceUserId::parse(UUID).expect("canonical");
        let actor = id.actor();
        assert_eq!(
            actor,
            Actor::ServiceUser {
                service_name: format!("svc:{UUID}")
            }
        );
        assert_eq!(ServiceUserId::from_actor(&actor), Some(id.clone()));
        assert_eq!(ServiceUserId::parse(&format!("svc:{UUID}")), Ok(id));
        let fresh = ServiceUserId::new_v4();
        assert_eq!(ServiceUserId::from_actor(&fresh.actor()), Some(fresh));
    }

    #[test]
    fn service_user_id_from_actor_rejects_infra_name_sad() {
        for name in ["cron", "ballot-bot", "service:svc", "svc", "svc:"] {
            let actor = Actor::ServiceUser {
                service_name: name.into(),
            };
            assert_eq!(ServiceUserId::from_actor(&actor), None, "{name}");
        }
    }

    #[test]
    fn service_user_id_from_actor_rejects_user_actor_sad() {
        let user = Actor::User {
            user_id: format!("svc:{UUID}"),
        };
        assert_eq!(ServiceUserId::from_actor(&user), None);
        assert_eq!(ServiceUserId::from_actor(&Actor::Anonymous), None);
        let system = Actor::System {
            operation: format!("svc:{UUID}"),
        };
        assert_eq!(ServiceUserId::from_actor(&system), None);
    }

    #[test]
    fn service_user_id_from_actor_rejects_bad_uuid_sad() {
        for name in [
            "svc:not-a-uuid",
            "svc:1b4e28ba2fa141d2883f0016d3cca427",
            "svc:{1b4e28ba-2fa1-41d2-883f-0016d3cca427}",
        ] {
            let actor = Actor::ServiceUser {
                service_name: name.into(),
            };
            assert_eq!(ServiceUserId::from_actor(&actor), None, "{name}");
        }
    }

    #[test]
    fn service_user_id_from_actor_rejects_uppercase_sad() {
        let actor = Actor::ServiceUser {
            service_name: format!("svc:{}", UUID.to_uppercase()),
        };
        assert_eq!(ServiceUserId::from_actor(&actor), None);
        assert_eq!(
            ServiceUserId::parse(&UUID.to_uppercase()),
            Err(InvalidServiceUserId)
        );
    }

    #[test]
    fn service_user_id_from_actor_rejects_trailing_garbage_sad() {
        for name in [
            format!("svc:{UUID} "),
            format!("svc:{UUID}x"),
            format!(" svc:{UUID}"),
            format!("svc:svc:{UUID}"),
        ] {
            let actor = Actor::ServiceUser {
                service_name: name.clone(),
            };
            assert_eq!(ServiceUserId::from_actor(&actor), None, "{name}");
        }
    }

    #[test]
    fn service_user_id_parse_accepts_svc_prefix_happy() {
        let id = ServiceUserId::parse(&format!("svc:{UUID}")).expect("prefixed");
        assert_eq!(id.as_str(), UUID);
        assert_eq!(id.to_string(), UUID);
    }

    #[test]
    fn service_user_id_from_actor_rejects_legacy_bot_prefix_sad() {
        for name in [
            format!("bot:{UUID}"),
            format!("bot:svc:{UUID}"),
            format!("svc:bot:{UUID}"),
        ] {
            let actor = Actor::ServiceUser {
                service_name: name.clone(),
            };
            assert_eq!(ServiceUserId::from_actor(&actor), None, "{name}");
        }
        assert_eq!(
            ServiceUserId::parse(&format!("bot:{UUID}")),
            Err(InvalidServiceUserId)
        );
    }

    #[test]
    fn is_managed_service_name_reserves_svc_and_bot_happy() {
        for name in [
            format!("svc:{UUID}"),
            format!("bot:{UUID}"),
            "svc:".to_string(),
            "bot:".to_string(),
            "svc:anything".to_string(),
        ] {
            assert!(is_managed_service_name(&name), "{name}");
        }
    }

    #[test]
    fn is_managed_service_name_builtin_names_sad() {
        for name in [
            "cron",
            "spectra-ingest",
            "",
            "svc",
            "bot",
            "service:svc",
            " svc:x",
        ] {
            assert!(!is_managed_service_name(name), "{name}");
        }
    }
}
