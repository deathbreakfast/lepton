//! Bot ids and their Valence actor encoding.

use std::fmt;

use valence::Actor;

/// `service_name` prefix that marks an [`Actor::ServiceUser`] as a bot.
///
/// A bot acts as `Actor::ServiceUser { service_name: "bot:<id>" }`. Any other
/// service name is an infrastructure service user, never a bot.
pub const BOT_SERVICE_PREFIX: &str = "bot:";

/// Stable identity of a bot: a lowercase, hyphenated UUID.
///
/// The id is the bot's identity everywhere: the `bot` row primary key, the
/// actor's `service_name`, and audit rows. Handles can collide; ids cannot.
///
/// # Examples
///
/// ```
/// use lepton_identity::bots::BotId;
/// use valence::Actor;
///
/// let id = BotId::new_v4();
/// let actor = id.actor();
/// assert_eq!(BotId::from_actor(&actor), Some(id.clone()));
///
/// // An infrastructure service user is not a bot.
/// let cron = Actor::ServiceUser { service_name: "cron".into() };
/// assert_eq!(BotId::from_actor(&cron), None);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BotId(String);

/// Returned by [`BotId::parse`] when the text is not a canonical bot id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidBotId;

impl fmt::Display for InvalidBotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("reason_class=bot_id: not a lowercase hyphenated UUID")
    }
}

impl std::error::Error for InvalidBotId {}

impl BotId {
    /// Mint a fresh random id for a new bot.
    #[must_use]
    pub fn new_v4() -> Self {
        Self(uuid::Uuid::new_v4().hyphenated().to_string())
    }

    /// Parse a bot id, accepting a bare UUID or a `bot:<uuid>` record id.
    ///
    /// Only the canonical form is accepted: lowercase and hyphenated.
    ///
    /// # Errors
    ///
    /// [`InvalidBotId`] when the text is not a canonical UUID.
    pub fn parse(text: &str) -> Result<Self, InvalidBotId> {
        let bare = text.strip_prefix("bot:").unwrap_or(text);
        let parsed = uuid::Uuid::parse_str(bare).map_err(|_| InvalidBotId)?;
        let canonical = parsed.hyphenated().to_string();
        if canonical == bare {
            Ok(Self(canonical))
        } else {
            Err(InvalidBotId)
        }
    }

    /// The bare UUID text, as stored in the `bot.id` column.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The Valence actor this bot acts as.
    #[must_use]
    pub fn actor(&self) -> Actor {
        Actor::ServiceUser {
            service_name: format!("{BOT_SERVICE_PREFIX}{}", self.0),
        }
    }

    /// The bot behind `actor`, or `None` for users, System, anonymous actors,
    /// and service users whose name is not exactly `bot:<canonical uuid>`.
    #[must_use]
    pub fn from_actor(actor: &Actor) -> Option<Self> {
        let Actor::ServiceUser { service_name } = actor else {
            return None;
        };
        let bare = service_name.strip_prefix(BOT_SERVICE_PREFIX)?;
        // `parse` would also accept a second `bot:` prefix; reject it here.
        if bare.starts_with(BOT_SERVICE_PREFIX) {
            return None;
        }
        Self::parse(bare).ok()
    }
}

impl fmt::Display for BotId {
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
    fn bot_id_actor_round_trip_happy() {
        let id = BotId::parse(UUID).expect("canonical");
        let actor = id.actor();
        assert_eq!(
            actor,
            Actor::ServiceUser {
                service_name: format!("bot:{UUID}")
            }
        );
        assert_eq!(BotId::from_actor(&actor), Some(id.clone()));
        assert_eq!(BotId::parse(&format!("bot:{UUID}")), Ok(id));
        let fresh = BotId::new_v4();
        assert_eq!(BotId::from_actor(&fresh.actor()), Some(fresh));
    }

    #[test]
    fn bot_id_from_actor_rejects_infra_name_sad() {
        for name in ["cron", "ballot-bot", "service:bot", "bot", "bot:"] {
            let actor = Actor::ServiceUser {
                service_name: name.into(),
            };
            assert_eq!(BotId::from_actor(&actor), None, "{name}");
        }
    }

    #[test]
    fn bot_id_from_actor_rejects_user_actor_sad() {
        let user = Actor::User {
            user_id: format!("bot:{UUID}"),
        };
        assert_eq!(BotId::from_actor(&user), None);
        assert_eq!(BotId::from_actor(&Actor::Anonymous), None);
        let system = Actor::System {
            operation: format!("bot:{UUID}"),
        };
        assert_eq!(BotId::from_actor(&system), None);
    }

    #[test]
    fn bot_id_from_actor_rejects_bad_uuid_sad() {
        for name in [
            "bot:not-a-uuid",
            "bot:1b4e28ba2fa141d2883f0016d3cca427",
            "bot:{1b4e28ba-2fa1-41d2-883f-0016d3cca427}",
        ] {
            let actor = Actor::ServiceUser {
                service_name: name.into(),
            };
            assert_eq!(BotId::from_actor(&actor), None, "{name}");
        }
    }

    #[test]
    fn bot_id_from_actor_rejects_uppercase_sad() {
        let actor = Actor::ServiceUser {
            service_name: format!("bot:{}", UUID.to_uppercase()),
        };
        assert_eq!(BotId::from_actor(&actor), None);
        assert_eq!(BotId::parse(&UUID.to_uppercase()), Err(InvalidBotId));
    }

    #[test]
    fn bot_id_from_actor_rejects_trailing_garbage_sad() {
        for name in [
            format!("bot:{UUID} "),
            format!("bot:{UUID}x"),
            format!(" bot:{UUID}"),
            format!("bot:bot:{UUID}"),
        ] {
            let actor = Actor::ServiceUser {
                service_name: name.clone(),
            };
            assert_eq!(BotId::from_actor(&actor), None, "{name}");
        }
    }
}
