//! [`verify_bearer_token`]: a presented token to the person or service user it acts as.

use chrono::{DateTime, Utc};
use serde_json::Value;
use valence::ownership::OwnershipService;
use valence::{Actor, Valence};

use super::personal::PERSONAL_TOKEN_TABLE;
use super::scope::{scopes_from_json, ApiScope};
use super::secret::{constant_time_eq, LeptonToken};
use crate::generated::ServiceUserTokenKind;
use crate::service_users::{active_service_user_owner, ref_id, ServiceUserId};

const SERVICE_USER_TOKEN_TABLE: &str = "service_user_token";
const USER_TABLE: &str = "user";

/// Who a verified token acts as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenPrincipal {
    /// A personal token: it acts as this person (`Actor::User` with the bare user id).
    Person(Actor),
    /// A service user token: it acts as the service user.
    ServiceUser {
        /// The service user the token acts as.
        service_user: ServiceUserId,
        /// The person who owns the service user.
        owner: Actor,
        /// Made by hand, or issued to a device.
        kind: ServiceUserTokenKind,
        /// The device a device token was issued to, when it names one.
        device_id: Option<String>,
    },
}

impl TokenPrincipal {
    /// The Valence actor to run the request as.
    #[must_use]
    pub fn actor(&self) -> Actor {
        match self {
            Self::Person(actor) => actor.clone(),
            Self::ServiceUser { service_user, .. } => service_user.actor(),
        }
    }
}

/// A token that verified: who it acts as and which APIs it may call.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedToken {
    /// Who the token acts as.
    pub principal: TokenPrincipal,
    /// The token's row id.
    pub token_id: String,
    /// The APIs the token may call.
    pub scopes: Vec<ApiScope>,
    /// When the token was last used before this request, if ever.
    pub last_used_at: Option<DateTime<Utc>>,
    /// The stored row the check read, kept for [`record_token_use`] so recording a use needs
    /// no second read through the lookup handle.
    row: Value,
}

impl std::fmt::Debug for VerifiedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedToken")
            .field("principal", &self.principal)
            .field("token_id", &self.token_id)
            .field("scopes", &self.scopes)
            .field("last_used_at", &self.last_used_at)
            .finish_non_exhaustive()
    }
}

impl VerifiedToken {
    /// Whether the token may call the API `scope` names.
    #[must_use]
    pub fn has_scope(&self, scope: &ApiScope) -> bool {
        self.scopes.contains(scope)
    }

    /// The table the token lives in: `personal_token` or `service_user_token`.
    #[must_use]
    pub const fn table(&self) -> &'static str {
        match self.principal {
            TokenPrincipal::Person(_) => PERSONAL_TOKEN_TABLE,
            TokenPrincipal::ServiceUser { .. } => SERVICE_USER_TOKEN_TABLE,
        }
    }
}

/// A stored timestamp: Unix seconds (how backends hold `DateTime`) or RFC 3339 text.
fn parse_time(value: &Value) -> Option<DateTime<Utc>> {
    if let Some(secs) = value.as_i64() {
        return DateTime::from_timestamp(secs, 0);
    }
    DateTime::parse_from_rfc3339(value.as_str()?)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Check a bearer token and name who it acts as, with its scopes.
///
/// Returns `Some` only when the token parses as `lptk_…`, its row exists in `personal_token`
/// or `service_user_token` and is not pending deletion, the secret hash matches, and it is
/// neither revoked nor expired. Then:
///
/// - a personal token's person must exist and be `active`;
/// - a service user token's service user must be `active`
///   ([`active_service_user_owner`]) and still owned by the token's owner.
///
/// Every other outcome, store errors included, is `None`, so a caller cannot tell an unknown
/// token from a revoked one.
///
/// The lookup happens before anyone is identified, so `v` is the host's System-level handle
/// for this lookup only; [`record_token_use`] reuses the row it read. Run the request itself on a Valence for
/// [`TokenPrincipal::actor`].
pub async fn verify_bearer_token(raw: &str, v: &Valence) -> Option<VerifiedToken> {
    let token = LeptonToken::parse(raw).ok()?;
    if let Some(row) = live_row(PERSONAL_TOKEN_TABLE, &token, v).await {
        return verify_personal(&token, &row, v).await;
    }
    let row = live_row(SERVICE_USER_TOKEN_TABLE, &token, v).await?;
    verify_service_user(&token, &row, v).await
}

/// The token's row in `table` when it exists, matches the secret, and is neither revoked,
/// expired, nor pending deletion.
async fn live_row(table: &str, token: &LeptonToken, v: &Valence) -> Option<Value> {
    let backend = v.backend_for_table(table).ok()?;
    let row = valence::get_record(
        backend.as_ref(),
        table,
        token.id(),
        valence::use_!(r"When a **person or service user** presents an access token, we **read the token's stored hash, scopes, expiry, and revoked time** to check that it is valid. Nothing is shown to anyone; an unknown, expired, or revoked token gets no access."),
    )
    .await
    .ok()??;
    OwnershipService::pending_deletion_gate(table, token.id(), v)
        .await
        .ok()?;
    let stored = row.get("token_hash").and_then(Value::as_str)?;
    if !constant_time_eq(stored, &token.hash()) {
        return None;
    }
    if row.get("revoked_at").is_some_and(|r| !r.is_null()) {
        return None;
    }
    if parse_time(row.get("expires_at")?)? <= Utc::now() {
        return None;
    }
    Some(row)
}

fn verified(token: &LeptonToken, row: &Value, principal: TokenPrincipal) -> VerifiedToken {
    VerifiedToken {
        principal,
        token_id: token.id().to_string(),
        scopes: scopes_from_json(row.get("scopes")),
        last_used_at: row.get("last_used_at").and_then(parse_time),
        row: row.clone(),
    }
}

async fn verify_personal(token: &LeptonToken, row: &Value, v: &Valence) -> Option<VerifiedToken> {
    let user_id = ref_id(row.get("user")?)?;
    let backend = v.backend_for_table(USER_TABLE).ok()?;
    let user = valence::get_record(
        backend.as_ref(),
        USER_TABLE,
        &user_id,
        valence::use_!(r"When a **personal access token** is presented, we **read its person's status** to check that the account is still active. Nothing is shown to anyone; a disabled or deleted account's tokens get no access."),
    )
    .await
    .ok()??;
    OwnershipService::pending_deletion_gate(USER_TABLE, &user_id, v)
        .await
        .ok()?;
    if user.get("status").and_then(Value::as_str) != Some("active") {
        return None;
    }
    Some(verified(
        token,
        row,
        TokenPrincipal::Person(Actor::User { user_id }),
    ))
}

async fn verify_service_user(
    token: &LeptonToken,
    row: &Value,
    v: &Valence,
) -> Option<VerifiedToken> {
    let service_user = ServiceUserId::parse(&ref_id(row.get("service_user")?)?).ok()?;
    let owner = active_service_user_owner(service_user.as_str(), v).await?;
    let Actor::User { user_id } = &owner else {
        return None;
    };
    let owner_bare = user_id
        .split_once(':')
        .map_or(user_id.as_str(), |(_, id)| id);
    if ref_id(row.get("user")?)? != owner_bare {
        return None;
    }
    let kind = match row.get("kind").and_then(Value::as_str) {
        None | Some("manual") => ServiceUserTokenKind::Manual,
        Some("device") => ServiceUserTokenKind::Device,
        Some(_) => return None,
    };
    let device_id = row
        .get("device_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let principal = TokenPrincipal::ServiceUser {
        service_user,
        owner,
        kind,
        device_id,
    };
    Some(verified(token, row, principal))
}

/// Record that `token` was just used, writing `last_used_at` as the token's own actor.
///
/// It reuses the row [`verify_bearer_token`] read, so nothing past the lookup before identity
/// touches the System handle. The write goes through `caller`, a Valence for
/// [`TokenPrincipal::actor`]. A person updates their own token; a service user passes
/// [`SERVICE_USER_TOKEN_TOUCH`](crate::service_users::SERVICE_USER_TOKEN_TOUCH), which lets it
/// change `last_used_at` and nothing else.
///
/// # Errors
///
/// A store or privacy error from the write. Callers treat this as best effort.
pub async fn record_token_use(token: &VerifiedToken, caller: &Valence) -> valence::Result<()> {
    use crate::generated::{PersonalToken, ServiceUserToken};

    let now = Utc::now();
    let purpose = valence::use_!(
        r"When an **access token** is used, we **save the time** as its **last used** time. Its owner sees it in the token list, to spot tokens nobody uses any more."
    );
    match token.principal {
        TokenPrincipal::Person(_) => {
            let model: PersonalToken = serde_json::from_value(token.row.clone())?;
            model
                .get_mutable(caller, purpose)
                .set_last_used_at(now)?
                .commit()
                .await?;
        }
        TokenPrincipal::ServiceUser { .. } => {
            let model: ServiceUserToken = serde_json::from_value(token.row.clone())?;
            model
                .get_mutable(caller, purpose)
                .set_last_used_at(now)?
                .commit()
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parse_time_accepts_stored_shapes() {
        assert!(parse_time(&json!(1_793_670_014)).is_some());
        assert!(parse_time(&json!("2026-11-02T00:00:00Z")).is_some());
        assert!(parse_time(&json!(null)).is_none());
        assert!(parse_time(&json!("soon")).is_none());
    }

    #[test]
    fn principal_actor_and_scope_check() {
        let id = ServiceUserId::new_v4();
        let token = VerifiedToken {
            principal: TokenPrincipal::ServiceUser {
                service_user: id.clone(),
                owner: Actor::User {
                    user_id: "alice".into(),
                },
                kind: ServiceUserTokenKind::Manual,
                device_id: None,
            },
            token_id: "t".into(),
            scopes: vec![ApiScope::parse("magnon:read").expect("scope")],
            last_used_at: None,
            row: Value::Null,
        };
        assert_eq!(token.principal.actor(), id.actor());
        assert_eq!(token.table(), "service_user_token");
        assert!(token.has_scope(&ApiScope::parse("magnon:read").expect("scope")));
        assert!(!token.has_scope(&ApiScope::parse("magnon:write").expect("scope")));

        let person = TokenPrincipal::Person(Actor::User {
            user_id: "alice".into(),
        });
        assert_eq!(
            person.actor(),
            Actor::User {
                user_id: "alice".into()
            }
        );
    }
}
