//! Personal access tokens for registered service users.
//!
//! A token is `lpt_<token id>_<secret>`: the token id is the `service_user_token` row key and
//! the secret is 64 lowercase hex characters (256 random bits). Only the SHA-256 hash of the
//! secret is stored. [`verify_bearer_token`] turns a presented token into the service user it
//! acts as, and refuses unknown, malformed, revoked, expired, and suspended or deleted cases
//! alike, so a caller cannot tell them apart.

use std::any::Any;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use valence::ownership::OwnershipService;
use valence::{Actor, ActorContext, PolicyEvaluator, PrivacyOperation, Result, Valence};

use super::id::ServiceUserId;
use super::resolve::active_service_user_owner;
use super::rules::{identity_fields_changed, ref_id, user_actor, SERVICE_USER_TABLE};
use valence::privacy_policies::owner::check_owner_by_field;

const TOKEN_TABLE: &str = "service_user_token";

/// Fixed prefix of every token, so scanners and logs can spot a leaked one.
pub const TOKEN_PREFIX: &str = "lpt_";

const SECRET_HEX_LEN: usize = 64;

/// Fields that never change after a token is created.
const TOKEN_IMMUTABLE_FIELDS: &[&str] = &["user", "service_user", "token_hash", "expires_at"];

/// Why a presented token string is not shaped like a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceUserTokenParseError {
    /// Missing the `lpt_` prefix or the `_` between id and secret.
    Shape,
    /// The token id is not a canonical UUID.
    Id,
    /// The secret is not 64 lowercase hex characters.
    Secret,
}

/// A parsed token: the row id and the secret half.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceUserToken {
    id: String,
    secret: String,
}

impl std::fmt::Debug for ServiceUserToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceUserToken")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl ServiceUserToken {
    /// A fresh token with a random id and a random 256-bit secret.
    #[must_use]
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let secret = to_hex(&bytes);
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            secret,
        }
    }

    /// Parse `lpt_<id>_<secret>`.
    ///
    /// # Errors
    ///
    /// [`ServiceUserTokenParseError`] naming the first part that is wrong.
    pub fn parse(raw: &str) -> std::result::Result<Self, ServiceUserTokenParseError> {
        let rest = raw
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(ServiceUserTokenParseError::Shape)?;
        let (id, secret) = rest
            .split_once('_')
            .ok_or(ServiceUserTokenParseError::Shape)?;
        let parsed = uuid::Uuid::parse_str(id).map_err(|_| ServiceUserTokenParseError::Id)?;
        if parsed.to_string() != id {
            return Err(ServiceUserTokenParseError::Id);
        }
        let hex_ok = secret.len() == SECRET_HEX_LEN
            && secret
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !hex_ok {
            return Err(ServiceUserTokenParseError::Secret);
        }
        Ok(Self {
            id: id.to_string(),
            secret: secret.to_string(),
        })
    }

    /// The `service_user_token` row key.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The value to store in `token_hash`.
    #[must_use]
    pub fn hash(&self) -> String {
        hash_token_secret(&self.secret)
    }

    /// The full token string. Show it to the owner once; it cannot be recovered later.
    #[must_use]
    pub fn expose(&self) -> String {
        format!("{TOKEN_PREFIX}{}_{}", self.id, self.secret)
    }
}

/// Lowercase hex SHA-256 of a token secret.
#[must_use]
pub fn hash_token_secret(secret: &str) -> String {
    to_hex(&Sha256::digest(secret.as_bytes()))
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A service user that presented a valid token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedServiceUser {
    /// The service user the token acts as.
    pub service_user: ServiceUserId,
    /// The token that was presented (row id).
    pub token_id: String,
    /// The user who owns the service user.
    pub owner: Actor,
}

impl VerifiedServiceUser {
    /// The Valence actor to run the request as.
    #[must_use]
    pub fn actor(&self) -> Actor {
        self.service_user.actor()
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

/// Check a bearer token and name the service user it acts as.
///
/// Returns `Some` only when the token parses, its row exists and is not pending deletion, the
/// secret hash matches, it is neither revoked nor expired, and its service user is `active`
/// ([`active_service_user_owner`]) and still owned by the token's owner. Every other outcome,
/// store errors included, is `None`.
pub async fn verify_bearer_token(raw: &str, v: &Valence) -> Option<VerifiedServiceUser> {
    let token = ServiceUserToken::parse(raw).ok()?;
    let backend = v.backend_for_table(TOKEN_TABLE).ok()?;
    let row = valence::get_record(
        backend.as_ref(),
        TOKEN_TABLE,
        token.id(),
        valence::use_!(r"When a **service user** presents an access token, we **read the token's stored hash, expiry, and revoked time** to check that it is valid. Nothing is shown to anyone; an unknown, expired, or revoked token gets no access."),
    )
    .await
    .ok()??;
    OwnershipService::pending_deletion_gate(TOKEN_TABLE, token.id(), v)
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
    Some(VerifiedServiceUser {
        service_user,
        token_id: token.id().to_string(),
        owner,
    })
}

/// `create` rule: the caller owns both the token row and the service user it acts as.
///
/// The service user's owner is read from its stored row, so nobody mints a token for a service
/// user they do not own.
pub const SERVICE_USER_TOKEN_CREATE: ServiceUserTokenCreateRule = ServiceUserTokenCreateRule;

/// `update` `always_block` rule: blocks any change to the owner, service user, secret hash, or
/// expiry. Revoking sets `revoked_at` only.
pub const SERVICE_USER_TOKEN_IMMUTABLE: ServiceUserTokenImmutableRule =
    ServiceUserTokenImmutableRule;

/// See [`SERVICE_USER_TOKEN_CREATE`].
#[derive(Debug, Clone, Copy)]
pub struct ServiceUserTokenCreateRule;

/// See [`SERVICE_USER_TOKEN_IMMUTABLE`].
#[derive(Debug, Clone, Copy)]
pub struct ServiceUserTokenImmutableRule;

#[async_trait]
impl PolicyEvaluator for ServiceUserTokenCreateRule {
    fn name(&self) -> &'static str {
        "lepton::SERVICE_USER_TOKEN_CREATE"
    }

    fn description(&self) -> Option<&'static str> {
        Some("Caller creates an access token for a service user it owns")
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
        if !check_owner_by_field(record, &user, "user") {
            return Ok(false);
        }
        let Some(service_user) = record.get("service_user").and_then(ref_id) else {
            return Ok(false);
        };
        let backend = v.backend_for_table(SERVICE_USER_TABLE)?;
        let stored = valence::get_record(
            backend.as_ref(),
            SERVICE_USER_TABLE,
            &service_user,
            valence::use_!(r"Before a **service user access token** is saved, we **read the service user's stored owner** to make sure the person creating the token owns that service user. Nothing is shown to anyone; the check blocks the save when the owner differs."),
        )
        .await?;
        Ok(stored.is_some_and(|row| check_owner_by_field(&row, &user, "user")))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[async_trait]
impl PolicyEvaluator for ServiceUserTokenImmutableRule {
    fn name(&self) -> &'static str {
        "lepton::SERVICE_USER_TOKEN_IMMUTABLE"
    }

    fn description(&self) -> Option<&'static str> {
        Some("Blocks any update that changes a token's owner, service user, secret hash, or expiry")
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
        let backend = v.backend_for_table(TOKEN_TABLE)?;
        let stored = valence::get_record(
            backend.as_ref(),
            TOKEN_TABLE,
            &id,
            valence::use_!(r"Before anyone saves a change to a **service user access token**, we **read the stored owner, service user, and secret hash** to make sure the change does not **repoint the token** or **swap its secret**. Nothing is shown to anyone; the check blocks the save when they differ."),
        )
        .await?;
        let Some(stored) = stored else {
            return Ok(true);
        };
        Ok(identity_fields_changed(
            TOKEN_IMMUTABLE_FIELDS,
            record,
            &stored,
        ))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_parse_roundtrip_happy() {
        let token = ServiceUserToken::generate();
        let parsed = ServiceUserToken::parse(&token.expose()).expect("parse");
        assert_eq!(parsed, token);
        assert_eq!(parsed.hash(), token.hash());
        assert_eq!(token.hash().len(), 64);
        assert_ne!(token.hash(), token.secret);
    }

    #[test]
    fn parse_rejects_malformed_sad() {
        let good = ServiceUserToken::generate().expose();
        for bad in [
            "",
            "lpt_",
            "nope",
            &good.replacen("lpt_", "xpt_", 1),
            &good[..good.len() - 1],
            &format!("{good}0"),
            &good.to_uppercase(),
            "lpt_not-a-uuid_00",
        ] {
            assert!(ServiceUserToken::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn debug_redacts_secret_sad() {
        let token = ServiceUserToken::generate();
        assert!(!format!("{token:?}").contains(&token.secret));
    }

    #[test]
    fn parse_time_accepts_stored_shapes() {
        use serde_json::json;
        assert!(parse_time(&json!(1_793_670_014)).is_some());
        assert!(parse_time(&json!("2026-11-02T00:00:00Z")).is_some());
        assert!(parse_time(&json!(null)).is_none());
        assert!(parse_time(&json!("soon")).is_none());
    }

    #[test]
    fn constant_time_eq_cases() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
    }
}
