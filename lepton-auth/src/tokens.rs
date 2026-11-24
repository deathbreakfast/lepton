//! Personal access tokens: create, list, and revoke tokens that act as their person.
//!
//! A personal token lets a tool or an agent act as the person who made it, through the APIs
//! they tick. It is the same model as a service user token (see
//! [`lepton_identity::tokens`]): `lptk_…`, shown once, stored as a hash, with a label,
//! scopes, a 30- or 90-day expiry, a last-used time and a revoke time. For a device other
//! people can use, sign it in as a service user instead; its token then acts as the service
//! user ([`crate::service_users`]).
//!
//! | Call | Who | Notes |
//! |------|-----|-------|
//! | [`create_personal_token`] | the signed-in person | needs a recent step-up and the `totp` feature; [`MAX_PERSONAL_TOKENS`] live tokens each |
//! | [`list_personal_tokens`] | the signed-in person | their own tokens only |
//! | [`revoke_personal_token`] | the signed-in person | stops the token at once |
//!
//! Nobody else, managers included, can see or revoke a person's tokens. A service user can't
//! make personal tokens. Deleting the person deletes their tokens.

use chrono::{DateTime, Utc};
use lepton_host_adapter::generated::PersonalToken as TokenRow;
use lepton_identity::tokens::{scopes_to_json, ApiScope, LeptonToken, TokenLifetime};
use thiserror::Error;
use tokio::sync::Mutex;
use valence::{Actor, Model, RecordId, Valence};

use crate::scopes::{check_scopes, ScopeError};

/// Live (unrevoked, unexpired) personal tokens one person can have at once.
pub const MAX_PERSONAL_TOKENS: usize = 25;

const MAX_LABEL: usize = 80;

/// Serializes the count-then-insert in [`create_personal_token`] so concurrent creates cannot
/// both pass the limit.
static CREATE_LOCK: Mutex<()> = Mutex::const_new(());

/// Why a personal token call failed.
///
/// Messages start with `reason_class=<class>` and never echo the label the caller sent.
#[derive(Debug, Error)]
pub enum PersonalTokenError {
    /// The caller is not a signed-in person. Service users, System and anonymous callers have
    /// no personal tokens.
    #[error("reason_class=actor: only a signed-in person has personal tokens")]
    NotAUser,
    /// Minting a token needs a recent step-up, and there is none. `reason_class` is the
    /// step-up reason, such as `step_up_required` or `totp_enrollment_required`.
    #[error("reason_class=step_up: step-up needed ({reason_class})")]
    StepUp {
        /// The step-up failure's reason class.
        reason_class: &'static str,
    },
    /// The label or the scopes are not acceptable.
    #[error("reason_class=profile: invalid {field}")]
    InvalidProfile {
        /// `label` or `scopes`.
        field: &'static str,
    },
    /// The host registered no API scopes, so no token can be minted. A host configuration
    /// problem; see [`register_api_scopes`](crate::scopes::register_api_scopes).
    #[error("reason_class=not_configured: no API scopes registered")]
    ScopesNotRegistered,
    /// The person already has [`MAX_PERSONAL_TOKENS`] live tokens. Revoking one frees a slot.
    #[error("reason_class=quota: personal token limit of {limit} reached")]
    QuotaReached {
        /// The per-person limit.
        limit: usize,
    },
    /// No such token among the caller's own.
    #[error("reason_class=not_found: token not found")]
    NotFound,
    /// The store refused the write on privacy grounds.
    #[error("reason_class=forbidden: not allowed to change this token")]
    Forbidden,
    /// Storage failed.
    #[error("reason_class=store: personal token store operation failed")]
    Store,
}

impl PersonalTokenError {
    /// Stable, loggable cause class.
    #[must_use]
    pub const fn reason_class(&self) -> &'static str {
        match self {
            Self::NotAUser => "actor",
            Self::StepUp { .. } => "step_up",
            Self::InvalidProfile { .. } => "profile",
            Self::ScopesNotRegistered => "not_configured",
            Self::QuotaReached { .. } => "quota",
            Self::NotFound => "not_found",
            Self::Forbidden => "forbidden",
            Self::Store => "store",
        }
    }

    /// Map a failed step-up check: no signed-in session is [`Self::NotAUser`], a session store
    /// failure is [`Self::Store`], and everything else is [`Self::StepUp`].
    #[cfg(feature = "totp")]
    const fn from_step_up(e: &crate::step_up::StepUpError) -> Self {
        use crate::step_up::StepUpError;
        match e {
            StepUpError::AuthRequired => Self::NotAUser,
            StepUpError::Store => Self::Store,
            other => Self::StepUp {
                reason_class: other.reason_class(),
            },
        }
    }
}

/// Settings for a new personal token. See [`create_personal_token`].
#[derive(Debug, Clone, Copy)]
pub struct NewPersonalToken<'a> {
    /// What the token is for, such as `Laptop CLI` (1-80 characters).
    pub label: &'a str,
    /// The APIs the token may call. At least one, each registered by the host
    /// ([`register_api_scopes`](crate::scopes::register_api_scopes)).
    pub scopes: &'a [ApiScope],
    /// How long the token lasts: 30 or 90 days.
    pub lifetime: TokenLifetime,
}

/// A personal token just created: the stored row plus the one-time plaintext.
#[derive(Clone)]
pub struct CreatedPersonalToken {
    /// The stored row. It holds the hash, never the plaintext.
    pub row: TokenRow,
    /// The full bearer token. Show it once; it cannot be recovered.
    pub token: String,
}

impl std::fmt::Debug for CreatedPersonalToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedPersonalToken")
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

fn caller_bare(valence: &Valence) -> Result<String, PersonalTokenError> {
    match valence.actor() {
        Actor::User { user_id } => Ok(user_id
            .split_once(':')
            .map_or(user_id.as_str(), |(_, id)| id)
            .to_string()),
        _ => Err(PersonalTokenError::NotAUser),
    }
}

fn is_live(row: &TokenRow, now: DateTime<Utc>) -> bool {
    row.revoked_at().is_none() && *row.expires_at() > now
}

const fn write_error(e: &valence::Error) -> PersonalTokenError {
    match e {
        valence::Error::Privacy(_) => PersonalTokenError::Forbidden,
        _ => PersonalTokenError::Store,
    }
}

fn log(op: &'static str, result: Result<(), &PersonalTokenError>) {
    match result {
        Ok(()) => tracing::info!(target: "lepton.token", op, "personal token"),
        Err(e) => tracing::debug!(
            target: "lepton.token",
            op,
            reason_class = e.reason_class(),
            "personal token refused"
        ),
    }
}

/// Create a personal token for the signed-in person, after a recent step-up.
///
/// Call it from a server function with the request Valence (`ctx.valence()`). It first
/// checks the session's step-up window
/// ([`require_recent_verification`](crate::step_up::require_recent_verification)); open one
/// with lepton-auth-ui's step-up flow before calling.
///
/// # Errors
///
/// - [`PersonalTokenError::StepUp`] when the session has no recent step-up.
/// - [`PersonalTokenError::NotAUser`] when the caller is not a signed-in person.
/// - [`PersonalTokenError::InvalidProfile`] for a bad `label` or `scopes`.
/// - [`PersonalTokenError::ScopesNotRegistered`] when the host registered no scopes.
/// - [`PersonalTokenError::QuotaReached`] at [`MAX_PERSONAL_TOKENS`] live tokens.
/// - [`PersonalTokenError::Forbidden`] or [`PersonalTokenError::Store`] when the save fails.
#[cfg(feature = "totp")]
pub async fn create_personal_token(
    valence: &Valence,
    input: NewPersonalToken<'_>,
) -> Result<CreatedPersonalToken, PersonalTokenError> {
    use crate::step_up::{require_recent_verification, StepUpScope};

    if let Err(e) = require_recent_verification(StepUpScope::SensitiveMutation).await {
        let err = PersonalTokenError::from_step_up(&e);
        log("token_create", Err(&err));
        return Err(err);
    }
    mint_personal_token(valence, input).await
}

/// **Test only.** [`create_personal_token`] without the step-up check, for suites that run
/// without an HTTP session.
///
/// # Errors
///
/// As [`create_personal_token`], except [`PersonalTokenError::StepUp`].
#[cfg(feature = "test-utils")]
pub async fn create_personal_token_without_step_up(
    valence: &Valence,
    input: NewPersonalToken<'_>,
) -> Result<CreatedPersonalToken, PersonalTokenError> {
    mint_personal_token(valence, input).await
}

#[cfg_attr(not(any(feature = "totp", feature = "test-utils")), allow(dead_code))]
async fn mint_personal_token(
    valence: &Valence,
    input: NewPersonalToken<'_>,
) -> Result<CreatedPersonalToken, PersonalTokenError> {
    let result = create_inner(valence, input).await;
    log("token_create", result.as_ref().map(|_| ()));
    result
}

async fn create_inner(
    valence: &Valence,
    input: NewPersonalToken<'_>,
) -> Result<CreatedPersonalToken, PersonalTokenError> {
    let owner = caller_bare(valence)?;
    let label = input.label.trim();
    if label.is_empty() || label.chars().count() > MAX_LABEL {
        return Err(PersonalTokenError::InvalidProfile { field: "label" });
    }
    let scopes = check_scopes(input.scopes).map_err(|e| match e {
        ScopeError::NotRegistered => PersonalTokenError::ScopesNotRegistered,
        ScopeError::Empty | ScopeError::Unknown(_) => {
            PersonalTokenError::InvalidProfile { field: "scopes" }
        }
    })?;
    let now = Utc::now();

    let _guard = CREATE_LOCK.lock().await;
    let live = list_rows(valence, &owner)
        .await?
        .iter()
        .filter(|r| is_live(r, now))
        .count();
    if live >= MAX_PERSONAL_TOKENS {
        return Err(PersonalTokenError::QuotaReached {
            limit: MAX_PERSONAL_TOKENS,
        });
    }

    let token = LeptonToken::generate();
    let row = TokenRow::new(
        RecordId::new("user", &owner),
        label.to_string(),
        token.hash(),
        scopes_to_json(&scopes),
        input.lifetime.expires_at(now),
        None,
        None,
        now,
    )
    .map_err(|_| PersonalTokenError::Store)?;
    let row = TokenRow::upsert(
        token.id(),
        row,
        valence,
        valence::use_!(r"When you **create a personal token**, we **save its label, the APIs it may call, its expiry, and a one-way hash of the secret**, and **show you the token once**. You see the label, APIs, expiry and last use under Your tokens; the secret itself is never stored."),
    )
    .await
    .map_err(|e| write_error(&e))?;
    Ok(CreatedPersonalToken {
        row,
        token: token.expose(),
    })
}

async fn list_rows(valence: &Valence, owner: &str) -> Result<Vec<TokenRow>, PersonalTokenError> {
    TokenRow::get_from_user_id(
        owner,
        valence,
        valence::use_!(r"Under **Your tokens**, we **list your personal tokens** with their label, the APIs they may call, expiry, last use, and whether they are revoked, so you can see and revoke them. The secret is never included."),
    )
    .await
    .map_err(|_| PersonalTokenError::Store)
}

/// The signed-in person's personal tokens, oldest first, revoked and expired ones included.
/// Metadata only: the secret and its hash are not part of any view the caller is meant to
/// show.
///
/// # Errors
///
/// [`PersonalTokenError::NotAUser`] or [`PersonalTokenError::Store`].
pub async fn list_personal_tokens(valence: &Valence) -> Result<Vec<TokenRow>, PersonalTokenError> {
    let owner = caller_bare(valence)?;
    let mut rows = list_rows(valence, &owner).await?;
    rows.sort_by_key(|r| *r.created_at());
    Ok(rows)
}

/// Revoke one of the signed-in person's personal tokens. Revoking an already revoked token
/// succeeds and keeps the first revoke time.
///
/// # Errors
///
/// [`PersonalTokenError::NotAUser`]; [`PersonalTokenError::NotFound`] when the token is not
/// one of the caller's; [`PersonalTokenError::Forbidden`]; [`PersonalTokenError::Store`].
pub async fn revoke_personal_token(
    valence: &Valence,
    token_id: &str,
) -> Result<TokenRow, PersonalTokenError> {
    let result = revoke_inner(valence, token_id).await;
    log("token_revoke", result.as_ref().map(|_| ()));
    result
}

async fn revoke_inner(valence: &Valence, token_id: &str) -> Result<TokenRow, PersonalTokenError> {
    let owner = caller_bare(valence)?;
    let row = list_rows(valence, &owner)
        .await?
        .into_iter()
        .find(|r| r.id().is_some_and(|rid| rid.id() == token_id))
        .ok_or(PersonalTokenError::NotFound)?;
    if row.revoked_at().is_some() {
        return Ok(row);
    }
    row.get_mutable(
        valence,
        valence::use_!(r"When you **revoke a personal token**, we **record the revoke time** so the token stops working at once. You see it marked revoked under Your tokens."),
    )
    .set_revoked_at(Utc::now())
    .map_err(|_| PersonalTokenError::Store)?
    .commit()
    .await
    .map_err(|e| write_error(&e))
}

#[cfg(all(test, feature = "totp"))]
mod tests {
    use super::*;
    use crate::step_up::StepUpError;

    #[test]
    fn step_up_failures_map_happy() {
        assert!(matches!(
            PersonalTokenError::from_step_up(&StepUpError::AuthRequired),
            PersonalTokenError::NotAUser
        ));
        assert!(matches!(
            PersonalTokenError::from_step_up(&StepUpError::Store),
            PersonalTokenError::Store
        ));
        for (e, class) in [
            (StepUpError::StepUpRequired, "step_up_required"),
            (StepUpError::StepUpExpired, "step_up_expired"),
            (
                StepUpError::TotpEnrollmentRequired,
                "totp_enrollment_required",
            ),
        ] {
            assert!(matches!(
                PersonalTokenError::from_step_up(&e),
                PersonalTokenError::StepUp { reason_class } if reason_class == class
            ));
        }
    }

    #[tokio::test]
    async fn create_without_a_session_is_refused_sad() {
        let base = valence::Valence::builder()
            .with_actor(Actor::User {
                user_id: "alice".into(),
            })
            .build();
        let Ok(alice) = base else {
            // No in-memory store in this build; the mapping test above covers the refusal.
            return;
        };
        let scopes = [ApiScope::parse("magnon:read").expect("scope")];
        let err = create_personal_token(
            &alice,
            NewPersonalToken {
                label: "cli",
                scopes: &scopes,
                lifetime: TokenLifetime::Days30,
            },
        )
        .await
        .expect_err("no session, no step-up");
        assert!(matches!(
            err,
            PersonalTokenError::NotAUser | PersonalTokenError::StepUp { .. }
        ));
    }
}
