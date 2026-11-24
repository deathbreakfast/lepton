//! Create, list, and revoke access tokens for a service user.

use chrono::Utc;
use lepton_host_adapter::generated::{ServiceUserToken as TokenRow, ServiceUserTokenKind};
use lepton_identity::service_users::ServiceUserId;
use lepton_identity::tokens::{scopes_to_json, ApiScope, LeptonToken, TokenLifetime};
use tokio::sync::Mutex;
use valence::{Actor, Model, RecordId, Valence};

use super::activity::{record_service_user_token_activity, ServiceUserTokenEvent};
use super::api::get_service_user;
use super::ServiceUserError;
use crate::scopes::{check_scopes, ScopeError};

/// Live (unrevoked, unexpired) tokens one service user can have at once.
pub const MAX_TOKENS_PER_SERVICE_USER: usize = 10;

const MAX_LABEL: usize = 80;

const MAX_DEVICE_ID: usize = 128;

/// Serializes the count-then-insert in [`create_service_user_token`] so concurrent creates
/// cannot both pass the limit.
static CREATE_LOCK: Mutex<()> = Mutex::const_new(());

/// Settings for a new token. See [`create_service_user_token`].
#[derive(Debug, Clone)]
pub struct NewServiceUserToken<'a> {
    /// What the token is for, such as `ci` (1-80 characters).
    pub label: &'a str,
    /// The APIs the token may call. At least one, each registered by the host
    /// ([`register_api_scopes`](crate::scopes::register_api_scopes)).
    pub scopes: &'a [ApiScope],
    /// How long the token lasts: 30 or 90 days.
    pub lifetime: TokenLifetime,
    /// Made by hand on the service user's page, or issued to a device.
    pub kind: ServiceUserTokenKind,
    /// The device a [`ServiceUserTokenKind::Device`] token is issued to, when there is a device
    /// record (up to 128 characters). Must be `None` for a hand-made token.
    pub device_id: Option<&'a str>,
}

/// A token just created: the stored row plus the one-time plaintext.
#[derive(Clone)]
pub struct CreatedServiceUserToken {
    /// The stored row. It holds the hash, never the plaintext.
    pub row: TokenRow,
    /// The full bearer token. Show it once; it cannot be recovered.
    pub token: String,
}

impl std::fmt::Debug for CreatedServiceUserToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedServiceUserToken")
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

fn caller_bare(valence: &Valence) -> Result<String, ServiceUserError> {
    match valence.actor() {
        Actor::User { user_id } => Ok(user_id
            .split_once(':')
            .map_or(user_id.as_str(), |(_, id)| id)
            .to_string()),
        _ => Err(ServiceUserError::NotAUser),
    }
}

fn is_live(row: &TokenRow, now: chrono::DateTime<Utc>) -> bool {
    row.revoked_at().is_none() && *row.expires_at() > now
}

const fn write_error(e: &valence::Error) -> ServiceUserError {
    match e {
        valence::Error::Privacy(_) => ServiceUserError::Forbidden,
        _ => ServiceUserError::Store,
    }
}

fn log(op: &'static str, result: Result<(), &ServiceUserError>, service_user: &ServiceUserId) {
    match result {
        Ok(()) => tracing::info!(
            target: "lepton.service_user",
            op,
            service_user_id = service_user.as_str(),
            "service user token"
        ),
        Err(e) => tracing::debug!(
            target: "lepton.service_user",
            op,
            reason_class = e.reason_class(),
            "service user token refused"
        ),
    }
}

/// Create an access token for a service user the caller owns, after a recent step-up.
///
/// Call it from a server function with the request Valence (`ctx.valence()`). It first
/// checks the session's step-up window
/// ([`require_recent_verification`](crate::step_up::require_recent_verification)); open one
/// with lepton-auth-ui's step-up flow before calling. Callers who can only see a service user
/// (manage-any) cannot create tokens for it.
///
/// # Errors
///
/// - [`ServiceUserError::StepUp`] when the session has no recent step-up.
/// - [`ServiceUserError::NotAUser`] when the caller is not a signed-in user.
/// - [`ServiceUserError::NotFound`] when the service user does not exist or the caller cannot
///   see it.
/// - [`ServiceUserError::InvalidProfile`] for a bad `label`, `scopes`, or `device_id`.
/// - [`ServiceUserError::ScopesNotRegistered`] when the host registered no scopes.
/// - [`ServiceUserError::QuotaReached`] at [`MAX_TOKENS_PER_SERVICE_USER`] live tokens.
/// - [`ServiceUserError::Forbidden`] when the caller sees the service user but does not own it.
/// - [`ServiceUserError::Store`] on a storage failure.
#[cfg(feature = "totp")]
pub async fn create_service_user_token(
    valence: &Valence,
    id: &ServiceUserId,
    input: NewServiceUserToken<'_>,
) -> Result<CreatedServiceUserToken, ServiceUserError> {
    use crate::step_up::{require_recent_verification, StepUpScope};

    if let Err(e) = require_recent_verification(StepUpScope::SensitiveMutation).await {
        let err = ServiceUserError::from_step_up(&e);
        log("token_create", Err(&err), id);
        return Err(err);
    }
    mint_service_user_token(valence, id, input).await
}

/// **Test only.** [`create_service_user_token`] without the step-up check, for suites that
/// run without an HTTP session.
///
/// # Errors
///
/// As [`create_service_user_token`], except [`ServiceUserError::StepUp`].
#[cfg(feature = "test-utils")]
pub async fn create_service_user_token_without_step_up(
    valence: &Valence,
    id: &ServiceUserId,
    input: NewServiceUserToken<'_>,
) -> Result<CreatedServiceUserToken, ServiceUserError> {
    mint_service_user_token(valence, id, input).await
}

/// Mint a token once the caller has passed step-up.
#[cfg_attr(not(any(feature = "totp", feature = "test-utils")), allow(dead_code))]
async fn mint_service_user_token(
    valence: &Valence,
    id: &ServiceUserId,
    input: NewServiceUserToken<'_>,
) -> Result<CreatedServiceUserToken, ServiceUserError> {
    let result = create_inner(valence, id, input).await;
    log("token_create", result.as_ref().map(|_| ()), id);
    if let Ok(created) = &result {
        record_event(
            valence,
            id,
            ServiceUserTokenEvent::Created,
            created.row.label(),
        )
        .await;
    }
    result
}

fn checked_scopes(requested: &[ApiScope]) -> Result<Vec<ApiScope>, ServiceUserError> {
    check_scopes(requested).map_err(|e| match e {
        ScopeError::NotRegistered => ServiceUserError::ScopesNotRegistered,
        ScopeError::Empty | ScopeError::Unknown(_) => {
            ServiceUserError::InvalidProfile { field: "scopes" }
        }
    })
}

fn checked_device_id<'a>(
    kind: &ServiceUserTokenKind,
    device_id: Option<&'a str>,
) -> Result<Option<&'a str>, ServiceUserError> {
    let bad = ServiceUserError::InvalidProfile { field: "device_id" };
    match (kind, device_id.map(str::trim)) {
        (_, None) => Ok(None),
        (ServiceUserTokenKind::Manual, Some(_)) => Err(bad),
        (ServiceUserTokenKind::Device, Some(d)) if d.is_empty() || d.len() > MAX_DEVICE_ID => {
            Err(bad)
        }
        (ServiceUserTokenKind::Device, Some(d)) => Ok(Some(d)),
    }
}

async fn create_inner(
    valence: &Valence,
    id: &ServiceUserId,
    input: NewServiceUserToken<'_>,
) -> Result<CreatedServiceUserToken, ServiceUserError> {
    let owner = caller_bare(valence)?;
    let label = input.label.trim();
    if label.is_empty() || label.chars().count() > MAX_LABEL {
        return Err(ServiceUserError::InvalidProfile { field: "label" });
    }
    let scopes = checked_scopes(input.scopes)?;
    let device_id = checked_device_id(&input.kind, input.device_id)?;
    let now = Utc::now();
    let service_user = get_service_user(valence, id).await?;

    let _guard = CREATE_LOCK.lock().await;
    let live = list_rows(valence, &service_user)
        .await?
        .iter()
        .filter(|r| is_live(r, now))
        .count();
    if live >= MAX_TOKENS_PER_SERVICE_USER {
        return Err(ServiceUserError::QuotaReached {
            limit: MAX_TOKENS_PER_SERVICE_USER,
        });
    }

    let token = LeptonToken::generate();
    let row = TokenRow::new(
        Some(RecordId::new("user", &owner)),
        Some(RecordId::new("service_user_account", id.as_str())),
        label.to_string(),
        token.hash(),
        Some(scopes_to_json(&scopes)),
        Some(input.kind),
        device_id.map(str::to_string),
        input.lifetime.expires_at(now),
        None,
        None,
        now,
    )
    .map_err(|_| ServiceUserError::Store)?;
    let row = TokenRow::upsert(
        token.id(),
        row,
        valence,
        valence::use_!(r"When you **create an access token for a service user**, we **save its label, the APIs it may call, its expiry, and a one-way hash of the secret**, and **show you the token once**. You see the label, APIs and expiry on the service user's page; the secret itself is never stored."),
    )
    .await
    .map_err(|e| write_error(&e))?;
    Ok(CreatedServiceUserToken {
        row,
        token: token.expose(),
    })
}

/// Add a token event to the service user's history. Best-effort; never fails the call.
async fn record_event(
    valence: &Valence,
    id: &ServiceUserId,
    event: ServiceUserTokenEvent,
    label: &str,
) {
    if let Err(e) = record_service_user_token_activity(valence, id, event, Some(label)).await {
        tracing::warn!(
            target: "lepton.service_user",
            reason_class = e.reason_class(),
            "service user history entry not saved"
        );
    }
}

async fn list_rows(
    valence: &Valence,
    service_user: &lepton_host_adapter::generated::ServiceUserAccount,
) -> Result<Vec<TokenRow>, ServiceUserError> {
    TokenRow::get_from_service_user(
        service_user,
        valence,
        valence::use_!(r"On a **service user's page**, we **list its access tokens** with their label, the APIs they may call, expiry, last use, and whether they are revoked, so the owner can see and revoke them. The secret is never included."),
    )
    .await
    .map_err(|_| ServiceUserError::Store)
}

/// Tokens of a service user the caller may see, oldest first, with their scopes, kind, last
/// use and status. Metadata only: the secret and its hash are not part of any view the caller
/// is meant to show.
///
/// # Errors
///
/// [`ServiceUserError::NotAUser`], [`ServiceUserError::NotFound`], or
/// [`ServiceUserError::Store`].
pub async fn list_service_user_tokens(
    valence: &Valence,
    id: &ServiceUserId,
) -> Result<Vec<TokenRow>, ServiceUserError> {
    caller_bare(valence)?;
    let service_user = get_service_user(valence, id).await?;
    let mut rows = list_rows(valence, &service_user).await?;
    rows.sort_by_key(|r| *r.created_at());
    Ok(rows)
}

/// Revoke one token of a service user. Revoking an already revoked token succeeds and keeps
/// the first revoke time. The owner and manage-any users may revoke.
///
/// # Errors
///
/// [`ServiceUserError::NotAUser`]; [`ServiceUserError::NotFound`] when the service user or
/// token is unknown to the caller; [`ServiceUserError::Forbidden`]; [`ServiceUserError::Store`].
pub async fn revoke_service_user_token(
    valence: &Valence,
    id: &ServiceUserId,
    token_id: &str,
) -> Result<TokenRow, ServiceUserError> {
    let result = revoke_inner(valence, id, token_id).await;
    log("token_revoke", result.as_ref().map(|_| ()), id);
    if let Ok((row, true)) = &result {
        record_event(valence, id, ServiceUserTokenEvent::Revoked, row.label()).await;
    }
    result.map(|(row, _)| row)
}

/// Revoke and report whether this call changed the token (`false` when already revoked).
async fn revoke_inner(
    valence: &Valence,
    id: &ServiceUserId,
    token_id: &str,
) -> Result<(TokenRow, bool), ServiceUserError> {
    caller_bare(valence)?;
    let service_user = get_service_user(valence, id).await?;
    let row = list_rows(valence, &service_user)
        .await?
        .into_iter()
        .find(|r| r.id().is_some_and(|rid| rid.id() == token_id))
        .ok_or(ServiceUserError::NotFound)?;
    if row.revoked_at().is_some() {
        return Ok((row, false));
    }
    row.get_mutable(
        valence,
        valence::use_!(r"When the owner **revokes an access token**, we **record the revoke time** so the token stops working at once. The owner sees it marked revoked on the service user's page."),
    )
    .set_revoked_at(Utc::now())
    .map_err(|_| ServiceUserError::Store)?
    .commit()
    .await
    .map(|row| (row, true))
    .map_err(|e| write_error(&e))
}
