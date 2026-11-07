//! Create, list, and revoke personal access tokens for a service user.

use chrono::{DateTime, Duration, Utc};
use lepton_host_adapter::generated::ServiceUserToken as TokenRow;
use lepton_identity::service_users::{ServiceUserId, ServiceUserToken};
use tokio::sync::Mutex;
use valence::{Actor, Model, RecordId, Valence};

use super::activity::{record_service_user_token_activity, ServiceUserTokenEvent};
use super::api::get_service_user;
use super::ServiceUserError;

/// Live (unrevoked, unexpired) tokens one service user can have at once.
pub const MAX_TOKENS_PER_SERVICE_USER: usize = 10;

/// Longest a token can live from the moment it is created, in days.
pub const MAX_TOKEN_LIFETIME_DAYS: i64 = 365;

const MAX_LABEL: usize = 80;

/// Serializes the count-then-insert in [`create_service_user_token`] so concurrent creates
/// cannot both pass the limit.
static CREATE_LOCK: Mutex<()> = Mutex::const_new(());

/// Settings for a new token. See [`create_service_user_token`].
#[derive(Debug, Clone, Copy)]
pub struct NewServiceUserToken<'a> {
    /// What the token is for, such as `ci` (1-80 characters).
    pub label: &'a str,
    /// When the token stops working. Must be in the future and within
    /// [`MAX_TOKEN_LIFETIME_DAYS`] of now.
    pub expires_at: DateTime<Utc>,
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

fn is_live(row: &TokenRow, now: DateTime<Utc>) -> bool {
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

/// Create an access token for a service user the caller owns.
///
/// Pass the request Valence (`ctx.valence()`). Callers who can only see a service user
/// (manage-any) cannot create tokens for it.
///
/// # Errors
///
/// - [`ServiceUserError::NotAUser`] when the caller is not a signed-in user.
/// - [`ServiceUserError::NotFound`] when the service user does not exist or the caller cannot
///   see it.
/// - [`ServiceUserError::InvalidProfile`] for a bad label (`label`) or expiry (`expires_at`).
/// - [`ServiceUserError::QuotaReached`] at [`MAX_TOKENS_PER_SERVICE_USER`] live tokens.
/// - [`ServiceUserError::Forbidden`] when the caller sees the service user but does not own it.
/// - [`ServiceUserError::Store`] on a storage failure.
pub async fn create_service_user_token(
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
    let now = Utc::now();
    if input.expires_at <= now || input.expires_at > now + Duration::days(MAX_TOKEN_LIFETIME_DAYS) {
        return Err(ServiceUserError::InvalidProfile {
            field: "expires_at",
        });
    }
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

    let token = ServiceUserToken::generate();
    let row = TokenRow::new(
        Some(RecordId::new("user", &owner)),
        Some(RecordId::new("service_user_account", id.as_str())),
        label.to_string(),
        token.hash(),
        input.expires_at,
        None,
        now,
    )
    .map_err(|_| ServiceUserError::Store)?;
    let row = TokenRow::upsert(
        token.id(),
        row,
        valence,
        valence::use_!(r"When you **create an access token for a service user**, we **save its label, expiry, and a one-way hash of the secret**, and **show you the token once**. You see the label and expiry on the service user's page; the secret itself is never stored."),
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
        valence::use_!(r"On a **service user's page**, we **list its access tokens** with their label, expiry, and whether they are revoked, so the owner can see and revoke them. The secret is never included."),
    )
    .await
    .map_err(|_| ServiceUserError::Store)
}

/// Tokens of a service user the caller may see, oldest first. Metadata only: the secret and
/// its hash are not part of any view the caller is meant to show.
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
