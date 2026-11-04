//! Per-service-user history: lifecycle changes and token events.

use chrono::Utc;
use lepton_host_adapter::generated::{ServiceUserActivity, ServiceUserActivityKind};
use lepton_identity::service_users::ServiceUserId;
use valence::{Model, RecordId, Valence};

use super::api::{caller_user, load, owner_id};
use super::ServiceUserError;

/// Entries [`list_service_user_activity`] returns when the caller passes no larger limit.
pub const DEFAULT_ACTIVITY_LIMIT: usize = 20;
/// Most entries [`list_service_user_activity`] ever returns.
pub const MAX_ACTIVITY_LIMIT: usize = 100;
const MAX_DETAIL: usize = 120;

/// A token event the host reports with [`record_service_user_token_activity`].
///
/// Lepton does not mint tokens; the host that does reports each one here so the history
/// shows it next to the lifecycle changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceUserTokenEvent {
    /// A token was minted.
    Created,
    /// A token was revoked.
    Revoked,
    /// A token was replaced by a new one.
    Rotated,
}

impl ServiceUserTokenEvent {
    const fn kind(self) -> ServiceUserActivityKind {
        match self {
            Self::Created => ServiceUserActivityKind::TokenCreated,
            Self::Revoked => ServiceUserActivityKind::TokenRevoked,
            Self::Rotated => ServiceUserActivityKind::TokenRotated,
        }
    }
}

/// Append one history row. `owner` and the caller come from the loaded service user and the
/// request Valence.
async fn append(
    valence: &Valence,
    id: &ServiceUserId,
    owner: Option<String>,
    kind: ServiceUserActivityKind,
    detail: Option<String>,
) -> Result<(), ServiceUserError> {
    let actor = caller_user(valence)?;
    let now = Utc::now();
    let row = ServiceUserActivity::new(
        RecordId::new("service_user_account", id.as_str()),
        owner.as_deref().map(|o| RecordId::new("user", o)),
        kind,
        Some(RecordId::new("user", &actor)),
        detail,
        now,
    )
    .map_err(|_| ServiceUserError::Store)?;
    // Time-ordered id: the stored timestamp has second precision, so the id keeps order.
    let row_id = format!(
        "{:020}-{}",
        now.timestamp_micros(),
        ServiceUserId::new_v4().as_str()
    );
    ServiceUserActivity::upsert(
        &row_id,
        row,
        valence,
        valence::use_!(r"When a **service user changes** (created, edited, suspended, resumed) or one of its **tokens is created, revoked, or rotated**, we **save one history entry** with what happened, when, and who did it. The owner sees it in the service user's recent activity; entries never show token text."),
    )
    .await
    .map(|_| ())
    .map_err(|_| ServiceUserError::Store)
}

/// Best-effort lifecycle entry: a failed write is logged and never fails the change.
pub(super) async fn record_lifecycle(
    valence: &Valence,
    service_user: &lepton_host_adapter::generated::ServiceUserAccount,
    id: &ServiceUserId,
    kind: ServiceUserActivityKind,
) {
    if let Err(e) = append(valence, id, owner_id(service_user), kind, None).await {
        tracing::warn!(
            target: "lepton.service_user",
            reason_class = e.reason_class(),
            "service user history entry not saved"
        );
    }
}

/// Record a token event for a service user.
///
/// Pass the request Valence. The caller must be able to see the service user: its owner, or
/// a user the host's gate lets manage any service user. `label` is a short name such as the
/// token's label (at most 120 characters); never pass token text.
///
/// # Errors
///
/// [`ServiceUserError::NotAUser`], [`ServiceUserError::NotFound`] when the service user does
/// not exist or the caller may not see it, [`ServiceUserError::InvalidProfile`] when `label`
/// is too long, or [`ServiceUserError::Store`].
pub async fn record_service_user_token_activity(
    valence: &Valence,
    id: &ServiceUserId,
    event: ServiceUserTokenEvent,
    label: Option<&str>,
) -> Result<(), ServiceUserError> {
    caller_user(valence)?;
    let detail = match label.map(str::trim).filter(|l| !l.is_empty()) {
        Some(l) if l.chars().count() > MAX_DETAIL => {
            return Err(ServiceUserError::InvalidProfile { field: "label" });
        }
        Some(l) => Some(l.to_string()),
        None => None,
    };
    let service_user = load(valence, id).await?;
    append(valence, id, owner_id(&service_user), event.kind(), detail).await
}

/// Recent history of one service user, newest first.
///
/// `limit` is capped at [`MAX_ACTIVITY_LIMIT`]; `None` means [`DEFAULT_ACTIVITY_LIMIT`].
/// Anyone who cannot see the service user gets [`ServiceUserError::NotFound`].
///
/// # Errors
///
/// [`ServiceUserError::NotAUser`], [`ServiceUserError::NotFound`], or
/// [`ServiceUserError::Store`].
pub async fn list_service_user_activity(
    valence: &Valence,
    id: &ServiceUserId,
    limit: Option<usize>,
) -> Result<Vec<ServiceUserActivity>, ServiceUserError> {
    caller_user(valence)?;
    load(valence, id).await?;
    // The generated query's `order_by_id` and `limit` are not honored by the backend today
    // (rows come back in storage order), so sort and cut here. Ids start with the write time.
    let mut rows = ServiceUserActivity::get_from_service_user_id(
        id.as_str(),
        valence,
        valence::use_!(r"On a **service user's page**, we **list its recent activity**: changes to the service user and its tokens, with when each happened and who made it. Only its owner, or a platform administrator, can see it."),
    )
    .await
    .map_err(|_| ServiceUserError::Store)?;
    rows.sort_by(|a, b| b.id().map(RecordId::id).cmp(&a.id().map(RecordId::id)));
    rows.truncate(
        limit
            .unwrap_or(DEFAULT_ACTIVITY_LIMIT)
            .min(MAX_ACTIVITY_LIMIT),
    );
    Ok(rows)
}
