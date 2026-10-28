//! Create, read, edit, suspend, resume, and delete service users.

use chrono::Utc;
use lepton_host_adapter::generated::{
    ServiceUserAccount, ServiceUserAccountOwnerKind, ServiceUserAccountStatus,
};
use lepton_identity::config::service_users_per_owner;
use lepton_identity::service_users::{
    installed_service_user_gate, ServiceUserHandle, ServiceUserId,
};
use tokio::sync::Mutex;
use valence::ownership::OwnershipService;
use valence::{Actor, Model, RecordId, Valence};

use super::handle_lookup::{first_free, handle_key_taken};
use super::ServiceUserError;
use crate::events::{publish_service_user_lifecycle, ServiceUserLifecycleEvent};

const MAX_DISPLAY_NAME: usize = 80;
const MAX_DESCRIPTION: usize = 500;

/// Service users one owner can have at once when the host sets no limit.
///
/// Hosts change the limit at boot with
/// [`install_service_users_per_owner`](lepton_identity::config::install_service_users_per_owner).
/// Active and suspended service users count; deleted ones (including deletions
/// still running) do not. Super users are held to the same limit for the service
/// users they own.
pub const MAX_SERVICE_USERS_PER_OWNER: usize =
    lepton_identity::config::DEFAULT_SERVICE_USERS_PER_OWNER;

/// Serializes the check-then-insert in [`create_service_user`] so concurrent
/// creates cannot both pass the per-owner quota or claim the same handle.
static CREATE_LOCK: Mutex<()> = Mutex::const_new(());

/// Profile for a new service user. See [`create_service_user`].
#[derive(Debug, Clone, Copy)]
pub struct NewServiceUser<'a> {
    /// Requested handle, for example `spectra-agent`.
    pub handle: &'a str,
    /// Name shown next to the service user's actions (1–80 characters).
    pub display_name: &'a str,
    /// What the service user is for (at most 500 characters).
    pub description: Option<&'a str>,
}

/// Profile edits for [`update_service_user`]. `None` leaves a field as it is.
#[derive(Debug, Clone, Copy, Default)]
pub struct ServiceUserProfileUpdate<'a> {
    /// New display name.
    pub display_name: Option<&'a str>,
    /// `Some(None)` clears the description; `Some(Some(text))` replaces it.
    pub description: Option<Option<&'a str>>,
}

#[derive(Debug, Clone, Copy)]
enum Op {
    Create,
    Update,
    Suspend,
    Resume,
    Delete,
}

impl Op {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Suspend => "suspend",
            Self::Resume => "resume",
            Self::Delete => "delete",
        }
    }
}

/// Log and count the outcome once, at the service boundary.
fn record<T>(
    op: Op,
    result: Result<T, ServiceUserError>,
    service_user_id: Option<&ServiceUserId>,
) -> Result<T, ServiceUserError> {
    match &result {
        Ok(_) => tracing::info!(
            target: "lepton.service_user",
            op = op.as_str(),
            service_user_id = service_user_id.map(ServiceUserId::as_str),
            "service user lifecycle"
        ),
        Err(
            e @ (ServiceUserError::Store
            | ServiceUserError::Gate(_)
            | ServiceUserError::Misconfigured),
        ) => tracing::warn!(
            target: "lepton.service_user",
            op = op.as_str(),
            reason_class = e.reason_class(),
            "service user lifecycle failed"
        ),
        Err(e) => tracing::debug!(
            target: "lepton.service_user",
            op = op.as_str(),
            reason_class = e.reason_class(),
            "service user lifecycle refused"
        ),
    }
    #[cfg(feature = "spectra")]
    crate::spectra_emit::service_user(
        match op {
            Op::Create => crate::spectra_emit::ServiceUserOperation::Create,
            Op::Update => crate::spectra_emit::ServiceUserOperation::Update,
            Op::Suspend => crate::spectra_emit::ServiceUserOperation::Suspend,
            Op::Resume => crate::spectra_emit::ServiceUserOperation::Resume,
            Op::Delete => crate::spectra_emit::ServiceUserOperation::Delete,
        },
        result
            .as_ref()
            .err()
            .map_or("none", ServiceUserError::reason_class),
    );
    result
}

/// The calling user's bare id, or [`ServiceUserError::NotAUser`].
fn caller_user(valence: &Valence) -> Result<String, ServiceUserError> {
    match valence.actor() {
        Actor::User { user_id } => {
            let bare = user_id
                .split_once(':')
                .map_or(user_id.as_str(), |(_, id)| id);
            Ok(bare.to_string())
        }
        _ => Err(ServiceUserError::NotAUser),
    }
}

/// Bare user id of the service user's owner.
fn owner_id(service_user: &ServiceUserAccount) -> Option<String> {
    let owner = service_user.user()?;
    Some(valence::extract_id_from_record(owner).unwrap_or_else(|_| owner.id().to_string()))
}

/// Publish one lifecycle event for a saved change. Best-effort; never fails the call.
async fn publish(
    service_user: &ServiceUserAccount,
    id: &ServiceUserId,
    event: ServiceUserLifecycleEvent,
) {
    if let Some(owner) = owner_id(service_user) {
        publish_service_user_lifecycle(owner, id, event).await;
    }
}

/// Map a Valence write failure: a privacy refusal is [`ServiceUserError::Forbidden`].
const fn write_error(e: &valence::Error) -> ServiceUserError {
    match e {
        valence::Error::Privacy(_) => ServiceUserError::Forbidden,
        _ => ServiceUserError::Store,
    }
}

fn check_display_name(name: &str) -> Result<String, ServiceUserError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_DISPLAY_NAME {
        return Err(ServiceUserError::InvalidProfile {
            field: "display_name",
        });
    }
    Ok(name.to_string())
}

fn check_description(text: Option<&str>) -> Result<Option<String>, ServiceUserError> {
    let Some(text) = text.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    if text.chars().count() > MAX_DESCRIPTION {
        return Err(ServiceUserError::InvalidProfile {
            field: "description",
        });
    }
    Ok(Some(text.to_string()))
}

/// The status after moving to `to`, or [`ServiceUserError::InvalidTransition`] when the
/// service user is already there.
fn transition(
    from: &ServiceUserAccountStatus,
    to: ServiceUserAccountStatus,
) -> Result<ServiceUserAccountStatus, ServiceUserError> {
    if *from == to {
        Err(ServiceUserError::InvalidTransition { from: to })
    } else {
        Ok(to)
    }
}

/// Ask the installed gate whether the caller may create service users.
async fn require_create_permission(valence: &Valence) -> Result<(), ServiceUserError> {
    let gate = installed_service_user_gate().ok_or(ServiceUserError::GateNotInstalled)?;
    if gate
        .may_create_service_user(valence)
        .await
        .map_err(ServiceUserError::Gate)?
    {
        Ok(())
    } else {
        Err(ServiceUserError::CreateNotPermitted)
    }
}

/// Create a service user owned by the calling user.
///
/// The service user starts `active` with a fresh [`ServiceUserId`]. Pass the request Valence
/// (`ctx.valence()`), never a System handle: the owner is taken from its actor.
///
/// # Errors
///
/// - [`ServiceUserError::NotAUser`] when the caller is not a signed-in user.
/// - [`ServiceUserError::InvalidHandle`] / [`ServiceUserError::InvalidProfile`] for bad input.
/// - [`ServiceUserError::GateNotInstalled`], [`ServiceUserError::CreateNotPermitted`], or
///   [`ServiceUserError::Gate`] when the host's gate refuses or fails.
/// - [`ServiceUserError::QuotaReached`] when the caller already owns as many service users
///   as the host allows ([`service_users_per_owner`], default
///   [`MAX_SERVICE_USERS_PER_OWNER`]).
/// - [`ServiceUserError::HandleTaken`] with a free suggestion when another service user uses the
///   handle.
/// - [`ServiceUserError::Store`] on a storage failure.
pub async fn create_service_user(
    valence: &Valence,
    input: NewServiceUser<'_>,
) -> Result<ServiceUserAccount, ServiceUserError> {
    let result = create_service_user_inner(valence, input).await;
    let id = result
        .as_ref()
        .ok()
        .and_then(|b| b.id())
        .and_then(|rid| ServiceUserId::parse(rid.id()).ok());
    let result = record(Op::Create, result, id.as_ref());
    if let (Ok(service_user), Some(id)) = (&result, &id) {
        publish(service_user, id, ServiceUserLifecycleEvent::Created).await;
    }
    result
}

async fn create_service_user_inner(
    valence: &Valence,
    input: NewServiceUser<'_>,
) -> Result<ServiceUserAccount, ServiceUserError> {
    let owner = caller_user(valence)?;
    let handle = ServiceUserHandle::parse(input.handle)?;
    let display_name = check_display_name(input.display_name)?;
    let description = check_description(input.description)?;
    require_create_permission(valence).await?;

    // Serialize the quota count, the handle probe, and the insert. Each is a
    // check-then-insert: without this lock two concurrent creates for the same
    // owner could both read a count below the limit, or both find a handle free,
    // and then both insert. Service user creation is rare and quota-capped, so a
    // process-wide lock is cheap. The `unique: true` constraint on `handle_key`
    // backs this up across processes (mapped below).
    let _create_guard = CREATE_LOCK.lock().await;

    let limit = service_users_per_owner();
    if list_my_service_users(valence).await?.len() >= limit {
        return Err(ServiceUserError::QuotaReached { limit });
    }

    if handle_key_taken(valence, &handle.key()).await? {
        let suggestion = first_free(valence, handle).await.ok();
        return Err(ServiceUserError::HandleTaken { suggestion });
    }

    let id = ServiceUserId::new_v4();
    let owner_ref = RecordId::new("user", &owner);
    let now = Utc::now();
    let row = ServiceUserAccount::new(
        Some(owner_ref.clone()),
        ServiceUserAccountOwnerKind::User,
        Some(owner_ref),
        handle.as_str().to_string(),
        handle.key(),
        display_name,
        description,
        ServiceUserAccountStatus::Active,
        None,
        now,
        now,
    )
    .map_err(|_| ServiceUserError::Store)?;
    ServiceUserAccount::upsert(
        id.as_str(),
        row,
        valence,
        valence::use_!(r"When you **create a service user**, we **save its profile**: the handle and display name you chose, the description, and that **you own it**. You see this on your service users page, and the platform uses the owner link to decide who may manage the service user."),
    )
    .await
    .map_err(|e| {
        // The owner slipped past the in-process probe (another host, or a race the
        // lock above cannot see): the unique `handle_key` index rejects the insert.
        if e.as_unique_violation().is_some() {
            ServiceUserError::HandleTaken { suggestion: None }
        } else if matches!(e, valence::Error::Privacy(_)) {
            ServiceUserError::CreateNotPermitted
        } else {
            ServiceUserError::Store
        }
    })
}

/// Suggest a free handle built from free text such as a display name.
///
/// `"Spectra agent"` becomes `spectra-agent`, or `spectra-agent-2` when that is taken.
///
/// # Errors
///
/// [`ServiceUserError::NotAUser`], the gate errors from [`create_service_user`],
/// [`ServiceUserError::InvalidHandle`] when nothing usable is left after normalizing,
/// [`ServiceUserError::HandleTaken`] when every candidate is taken, or
/// [`ServiceUserError::Store`].
pub async fn suggest_service_user_handle(
    valence: &Valence,
    wanted: &str,
) -> Result<ServiceUserHandle, ServiceUserError> {
    caller_user(valence)?;
    require_create_permission(valence).await?;
    let handle = ServiceUserHandle::normalize(wanted)?;
    first_free(valence, handle).await
}

/// Load one service user the caller may see: its own, or any service user when the gate grants
/// manage-any.
///
/// # Errors
///
/// [`ServiceUserError::NotAUser`]; [`ServiceUserError::NotFound`] when the service user does
/// not exist or the caller may not see it; [`ServiceUserError::Store`].
pub async fn get_service_user(
    valence: &Valence,
    id: &ServiceUserId,
) -> Result<ServiceUserAccount, ServiceUserError> {
    caller_user(valence)?;
    load(valence, id).await
}

async fn load(
    valence: &Valence,
    id: &ServiceUserId,
) -> Result<ServiceUserAccount, ServiceUserError> {
    ServiceUserAccount::get(
        id.as_str(),
        valence,
        valence::use_!(r"On the **service user** pages, we **load one service user's profile and status** so its owner (or a platform administrator) can see it and act on it. Anyone else gets **not found**, as if the service user did not exist."),
    )
    .await
    .map_err(|e| match e {
        // A deleted service user stays invisible while its deletion run finishes.
        valence::Error::PendingDeletion(_) => ServiceUserError::NotFound,
        _ => ServiceUserError::Store,
    })?
    .ok_or(ServiceUserError::NotFound)
}

/// The calling user's service users, oldest first (ties by handle).
///
/// # Errors
///
/// [`ServiceUserError::NotAUser`] or [`ServiceUserError::Store`].
pub async fn list_my_service_users(
    valence: &Valence,
) -> Result<Vec<ServiceUserAccount>, ServiceUserError> {
    let owner = caller_user(valence)?;
    let service_users = ServiceUserAccount::get_from_user_id(
        &owner,
        valence,
        valence::use_!(r"On **your service users** page, we **list the service users you own** with their handle, display name, and status, and **show them to you**. Other people's service users are never included."),
    )
    .await
    .map_err(|_| ServiceUserError::Store)?;
    visible_oldest_first(valence, service_users).await
}

/// Every service user, whoever owns it, oldest first (ties by handle). Only callers the
/// host's [`ServiceUserGate`](lepton_identity::service_users::ServiceUserGate) grants
/// manage-any may list them.
///
/// # Errors
///
/// [`ServiceUserError::NotAUser`]; [`ServiceUserError::Forbidden`] when the gate does not
/// grant manage-any; [`ServiceUserError::GateNotInstalled`] or [`ServiceUserError::Gate`]
/// when there is no gate or it fails; [`ServiceUserError::Store`].
pub async fn list_all_service_users(
    valence: &Valence,
) -> Result<Vec<ServiceUserAccount>, ServiceUserError> {
    caller_user(valence)?;
    let gate = installed_service_user_gate().ok_or(ServiceUserError::GateNotInstalled)?;
    if !gate
        .may_manage_any_service_user(valence)
        .await
        .map_err(ServiceUserError::Gate)?
    {
        return Err(ServiceUserError::Forbidden);
    }
    let service_users = ServiceUserAccount::query(
        valence,
        valence::use_!(r"On the **all service users** page, a platform administrator sees **every service user, whoever owns it**, with its handle, display name, owner, and status, so they can suspend or delete one. Only people the host lets manage every service user can open it."),
    )
    .await
    .map_err(|_| ServiceUserError::Store)?;
    visible_oldest_first(valence, service_users).await
}

/// Drop rows whose deletion is still running and sort oldest first, ties by handle.
async fn visible_oldest_first(
    valence: &Valence,
    service_users: Vec<ServiceUserAccount>,
) -> Result<Vec<ServiceUserAccount>, ServiceUserError> {
    // Queries return rows whose deletion is still running; `ServiceUserAccount::get` hides
    // them, so the list must too.
    let mut visible = Vec::with_capacity(service_users.len());
    for service_user in service_users {
        let Some(rid) = service_user.id() else {
            continue;
        };
        let bare = valence::extract_id_from_record(rid).unwrap_or_else(|_| rid.id().to_string());
        match OwnershipService::pending_deletion_gate("service_user_account", &bare, valence).await
        {
            Ok(()) => visible.push(service_user),
            Err(valence::Error::PendingDeletion(_)) => {}
            Err(_) => return Err(ServiceUserError::Store),
        }
    }
    // Timestamps are stored at second precision; the handle breaks ties.
    visible.sort_by(|a, b| (a.created_at(), a.handle()).cmp(&(b.created_at(), b.handle())));
    Ok(visible)
}

/// Edit a service user's display name or description. The handle and owner never change.
///
/// # Errors
///
/// [`ServiceUserError::NotAUser`], [`ServiceUserError::NotFound`],
/// [`ServiceUserError::InvalidProfile`], [`ServiceUserError::Forbidden`], or
/// [`ServiceUserError::Store`].
pub async fn update_service_user(
    valence: &Valence,
    id: &ServiceUserId,
    update: ServiceUserProfileUpdate<'_>,
) -> Result<ServiceUserAccount, ServiceUserError> {
    let result = update_service_user_inner(valence, id, update).await;
    record(Op::Update, result, Some(id))
}

async fn update_service_user_inner(
    valence: &Valence,
    id: &ServiceUserId,
    update: ServiceUserProfileUpdate<'_>,
) -> Result<ServiceUserAccount, ServiceUserError> {
    caller_user(valence)?;
    let display_name = update.display_name.map(check_display_name).transpose()?;
    let description = update.description.map(check_description).transpose()?;
    let service_user = load(valence, id).await?;
    let mut edit = service_user.get_mutable(
        valence,
        valence::use_!(r"When the owner **edits a service user**, we **save the new display name or description** they typed. The owner sees the change on the service user's page, and the service user's actions show the new name."),
    );
    if let Some(name) = display_name {
        edit = edit
            .set_display_name(name)
            .map_err(|_| ServiceUserError::Store)?;
    }
    match description {
        Some(Some(text)) => {
            edit = edit
                .set_description(text)
                .map_err(|_| ServiceUserError::Store)?;
        }
        Some(None) => edit = edit.clear_description(),
        None => {}
    }
    edit.set_updated_at(Utc::now())
        .map_err(|_| ServiceUserError::Store)?
        .commit()
        .await
        .map_err(|e| write_error(&e))
}

/// Suspend an active service user. A suspended service user keeps its profile but must not act;
/// token checks (added with service user tokens) refuse it.
///
/// # Errors
///
/// [`ServiceUserError::InvalidTransition`] when already suspended, plus the errors of
/// [`update_service_user`].
pub async fn suspend_service_user(
    valence: &Valence,
    id: &ServiceUserId,
) -> Result<ServiceUserAccount, ServiceUserError> {
    let result = set_status(valence, id, ServiceUserAccountStatus::Suspended).await;
    let result = record(Op::Suspend, result, Some(id));
    if let Ok(service_user) = &result {
        publish(service_user, id, ServiceUserLifecycleEvent::Suspended).await;
    }
    result
}

/// Resume a suspended service user.
///
/// # Errors
///
/// [`ServiceUserError::InvalidTransition`] when already active, plus the errors of
/// [`update_service_user`].
pub async fn resume_service_user(
    valence: &Valence,
    id: &ServiceUserId,
) -> Result<ServiceUserAccount, ServiceUserError> {
    let result = set_status(valence, id, ServiceUserAccountStatus::Active).await;
    let result = record(Op::Resume, result, Some(id));
    if let Ok(service_user) = &result {
        publish(service_user, id, ServiceUserLifecycleEvent::Resumed).await;
    }
    result
}

async fn set_status(
    valence: &Valence,
    id: &ServiceUserId,
    to: ServiceUserAccountStatus,
) -> Result<ServiceUserAccount, ServiceUserError> {
    caller_user(valence)?;
    let service_user = load(valence, id).await?;
    let next = transition(service_user.status(), to)?;
    let now = Utc::now();
    let edit = service_user
        .get_mutable(
            valence,
            valence::use_!(r"When the owner **suspends or resumes a service user**, we **save its new status and when it was suspended**. The owner sees the status on the service user's page, and a suspended service user is refused when it tries to act."),
        )
        .set_status(next.clone())
        .map_err(|_| ServiceUserError::Store)?;
    let edit = if next == ServiceUserAccountStatus::Suspended {
        edit.set_suspended_at(now)
            .map_err(|_| ServiceUserError::Store)?
    } else {
        edit.clear_suspended_at()
    };
    edit.set_updated_at(now)
        .map_err(|_| ServiceUserError::Store)?
        .commit()
        .await
        .map_err(|e| write_error(&e))
}

/// Delete a service user with the standard Valence delete.
///
/// The service user disappears from reads right away. Valence then removes it, and anything
/// that cascades from it, in the deletion run started by the host's deletion
/// dispatcher. Hosts register one at boot (valence-platform's
/// `register_deletion_dispatch`, which runs the Chronon deletion orchestrator);
/// without it the service user stays hidden but is never purged.
///
/// # Errors
///
/// [`ServiceUserError::NotAUser`], [`ServiceUserError::NotFound`],
/// [`ServiceUserError::Forbidden`], or [`ServiceUserError::Store`] (including a host with no
/// deletion dispatcher).
pub async fn delete_service_user(
    valence: &Valence,
    id: &ServiceUserId,
) -> Result<(), ServiceUserError> {
    let result = delete_service_user_inner(valence, id).await;
    match record(Op::Delete, result, Some(id)) {
        Ok(service_user) => {
            publish(&service_user, id, ServiceUserLifecycleEvent::Deleted).await;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Delete and return the row as it was loaded, so the event can name its owner.
async fn delete_service_user_inner(
    valence: &Valence,
    id: &ServiceUserId,
) -> Result<ServiceUserAccount, ServiceUserError> {
    caller_user(valence)?;
    let service_user = load(valence, id).await?;
    ServiceUserAccount::delete(
        id.as_str(),
        valence,
        valence::use_!(r"When the owner **deletes a service user**, we **remove the service user and everything attached to it** so it can no longer act and none of its data stays behind."),
    )
    .await
    .map_err(|e| write_error(&e))?;
    Ok(service_user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_table_happy() {
        assert!(matches!(
            transition(
                &ServiceUserAccountStatus::Active,
                ServiceUserAccountStatus::Suspended
            ),
            Ok(ServiceUserAccountStatus::Suspended)
        ));
        assert!(matches!(
            transition(
                &ServiceUserAccountStatus::Suspended,
                ServiceUserAccountStatus::Active
            ),
            Ok(ServiceUserAccountStatus::Active)
        ));
    }

    #[test]
    fn transition_table_sad() {
        assert!(matches!(
            transition(
                &ServiceUserAccountStatus::Active,
                ServiceUserAccountStatus::Active
            ),
            Err(ServiceUserError::InvalidTransition {
                from: ServiceUserAccountStatus::Active
            })
        ));
        assert!(matches!(
            transition(
                &ServiceUserAccountStatus::Suspended,
                ServiceUserAccountStatus::Suspended
            ),
            Err(ServiceUserError::InvalidTransition {
                from: ServiceUserAccountStatus::Suspended
            })
        ));
    }

    #[test]
    fn profile_checks_sad() {
        assert!(matches!(
            check_display_name("   "),
            Err(ServiceUserError::InvalidProfile {
                field: "display_name"
            })
        ));
        assert!(matches!(
            check_display_name(&"x".repeat(81)),
            Err(ServiceUserError::InvalidProfile {
                field: "display_name"
            })
        ));
        assert!(matches!(
            check_description(Some(&"x".repeat(501))),
            Err(ServiceUserError::InvalidProfile {
                field: "description"
            })
        ));
    }

    #[test]
    fn profile_checks_happy() {
        assert_eq!(
            check_display_name("  Spectra agent ").ok().as_deref(),
            Some("Spectra agent")
        );
        assert!(matches!(check_description(Some("  ")), Ok(None)));
        assert_eq!(
            check_description(Some(" reads metrics "))
                .ok()
                .flatten()
                .as_deref(),
            Some("reads metrics")
        );
    }
}
