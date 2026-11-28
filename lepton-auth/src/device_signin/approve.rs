//! The approver's side: look a request up by its user code, then approve or deny it.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use chrono::{DateTime, Utc};
use lepton_host_adapter::generated::{
    DeviceAuthorization, DeviceAuthorizationStatus, ServiceUserAccount, ServiceUserAccountStatus,
    SignedInDevice, SignedInDeviceStatus,
};
use lepton_identity::device_signin::normalize_user_code;
use lepton_identity::service_users::ServiceUserId;
use lepton_identity::tokens::{scopes_from_json, scopes_to_json, ApiScope, TokenLifetime};
use valence::{Model, RecordId, StringPredicate, Valence};

use super::emit::{emit, DeviceSigninOperation};
use super::{caller_user, owned_by, write_error, DeviceSigninError};
use crate::attempt_throttle::{is_locked, record_failure};
use crate::scopes::{check_scopes, ScopeError};
use crate::service_users::tokens::{used_token_slots, CREATE_LOCK};
use crate::service_users::{
    create_service_user, get_service_user, list_my_service_users, NewServiceUser,
    MAX_TOKENS_PER_SERVICE_USER,
};

/// Wrong user codes per approver: failures so far and, once five are spent, until when they're
/// locked out.
type WrongCodes = HashMap<String, (i64, Option<DateTime<Utc>>)>;

static WRONG_CODES: LazyLock<Mutex<WrongCodes>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// A pending request as the approval page shows it.
#[derive(Debug, Clone)]
pub struct DeviceRequest {
    /// The code the person typed, as stored (`WDJB-MJHT`).
    pub user_code: String,
    /// What the device calls itself.
    pub device_name: String,
    /// The app that asked.
    pub client: String,
    /// The address it asked from.
    pub asked_from: Option<String>,
    /// Its `User-Agent`.
    pub user_agent: Option<String>,
    /// The scopes it asked for; the page starts with these ticked.
    pub requested_scopes: Vec<ApiScope>,
    /// When the request stops working.
    pub expires_at: DateTime<Utc>,
    /// The approver's own service users, the only ones it can act as.
    pub choices: Vec<ServiceUserChoice>,
}

/// One of the approver's service users, and whether the device can act as it now.
#[derive(Debug, Clone)]
pub struct ServiceUserChoice {
    /// The service user.
    pub id: ServiceUserId,
    /// Its handle, such as `ci-deploy`.
    pub handle: String,
    /// Its display name.
    pub display_name: String,
    /// Live tokens plus devices still waiting for one.
    pub used_token_slots: usize,
    /// [`MAX_TOKENS_PER_SERVICE_USER`].
    pub token_limit: usize,
    /// Why it can't be picked right now, if it can't.
    pub unavailable: Option<Unavailable>,
}

/// Why a service user can't take another device right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// It's paused; resume it first.
    Paused,
    /// It has as many tokens as allowed; sign out a device or revoke a token first.
    TokenLimit,
}

impl Unavailable {
    /// Stable class for the page's message.
    #[must_use]
    pub const fn reason_class(self) -> &'static str {
        match self {
            Self::Paused => "paused",
            Self::TokenLimit => "token_limit",
        }
    }
}

/// Which service user the device acts as.
#[derive(Debug, Clone, Copy)]
pub enum ActAs<'a> {
    /// One the approver already owns.
    Existing(&'a ServiceUserId),
    /// A new one made for the device, checked like the create flow (it starts with no groups).
    New(NewServiceUser<'a>),
}

/// What the approver picked. See [`approve_device`].
#[derive(Debug, Clone, Copy)]
pub struct ApproveDevice<'a> {
    /// The code from the device's screen; case, spaces and dashes don't matter.
    pub user_code: &'a str,
    /// The service user the device acts as.
    pub act_as: ActAs<'a>,
    /// The APIs its token may call: at least one, each registered by the host.
    pub scopes: &'a [ApiScope],
    /// How long its token lasts: 30 or 90 days.
    pub lifetime: TokenLifetime,
}

fn locked_out(caller: &str) -> bool {
    WRONG_CODES.lock().is_ok_and(|codes| {
        codes
            .get(caller)
            .is_some_and(|(_, until)| is_locked(until.as_ref(), Utc::now()))
    })
}

/// Count a wrong code; returns the error to give (locked once the fifth miss lands).
fn wrong_code(caller: &str) -> DeviceSigninError {
    let Ok(mut codes) = WRONG_CODES.lock() else {
        return DeviceSigninError::NotFound;
    };
    let now = Utc::now();
    let entry = codes.entry(caller.to_string()).or_insert((0, None));
    // A lockout that has run out starts a fresh budget.
    if entry.1.is_some_and(|until| until <= now) {
        *entry = (0, None);
    }
    let (failed, until) = record_failure(entry.0, now);
    *entry = (failed, until);
    if until.is_some() {
        DeviceSigninError::Locked
    } else {
        DeviceSigninError::NotFound
    }
}

fn right_code(caller: &str) {
    if let Ok(mut codes) = WRONG_CODES.lock() {
        codes.remove(caller);
    }
}

/// The open request with this user code. A code that matches none counts against the caller.
async fn find_open_request(
    valence: &Valence,
    caller: &str,
    raw_code: &str,
) -> Result<DeviceAuthorization, DeviceSigninError> {
    if locked_out(caller) {
        return Err(DeviceSigninError::Locked);
    }
    let Some(user_code) = normalize_user_code(raw_code) else {
        return Err(wrong_code(caller));
    };
    let found = DeviceAuthorization::query(
        valence,
        valence::use_!(r"When you **type the code a device shows** on the approval page, we **find the device's sign-in request** with that code so you can see its name, app, the address it asked from and the APIs it wants before you approve or deny it."),
    )
    .where_user_code(StringPredicate::Equals(user_code))
    .first()
    .await
    .map_err(|_| DeviceSigninError::Store)?;
    let open = found.filter(|r| {
        matches!(r.status(), DeviceAuthorizationStatus::Pending)
            && r.user().is_none()
            && *r.expires_at() > Utc::now()
    });
    open.map_or_else(
        || Err(wrong_code(caller)),
        |request| {
            right_code(caller);
            Ok(request)
        },
    )
}

/// Look up a device's request by the code the person typed, with their own service users to
/// pick from.
///
/// Only service users the caller owns are listed, manage-any users included. Five wrong codes
/// lock the caller out for five minutes.
///
/// # Errors
///
/// [`DeviceSigninError::NotAUser`], [`DeviceSigninError::NotFound`] (no open request has the
/// code), [`DeviceSigninError::Locked`], or [`DeviceSigninError::Store`].
pub async fn lookup_device_request(
    valence: &Valence,
    user_code: &str,
) -> Result<DeviceRequest, DeviceSigninError> {
    let caller = caller_user(valence)?;
    let request = find_open_request(valence, &caller, user_code).await?;
    let mut choices = Vec::new();
    for service_user in list_my_service_users(valence).await? {
        choices.push(choice(valence, &service_user).await?);
    }
    Ok(DeviceRequest {
        user_code: request.user_code().clone(),
        device_name: request.device_name().clone(),
        client: request.client().clone(),
        asked_from: request.asked_from().cloned(),
        user_agent: request.user_agent().cloned(),
        requested_scopes: scopes_from_json(request.scopes()),
        expires_at: *request.expires_at(),
        choices,
    })
}

async fn choice(
    valence: &Valence,
    service_user: &ServiceUserAccount,
) -> Result<ServiceUserChoice, DeviceSigninError> {
    let id = service_user
        .id()
        .and_then(|rid| ServiceUserId::parse(rid.id()).ok())
        .ok_or(DeviceSigninError::Store)?;
    let used = used_token_slots(valence, service_user).await?;
    let unavailable = if matches!(service_user.status(), ServiceUserAccountStatus::Suspended) {
        Some(Unavailable::Paused)
    } else if used >= MAX_TOKENS_PER_SERVICE_USER {
        Some(Unavailable::TokenLimit)
    } else {
        None
    };
    Ok(ServiceUserChoice {
        id,
        handle: service_user.handle().clone(),
        display_name: service_user.display_name().clone(),
        used_token_slots: used,
        token_limit: MAX_TOKENS_PER_SERVICE_USER,
        unavailable,
    })
}

/// Approve a device as one of the caller's service users, after a recent step-up.
///
/// Call it from the approval page's server function with the request Valence. It checks the
/// session's step-up window first. The device gets its token the next time it polls; until
/// then it holds one of the service user's token slots.
///
/// # Errors
///
/// - [`DeviceSigninError::StepUp`] when the session has no recent step-up.
/// - [`DeviceSigninError::NotAUser`], [`DeviceSigninError::NotFound`],
///   [`DeviceSigninError::Locked`] as for [`lookup_device_request`].
/// - [`DeviceSigninError::InvalidScopes`] when no API, or one the host doesn't offer, is
///   picked; [`DeviceSigninError::ScopesNotRegistered`] when the host offers none.
/// - [`DeviceSigninError::Forbidden`] for someone else's service user, manage-any callers
///   included.
/// - [`DeviceSigninError::Paused`] for a paused service user.
/// - [`DeviceSigninError::QuotaReached`] when the service user has no token slot left.
/// - [`DeviceSigninError::ServiceUser`] when making the new service user fails, such as a
///   taken handle (`handle_taken`, with a suggestion).
/// - [`DeviceSigninError::Store`] on a storage failure.
#[cfg(feature = "totp")]
pub async fn approve_device(
    valence: &Valence,
    input: ApproveDevice<'_>,
) -> Result<SignedInDevice, DeviceSigninError> {
    use crate::step_up::{require_recent_verification, StepUpScope};

    if let Err(e) = require_recent_verification(StepUpScope::SensitiveMutation).await {
        let err = DeviceSigninError::from_step_up(&e);
        emit(DeviceSigninOperation::Approve, Some(err.reason_class()));
        return Err(err);
    }
    approve_after_step_up(valence, input).await
}

/// **Test only.** [`approve_device`] without the step-up check, for suites that run without
/// an HTTP session.
///
/// # Errors
///
/// As [`approve_device`], except [`DeviceSigninError::StepUp`].
#[cfg(feature = "test-utils")]
pub async fn approve_device_without_step_up(
    valence: &Valence,
    input: ApproveDevice<'_>,
) -> Result<SignedInDevice, DeviceSigninError> {
    approve_after_step_up(valence, input).await
}

#[cfg_attr(not(any(feature = "totp", feature = "test-utils")), allow(dead_code))]
async fn approve_after_step_up(
    valence: &Valence,
    input: ApproveDevice<'_>,
) -> Result<SignedInDevice, DeviceSigninError> {
    let result = approve_inner(valence, input).await;
    log("approve", result.as_ref().map(|_| ()));
    emit(
        DeviceSigninOperation::Approve,
        result.as_ref().err().map(DeviceSigninError::reason_class),
    );
    result
}

fn checked_scopes(requested: &[ApiScope]) -> Result<Vec<ApiScope>, DeviceSigninError> {
    check_scopes(requested).map_err(|e| match e {
        ScopeError::NotRegistered => DeviceSigninError::ScopesNotRegistered,
        ScopeError::Empty | ScopeError::Unknown(_) => DeviceSigninError::InvalidScopes,
    })
}

/// A service user the caller owns that can take another device now.
pub(super) async fn usable_service_user(
    valence: &Valence,
    caller: &str,
    service_user: &ServiceUserAccount,
) -> Result<(), DeviceSigninError> {
    if !owned_by(service_user.user(), caller) {
        return Err(DeviceSigninError::Forbidden);
    }
    if matches!(service_user.status(), ServiceUserAccountStatus::Suspended) {
        return Err(DeviceSigninError::Paused);
    }
    if used_token_slots(valence, service_user).await? >= MAX_TOKENS_PER_SERVICE_USER {
        return Err(DeviceSigninError::QuotaReached {
            limit: MAX_TOKENS_PER_SERVICE_USER,
        });
    }
    Ok(())
}

async fn approve_inner(
    valence: &Valence,
    input: ApproveDevice<'_>,
) -> Result<SignedInDevice, DeviceSigninError> {
    let caller = caller_user(valence)?;
    let request = find_open_request(valence, &caller, input.user_code).await?;
    let scopes = checked_scopes(input.scopes)?;
    let service_user = match input.act_as {
        ActAs::Existing(id) => get_service_user(valence, id).await?,
        ActAs::New(new) => create_service_user(valence, new).await?,
    };
    let service_user_id = service_user
        .id()
        .map(|rid| rid.id().to_string())
        .ok_or(DeviceSigninError::Store)?;
    let request_id = request
        .id()
        .map(|rid| rid.id().to_string())
        .ok_or(DeviceSigninError::Store)?;

    // The token slot check and the decision run under the token create lock, so neither a
    // second approval of this request nor another token can slip in between.
    let _guard = CREATE_LOCK.lock().await;
    usable_service_user(valence, &caller, &service_user).await?;
    let caller_ref = RecordId::new("user", &caller);
    request
        .get_mutable(
            valence,
            valence::use_!(r"When you **approve a device's sign-in**, we **mark its request approved and record that you approved it**, so the request can't be approved or denied again."),
        )
        .set_status(DeviceAuthorizationStatus::Approved)
        .and_then(|m| m.set_user(caller_ref.clone()))
        .map_err(|_| DeviceSigninError::Store)?
        .commit()
        .await
        .map_err(|e| write_error(&e))?;
    let device = SignedInDevice::new(
        Some(caller_ref),
        Some(RecordId::new("service_user_account", &service_user_id)),
        request.device_name().clone(),
        request.client().clone(),
        request.asked_from().cloned(),
        request.user_agent().cloned(),
        request.device_code_hash().clone(),
        Some(scopes_to_json(&scopes)),
        input.lifetime.days(),
        SignedInDeviceStatus::IssuePending,
        None,
        Utc::now(),
        None,
        None,
    )
    .map_err(|_| DeviceSigninError::Store)?;
    SignedInDevice::upsert(
        &request_id,
        device,
        valence,
        valence::use_!(r"When you **approve a device's sign-in**, we **save the device** with its name, app, the address it asked from, the service user it acts as, the APIs its token may call and for how long, and a one-way hash of its code. You see it on the service user's page and under Settings, Devices."),
    )
    .await
    .map_err(|e| write_error(&e))
}

/// Deny a device's request. The device's next poll gets `access_denied`.
///
/// # Errors
///
/// [`DeviceSigninError::NotAUser`], [`DeviceSigninError::NotFound`],
/// [`DeviceSigninError::Locked`], or [`DeviceSigninError::Store`].
pub async fn deny_device(valence: &Valence, user_code: &str) -> Result<(), DeviceSigninError> {
    let result = deny_inner(valence, user_code).await;
    log("deny", result.as_ref().map(|&()| ()));
    emit(
        DeviceSigninOperation::Deny,
        result.as_ref().err().map(DeviceSigninError::reason_class),
    );
    result
}

async fn deny_inner(valence: &Valence, user_code: &str) -> Result<(), DeviceSigninError> {
    let caller = caller_user(valence)?;
    let request = find_open_request(valence, &caller, user_code).await?;
    request
        .get_mutable(
            valence,
            valence::use_!(r"When you **deny a device's sign-in**, we **mark its request denied and record that you denied it**, so the device is told no and the request can't be approved."),
        )
        .set_status(DeviceAuthorizationStatus::Denied)
        .and_then(|m| m.set_user(RecordId::new("user", &caller)))
        .map_err(|_| DeviceSigninError::Store)?
        .commit()
        .await
        .map_err(|e| write_error(&e))?;
    Ok(())
}

fn log(op: &'static str, result: Result<(), &DeviceSigninError>) {
    match result {
        Ok(()) => tracing::info!(target: "lepton.device_signin", op, "device sign-in"),
        Err(e) => tracing::debug!(
            target: "lepton.device_signin",
            op,
            reason_class = e.reason_class(),
            "device sign-in refused"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifth_wrong_code_locks_happy() {
        let caller = "lockout-unit-test";
        right_code(caller);
        for _ in 0..4 {
            assert!(matches!(wrong_code(caller), DeviceSigninError::NotFound));
        }
        assert!(!locked_out(caller));
        assert!(matches!(wrong_code(caller), DeviceSigninError::Locked));
        assert!(locked_out(caller));
        right_code(caller);
        assert!(!locked_out(caller));
    }

    #[test]
    fn unavailable_classes_happy() {
        assert_eq!(Unavailable::Paused.reason_class(), "paused");
        assert_eq!(Unavailable::TokenLimit.reason_class(), "token_limit");
    }
}
