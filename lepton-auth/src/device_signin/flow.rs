//! The device's side: start and poll. Both run before anyone is signed in.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use lepton_host_adapter::device_signin::{
    DevicePollError, DeviceSigninFlow, DeviceStartError, DeviceStartGrant, DeviceStartRequest,
    DeviceTokenGrant,
};
use lepton_host_adapter::generated::{
    DeviceAuthorization, DeviceAuthorizationStatus, SignedInDevice, SignedInDeviceStatus,
};
use lepton_identity::device_signin::DeviceCode;
use lepton_identity::service_users::{active_service_user_owner, ServiceUserId};
use lepton_identity::tokens::{scopes_from_json, scopes_to_json, ApiScope};
use tokio::sync::Mutex;
use valence::{Actor, Model, StringPredicate, Valence};

use super::emit::{emit, DeviceSigninOperation};
use crate::scopes::{check_scopes, ScopeError};
use crate::service_users::tokens::issue_device_token;

/// How long a device code and its user code work: 10 minutes.
pub const DEVICE_CODE_TTL_SECS: i64 = 600;

/// How often a device may poll while it waits, in seconds.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

const MAX_NAME: usize = 80;
const MAX_ORIGIN: usize = 255;
const USER_CODE_TRIES: usize = 5;

/// Serializes collecting a token, so two polls of one device can't both mint one.
static ISSUE_LOCK: Mutex<()> = Mutex::const_new(());

/// Lepton's [`DeviceSigninFlow`]: hand it to
/// [`device_signin_routes`](lepton_host_adapter::device_signin::device_signin_routes).
///
/// It keeps when each pending request last polled, to answer `slow_down` to a device that
/// polls faster than its interval. Use one per process.
#[derive(Debug)]
pub struct LeptonDeviceFlow {
    interval: Duration,
    last_poll: std::sync::Mutex<HashMap<String, Instant>>,
}

impl Default for LeptonDeviceFlow {
    fn default() -> Self {
        Self::new()
    }
}

impl LeptonDeviceFlow {
    /// A flow whose devices poll every [`DEFAULT_POLL_INTERVAL_SECS`] seconds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_poll_interval(Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS))
    }

    /// A flow with another poll interval (whole seconds are sent to the device).
    #[must_use]
    pub fn with_poll_interval(interval: Duration) -> Self {
        Self {
            interval,
            last_poll: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Start a device sign-in: store a pending request and return its codes.
    ///
    /// `lookup` is a System handle (the routes pass theirs); the device isn't anyone yet. The
    /// device may ask for no scopes, and the approver ticks them; any scope it does ask for must
    /// be one the host registered.
    ///
    /// # Errors
    ///
    /// [`DeviceStartError::InvalidRequest`] for an empty or over-long client or device name,
    /// [`DeviceStartError::InvalidScope`] for an unregistered scope, and
    /// [`DeviceStartError::ServerError`] when no scopes are registered or storage fails.
    pub async fn start(
        &self,
        lookup: &Valence,
        request: DeviceStartRequest,
    ) -> Result<DeviceStartGrant, DeviceStartError> {
        let result = start_inner(lookup, request, self.interval).await;
        emit(
            DeviceSigninOperation::Start,
            result.as_ref().err().map(|e| e.as_str()),
        );
        result
    }

    /// Answer one poll with the device's token, once, or the RFC 8628 error for where the
    /// request stands.
    ///
    /// `lookup` is a System handle, used only to find the request and device by the device
    /// code. The token is minted on a Valence opened as the service user the device was
    /// approved as, which the service user token rules allow only for this device's pending
    /// token. After the owner moves the device, the next poll with the same device code
    /// collects the replacement token.
    ///
    /// # Errors
    ///
    /// See [`DevicePollError`].
    pub async fn poll(
        &self,
        lookup: &Valence,
        device_code: &str,
    ) -> Result<DeviceTokenGrant, DevicePollError> {
        let result = self.poll_inner(lookup, device_code).await;
        match &result {
            Ok(_) => emit(DeviceSigninOperation::Issue, None),
            // Waiting is the normal state of a poll, not a failure worth counting.
            Err(DevicePollError::AuthorizationPending | DevicePollError::SlowDown) => {}
            Err(e) => emit(DeviceSigninOperation::Issue, Some(e.as_str())),
        }
        result
    }

    async fn poll_inner(
        &self,
        lookup: &Valence,
        raw: &str,
    ) -> Result<DeviceTokenGrant, DevicePollError> {
        let code = DeviceCode::parse(raw).map_err(|_| DevicePollError::InvalidGrant)?;
        let request = DeviceAuthorization::get(
            code.id(),
            lookup,
            valence::use_!(r"When a **device polls for its sign-in**, we **load its pending request** by the code it holds to see whether its owner approved or denied it. Nothing is shown to anyone but the device, which gets only the answer."),
        )
        .await
        .map_err(|_| DevicePollError::ServerError)?;
        if let Some(request) = request {
            if !code.matches(request.device_code_hash()) {
                return Err(DevicePollError::InvalidGrant);
            }
            match request.status() {
                DeviceAuthorizationStatus::Pending => {
                    if *request.expires_at() <= Utc::now() {
                        self.forget(code.id());
                        remove_request(lookup, code.id()).await;
                        return Err(DevicePollError::ExpiredToken);
                    }
                    return Err(if self.polled_too_soon(code.id()) {
                        DevicePollError::SlowDown
                    } else {
                        DevicePollError::AuthorizationPending
                    });
                }
                DeviceAuthorizationStatus::Denied => {
                    self.forget(code.id());
                    remove_request(lookup, code.id()).await;
                    return Err(DevicePollError::AccessDenied);
                }
                DeviceAuthorizationStatus::Approved => {
                    self.forget(code.id());
                    remove_request(lookup, code.id()).await;
                }
            }
        }
        collect_token(lookup, &code).await
    }

    /// Record this poll and say whether it came sooner than the interval allows.
    fn polled_too_soon(&self, id: &str) -> bool {
        let now = Instant::now();
        let Ok(mut polls) = self.last_poll.lock() else {
            return false;
        };
        // Requests live 10 minutes; drop what can no longer poll.
        let ttl = Duration::from_secs(DEVICE_CODE_TTL_SECS.unsigned_abs());
        polls.retain(|_, at| now.duration_since(*at) < ttl);
        polls
            .insert(id.to_string(), now)
            .is_some_and(|last| now.duration_since(last) < self.interval)
    }

    fn forget(&self, id: &str) {
        if let Ok(mut polls) = self.last_poll.lock() {
            polls.remove(id);
        }
    }
}

#[async_trait]
impl DeviceSigninFlow for LeptonDeviceFlow {
    async fn start(
        &self,
        lookup: &Valence,
        request: DeviceStartRequest,
    ) -> Result<DeviceStartGrant, DeviceStartError> {
        Self::start(self, lookup, request).await
    }

    async fn poll(
        &self,
        lookup: &Valence,
        device_code: &str,
    ) -> Result<DeviceTokenGrant, DevicePollError> {
        Self::poll(self, lookup, device_code).await
    }
}

fn bounded(raw: &str, max: usize) -> Option<String> {
    let trimmed = raw.trim();
    (!trimmed.is_empty() && trimmed.chars().count() <= max).then(|| trimmed.to_string())
}

fn cut(raw: Option<String>, max: usize) -> Option<String> {
    raw.map(|s| s.trim().chars().take(max).collect::<String>())
        .filter(|s| !s.is_empty())
}

fn requested_scopes(raw: &[String]) -> Result<Vec<ApiScope>, DeviceStartError> {
    let parsed = raw
        .iter()
        .map(|s| ApiScope::parse(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| DeviceStartError::InvalidScope)?;
    if parsed.is_empty() {
        return Ok(parsed);
    }
    check_scopes(&parsed).map_err(|e| match e {
        ScopeError::NotRegistered => DeviceStartError::ServerError,
        ScopeError::Empty | ScopeError::Unknown(_) => DeviceStartError::InvalidScope,
    })
}

async fn start_inner(
    lookup: &Valence,
    request: DeviceStartRequest,
    interval: Duration,
) -> Result<DeviceStartGrant, DeviceStartError> {
    let client = bounded(&request.client, MAX_NAME).ok_or(DeviceStartError::InvalidRequest)?;
    let name = bounded(&request.device_name, MAX_NAME).ok_or(DeviceStartError::InvalidRequest)?;
    let scopes = requested_scopes(&request.scopes)?;
    purge_expired(lookup).await;

    let code = DeviceCode::generate();
    let user_code = free_user_code(lookup).await?;
    let now = Utc::now();
    let row = DeviceAuthorization::new(
        code.hash(),
        user_code.clone(),
        name,
        client,
        cut(request.asked_from, MAX_ORIGIN),
        cut(request.user_agent, MAX_ORIGIN),
        Some(scopes_to_json(&scopes)),
        DeviceAuthorizationStatus::Pending,
        None,
        now + chrono::Duration::seconds(DEVICE_CODE_TTL_SECS),
        now,
    )
    .map_err(|_| DeviceStartError::ServerError)?;
    DeviceAuthorization::upsert(
        code.id(),
        row,
        lookup,
        valence::use_!(r"When a **device asks to sign in**, we **save its name, app, the address it asked from, the APIs it asks for, a short code to type, and a one-way hash of its secret code**. The person who types the short code sees the name, app, address and APIs on the approval page; the request is deleted once it is used, denied or 10 minutes old."),
    )
    .await
    .map_err(|_| DeviceStartError::ServerError)?;
    tracing::info!(target: "lepton.device_signin", op = "start", "device sign-in started");
    Ok(DeviceStartGrant {
        device_code: code.expose(),
        user_code,
        expires_in: DEVICE_CODE_TTL_SECS.unsigned_abs(),
        interval: interval.as_secs().max(1),
    })
}

/// A user code no open request uses.
async fn free_user_code(lookup: &Valence) -> Result<String, DeviceStartError> {
    for _ in 0..USER_CODE_TRIES {
        let candidate = DeviceCode::generate_user_code();
        let taken = DeviceAuthorization::query(
            lookup,
            valence::use_!(r"When a **device asks to sign in**, we **check whether the short code we picked is already in use** by another open request, and pick another if so. Only whether it is taken is used."),
        )
        .where_user_code(StringPredicate::Equals(candidate.clone()))
        .first()
        .await
        .map_err(|_| DeviceStartError::ServerError)?;
        if taken.is_none() {
            return Ok(candidate);
        }
    }
    Err(DeviceStartError::ServerError)
}

/// Delete requests past their 10 minutes. Best-effort; never fails the start.
async fn purge_expired(lookup: &Valence) {
    let rows = DeviceAuthorization::query(
        lookup,
        valence::use_!(r"When a **device asks to sign in**, we **look for sign-in requests older than 10 minutes** so they can be deleted. Nothing is shown to anyone."),
    )
    .await;
    let Ok(rows) = rows else {
        tracing::warn!(target: "lepton.device_signin", "expired requests not listed");
        return;
    };
    let now = Utc::now();
    for row in rows.iter().filter(|r| *r.expires_at() <= now) {
        if let Some(id) = row.id() {
            remove_request(lookup, id.id()).await;
        }
    }
}

/// Delete a request that was used, denied or expired. Best-effort.
async fn remove_request(lookup: &Valence, id: &str) {
    if let Err(e) = DeviceAuthorization::delete_now(
        id,
        lookup,
        valence::use_!(r"Once a **device sign-in request** is used, denied or 10 minutes old, we **delete it**, with the device's name, address and codes, so none of it stays behind."),
    )
    .await
    {
        tracing::warn!(target: "lepton.device_signin", error = %e, "device request not deleted");
    }
}

/// Mint the device's pending token, acting as its service user.
async fn collect_token(
    lookup: &Valence,
    code: &DeviceCode,
) -> Result<DeviceTokenGrant, DevicePollError> {
    let device = load_device(lookup, code.id()).await?;
    if !code.matches(device.device_code_hash()) {
        return Err(DevicePollError::InvalidGrant);
    }
    if matches!(device.status(), SignedInDeviceStatus::SignedIn) {
        return Err(DevicePollError::InvalidGrant);
    }
    let service_user = device
        .service_user()
        .and_then(|rid| ServiceUserId::parse(rid.id()).ok())
        .ok_or(DevicePollError::InvalidGrant)?;
    let owner = device.user().map(|rid| rid.id().to_string());

    // The device code proved who is polling; from here on the request runs as the service user
    // the device acts as, never as System.
    let as_service_user = lookup.with_actor(service_user.actor());
    match active_service_user_owner(service_user.as_str(), &as_service_user).await {
        Some(Actor::User { user_id }) if Some(&user_id) == owner.as_ref() => {}
        _ => return Err(DevicePollError::AccessDenied),
    }

    let _guard = ISSUE_LOCK.lock().await;
    let device = load_device(&as_service_user, code.id()).await?;
    if !matches!(device.status(), SignedInDeviceStatus::IssuePending) {
        return Err(DevicePollError::InvalidGrant);
    }
    let created = issue_device_token(&as_service_user, &device)
        .await
        .map_err(|e| {
            tracing::warn!(
                target: "lepton.device_signin",
                reason_class = e.reason_class(),
                "device token not minted"
            );
            DevicePollError::ServerError
        })?;
    let token_id = created
        .row
        .id()
        .map(|rid| rid.id().to_string())
        .ok_or(DevicePollError::ServerError)?;
    let expires_at = *created.row.expires_at();
    let now = Utc::now();
    device
        .get_mutable(
            &as_service_user,
            valence::use_!(r"When a **device collects its token**, we **record which token it holds, when it signed in, and until when**, so its owner sees it on the service user's and the Devices page."),
        )
        .set_token(token_id)
        .and_then(|m| m.set_status(SignedInDeviceStatus::SignedIn))
        .and_then(|m| m.set_last_seen_at(now))
        .and_then(|m| m.set_signed_in_until(expires_at))
        .map_err(|_| DevicePollError::ServerError)?
        .commit()
        .await
        .map_err(|e| {
            tracing::warn!(target: "lepton.device_signin", error = %e, "device record not updated");
            DevicePollError::ServerError
        })?;
    tracing::info!(
        target: "lepton.device_signin",
        op = "issue",
        service_user_id = service_user.as_str(),
        "device collected its token"
    );
    Ok(DeviceTokenGrant {
        access_token: created.token,
        expires_in: (expires_at - now).num_seconds().max(0).unsigned_abs(),
        scopes: scopes_from_json(created.row.scopes()),
    })
}

async fn load_device(v: &Valence, id: &str) -> Result<SignedInDevice, DevicePollError> {
    SignedInDevice::get(
        id,
        v,
        valence::use_!(r"When a **device polls for its token**, we **load its device record** by the code it holds to see which service user it acts as and whether a token is waiting for it. Nothing is shown to anyone but the device."),
    )
    .await
    .map_err(|e| match e {
        // A signed-out device, or one whose service user was deleted.
        valence::Error::PendingDeletion(_) => DevicePollError::InvalidGrant,
        _ => DevicePollError::ServerError,
    })?
    .ok_or(DevicePollError::InvalidGrant)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_down_only_inside_interval_happy() {
        let flow = LeptonDeviceFlow::with_poll_interval(Duration::from_secs(60));
        assert!(!flow.polled_too_soon("a"), "first poll is never too soon");
        assert!(flow.polled_too_soon("a"));
        assert!(!flow.polled_too_soon("b"));
        flow.forget("a");
        assert!(!flow.polled_too_soon("a"));
    }

    #[test]
    fn zero_interval_never_slows_down_sad() {
        let flow = LeptonDeviceFlow::with_poll_interval(Duration::ZERO);
        assert!(!flow.polled_too_soon("a"));
        assert!(!flow.polled_too_soon("a"));
    }

    #[test]
    fn names_are_bounded_sad() {
        assert_eq!(bounded("  uf CLI  ", 80).as_deref(), Some("uf CLI"));
        assert_eq!(bounded("   ", 80), None);
        assert_eq!(bounded(&"x".repeat(81), 80), None);
        assert_eq!(cut(Some(" ".into()), 10), None);
        assert_eq!(cut(Some("abcdef".into()), 3).as_deref(), Some("abc"));
    }
}
