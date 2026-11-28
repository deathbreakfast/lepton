//! Device sign-in (RFC 8628): a device signs in as a service user its approver owns, never as
//! the person.
//!
//! A device can be always on and take input from whoever is near it, so its access is held to
//! one service user's: the APIs its token's scopes name, and what that service user's groups
//! allow.
//!
//! | Step | Who | Call |
//! |------|-----|------|
//! | Ask for codes | the device, `POST /auth/device/code` | [`LeptonDeviceFlow::start`] |
//! | See the request | the person, on the approval page | [`lookup_device_request`] |
//! | Approve as one of their service users, or a new one | the person, after step-up | [`approve_device`] |
//! | Deny | the person | [`deny_device`] |
//! | Collect the token, once | the device, `POST /auth/device/token` | [`LeptonDeviceFlow::poll`] |
//! | List | the owner (or manage-any) | [`list_service_user_devices`], [`list_my_devices`] |
//! | Rename | the owner | [`rename_device`] |
//! | Move to another of their service users | the owner, after step-up | [`move_device`] |
//! | Sign out | the owner (or manage-any) | [`sign_out_device`] |
//!
//! The host mounts the two device routes with
//! [`device_signin_routes`](lepton_host_adapter::device_signin::device_signin_routes) and a
//! [`LeptonDeviceFlow`]; the rest are server functions behind its pages.
//!
//! The device's token is an ordinary service user token (`kind = device`), minted through
//! [`service_users`](crate::service_users) when the device collects it. It counts toward the
//! service user's token limit from the moment it's approved. Deleting the service user, or its
//! owner, deletes its devices; a paused service user's devices can't collect a token.
//!
//! Only the owner signs a device in as a service user. Users the service user gate lets manage
//! every service user can see and sign out devices, but can't approve one as somebody else's
//! service user ([`DeviceSigninError::Forbidden`]).

mod approve;
mod emit;
mod error;
mod flow;
mod manage;

#[cfg(feature = "totp")]
pub use approve::approve_device;
#[cfg(feature = "test-utils")]
pub use approve::approve_device_without_step_up;
pub use approve::{
    deny_device, lookup_device_request, ActAs, ApproveDevice, DeviceRequest, ServiceUserChoice,
    Unavailable,
};
pub use error::DeviceSigninError;
pub use flow::{
    LeptonDeviceFlow, DEFAULT_POLL_INTERVAL_SECS, DEVICE_CODE_TTL_SECS, MAX_OPEN_REQUESTS,
    MAX_OPEN_REQUESTS_PER_ADDRESS,
};
#[cfg(feature = "totp")]
pub use manage::move_device;
#[cfg(feature = "test-utils")]
pub use manage::move_device_without_step_up;
pub use manage::{
    list_my_devices, list_service_user_devices, rename_device, sign_out_device, DeviceListing,
};

use valence::{Actor, RecordId, Valence};

fn caller_user(valence: &Valence) -> Result<String, DeviceSigninError> {
    match valence.actor() {
        Actor::User { user_id } => Ok(user_id
            .split_once(':')
            .map_or(user_id.as_str(), |(_, id)| id)
            .to_string()),
        _ => Err(DeviceSigninError::NotAUser),
    }
}

fn owned_by(owner: Option<&RecordId>, caller: &str) -> bool {
    owner.is_some_and(|rid| rid.id() == caller)
}

const fn write_error(e: &valence::Error) -> DeviceSigninError {
    match e {
        valence::Error::Privacy(_) => DeviceSigninError::Forbidden,
        valence::Error::PendingDeletion(_) => DeviceSigninError::NotFound,
        _ => DeviceSigninError::Store,
    }
}
