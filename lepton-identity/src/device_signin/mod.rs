//! Device sign-in (RFC 8628): a device signs in as a service user its approver owns.
//!
//! A device that can't show a browser (a CLI, a kitchen screen) asks the host for a device
//! code and a short user code. The person types the user code on the host's approval page,
//! picks one of their own service users, and approves. The device then polls with its device
//! code and collects a service user token. It never acts as the person.
//!
//! Two tables hold the flow:
//!
//! - `device_authorization` ([`generated::DeviceAuthorization`](crate::generated::DeviceAuthorization)):
//!   the pending request, at most 10 minutes old. The device side writes and reads it before
//!   anyone is signed in, through the host's System lookup handle.
//! - `signed_in_device` ([`generated::SignedInDevice`](crate::generated::SignedInDevice)): the
//!   device once approved, owned by the approver, naming the service user it acts as and its
//!   current token.
//!
//! The token itself is minted when the device collects it, on a Valence opened as the service
//! user ([`SERVICE_USER_DEVICE_TOKEN_CREATE`](crate::service_users::SERVICE_USER_DEVICE_TOKEN_CREATE)),
//! so no token plaintext is ever stored. Starting, polling and approving are in
//! `lepton_auth::device_signin`.
//!
//! # Privacy
//!
//! | Actor | `device_authorization` | `signed_in_device` |
//! |-------|------------------------|--------------------|
//! | System (pre-sign-in lookup) | create, read, update, delete | nothing beyond Valence's usual System access |
//! | Signed-in person | read a pending request; approve or deny it once | read, rename, move, sign out devices they own |
//! | Gate's manage-any user | nothing | read and delete |
//! | The service user a device acts as | nothing | read its devices; record its token on them |
//!
//! Deleting the approver deletes their devices and requests; deleting a service user deletes
//! the devices that act as it.

mod code;
mod rules;

pub use code::{
    normalize_user_code, DeviceCode, DeviceCodeParseError, DEVICE_CODE_PREFIX, USER_CODE_ALPHABET,
};
pub use rules::{
    DeviceAuthDecideRule, DeviceAuthPendingReadRule, SignedInDeviceCreateRule,
    SignedInDeviceImmutableRule, SignedInDeviceSelfRule, SignedInDeviceSelfTouchRule,
    DEVICE_AUTH_DECIDE, DEVICE_AUTH_PENDING_READ, SIGNED_IN_DEVICE_CREATE,
    SIGNED_IN_DEVICE_IMMUTABLE, SIGNED_IN_DEVICE_SELF, SIGNED_IN_DEVICE_SELF_TOUCH,
};

/// Table of pending device sign-ins.
pub const DEVICE_AUTHORIZATION_TABLE: &str = "device_authorization";

/// Table of signed-in devices.
pub const SIGNED_IN_DEVICE_TABLE: &str = "signed_in_device";
