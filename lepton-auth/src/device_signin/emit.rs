//! Spectra counter for device sign-in, when the `spectra` feature is on.

#[cfg(feature = "spectra")]
pub use crate::spectra_emit::DeviceSigninOperation;

/// The operations counted, mirrored when `spectra` is off so call sites need no `cfg`.
#[cfg(not(feature = "spectra"))]
#[derive(Clone, Copy, Debug)]
pub enum DeviceSigninOperation {
    Start,
    Approve,
    Deny,
    Issue,
    Move,
    Rename,
    SignOut,
}

/// Count one operation; `error_class` is `None` on success. Labels carry no codes, names,
/// addresses or ids.
#[cfg_attr(not(feature = "spectra"), allow(clippy::missing_const_for_fn))]
pub fn emit(operation: DeviceSigninOperation, error_class: Option<&'static str>) {
    #[cfg(feature = "spectra")]
    crate::spectra_emit::device_signin(operation, error_class.unwrap_or("none"));
    #[cfg(not(feature = "spectra"))]
    let _ = (operation, error_class);
}
