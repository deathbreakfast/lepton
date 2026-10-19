//! Service users: create, edit, suspend, resume, and delete.
//!
//! A service user is a non-human account owned by a user. It has its own id and acts in
//! Valence as its own service actor, so what it does is attributed to the service user,
//! not to the person who owns it. Model, handle rules, and the host gate live in
//! [`lepton_identity::service_users`].
//!
//! Every call takes the **request** Valence (`ctx.valence()` after
//! [`require_auth_user`](crate::require_auth_user)); the caller must be a signed-in user.
//! Owners manage their own service users, and users the host's
//! [`ServiceUserGate`](lepton_identity::service_users::ServiceUserGate) grants manage-any can
//! manage every service user. Nobody else can see a service user: they get
//! [`ServiceUserError::NotFound`].
//!
//! The crate root walks through the full lifecycle with an example:
//! [Create and manage a service user](crate#create-and-manage-a-service-user).
//!
//! # Handle clashes
//!
//! Handles are pseudo-unique. When another service user already uses the handle (ignoring
//! case and dashes), [`create_service_user`] fails with [`ServiceUserError::HandleTaken`] and a
//! free suggestion such as `spectra-agent-2`. [`suggest_service_user_handle`] turns free
//! text into a free handle before the form is submitted.
//!
//! # Limit per owner
//!
//! One owner can have at most [`MAX_SERVICE_USERS_PER_OWNER`] service users, active or
//! suspended. [`create_service_user`] fails with [`ServiceUserError::QuotaReached`] past that;
//! deleting a service user frees its slot at once.
//!
//! # Deletion
//!
//! [`delete_service_user`] uses the standard Valence delete: the service user disappears from reads
//! at once, and the deletion run the host's dispatcher starts (valence-platform's
//! Chronon deletion orchestrator) removes the row. Deleting the owner's user
//! ([`identity_delete`](crate::identity_delete)) deletes their service users too.

mod api;
pub(crate) mod erase;
mod error;
mod handle_lookup;

pub use api::{
    create_service_user, delete_service_user, get_service_user, list_my_service_users,
    resume_service_user, suggest_service_user_handle, suspend_service_user, update_service_user,
    NewServiceUser, ServiceUserProfileUpdate, MAX_SERVICE_USERS_PER_OWNER,
};
pub use error::ServiceUserError;
