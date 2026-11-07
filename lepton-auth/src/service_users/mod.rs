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
//! suspended, unless the host sets another limit at boot with
//! [`install_service_users_per_owner`](lepton_identity::config::install_service_users_per_owner).
//! [`create_service_user`] fails with [`ServiceUserError::QuotaReached`] past the limit;
//! deleting a service user frees its slot at once.
//!
//! # Listing every service user
//!
//! [`list_my_service_users`] lists the caller's own. [`list_all_service_users`] lists every
//! service user, whoever owns it, for callers the gate grants manage-any; anyone else gets
//! [`ServiceUserError::Forbidden`]. The `lepton-auth-ui` crate's `AllServiceUsersPage` shows
//! this list with each owner and a handle filter; it calls the
//! [`list_all_service_users_admin`](crate::actions::service_users::list_all_service_users_admin)
//! server function.
//!
//! # Events
//!
//! Each saved create, suspend, resume, and delete publishes one Photon
//! [`ServiceUserLifecycleChanged`](crate::events::ServiceUserLifecycleChanged), keyed by the
//! owner and carrying ids only. Edits publish nothing.
//!
//! # Activity history
//!
//! Each create, edit, suspend, and resume saves one history row for the service user, saved
//! with the caller's own Valence. A failed write is logged and never fails the change.
//! Deleting writes none; the history goes with the service user.
//! [`list_service_user_activity`] returns the newest entries to whoever can see the service
//! user. Creating and revoking a token (see below) adds its own entry; a host
//! that issues tokens another way reports them with [`record_service_user_token_activity`]. Rows never change after they are saved.
//!
//! # Access tokens
//!
//! A service user calls in with a personal access token its owner creates with
//! [`create_service_user_token`]. The plaintext token comes back once; Lepton keeps a hash.
//! [`list_service_user_tokens`] shows labels and times, [`revoke_service_user_token`] stops a
//! token at once, and the host (or `lepton_host_adapter::bearer_middleware`) checks a presented
//! token with [`verify_bearer_token`](lepton_identity::service_users::verify_bearer_token).
//! Only the owner creates tokens; users the gate grants manage-any can list and revoke. A
//! service user can hold [`MAX_TOKENS_PER_SERVICE_USER`] live tokens, each valid for at most
//! [`MAX_TOKEN_LIFETIME_DAYS`] days. Deleting a service user or its owner deletes its tokens.
//!
//! # Deletion
//!
//!
//! [`delete_service_user`] uses the standard Valence delete: the service user disappears from reads
//! at once, and the deletion run the host's dispatcher starts (valence-platform's
//! Chronon deletion orchestrator) removes the row. Deleting the owner's user
//! ([`identity_delete`](crate::identity_delete)) deletes their service users too.

mod activity;
mod api;
pub(crate) mod erase;
mod error;
mod handle_lookup;
mod tokens;

pub use activity::{
    list_service_user_activity, record_service_user_token_activity, ServiceUserTokenEvent,
    DEFAULT_ACTIVITY_LIMIT, MAX_ACTIVITY_LIMIT,
};
pub use api::{
    create_service_user, delete_service_user, get_service_user, list_all_service_users,
    list_my_service_users, resume_service_user, suggest_service_user_handle, suspend_service_user,
    update_service_user, NewServiceUser, ServiceUserProfileUpdate, MAX_SERVICE_USERS_PER_OWNER,
};
pub use error::ServiceUserError;
pub use tokens::{
    create_service_user_token, list_service_user_tokens, revoke_service_user_token,
    CreatedServiceUserToken, NewServiceUserToken, MAX_TOKENS_PER_SERVICE_USER,
    MAX_TOKEN_LIFETIME_DAYS,
};
