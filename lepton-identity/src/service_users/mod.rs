//! Service users: non-human accounts owned by a user.
//!
//! A service user is the account an automation client, a CI job, a webhook consumer, or an agent uses
//! to act for a person. It has its own [`ServiceUserId`] and acts in Valence as
//! `Actor::ServiceUser { service_name: "svc:<id>" }`, so audit rows and privacy checks name
//! the service user, not the person who owns it. Its profile lives in the
//! `service_user_account` table
//! ([`generated::ServiceUserAccount`](crate::generated::ServiceUserAccount)): owner, a
//! [`ServiceUserHandle`] such as `spectra-agent`, display name, description, and status
//! (`active` or `suspended`).
//!
//! The owner can edit, suspend, resume, and delete the service user. A service user never manages
//! itself, and it gains no permissions just by existing. Deleting the owner's
//! user deletes their service users.
//!
//! Who may create service users, and who may manage every service user, is a host decision
//! made by a [`ServiceUserGate`] installed once at boot. Until one is installed, nobody can
//! create service users and nobody can manage service users they do not own. The crate root
//! walks through it: [Install the service user gate](crate#install-the-service-user-gate).
//!
//! # Privacy
//!
//! | Actor | Read | Create | Update / suspend | Delete |
//! |-------|------|--------|------------------|--------|
//! | Owner | own service users | when the gate allows | own service users | own service users |
//! | Gate's manage-any user | all service users | own service users, when allowed | all service users | all service users |
//! | Other user | nothing | own service users, when allowed | nothing | nothing |
//! | Any service user, registered or built-in | nothing | nothing | nothing | nothing |
//! | System | all | nothing | all | all |
//!
//! Nobody can change a service user's owner, creator, or handle after creation
//! ([`SERVICE_USER_IDENTITY_IMMUTABLE`]).
//!
//! The lifecycle calls (create, suspend, delete, …) are in `lepton_auth::service_users`.
//! How a host authenticates a service user and refuses a suspended one is in [Authentication
//! is the host's job](crate#authentication-is-the-hosts-job-preview).
//!
//! # Built-in and registered service users
//!
//! Valence has one actor variant for non-human callers, `Actor::ServiceUser`, and two kinds of
//! service user share it. Telling them apart matters because only one kind has an owner who
//! answers for what it does.
//!
//! - A **built-in** service user, such as `cron` or `spectra-ingest`, is asserted by host code
//!   for its own background work. It has no row and no owner, and it never gains
//!   the powers of a registered one.
//! - A **registered** service user is the managed kind described above: a row in the
//!   `service_user_account` table with an owner, a status, and any Gauge grants, acting as
//!   `svc:<id>`.
//!
//! [`ServiceUserId::from_actor`] is the one check that recognizes a registered service user.
//! [`is_managed_service_name`] reserves the `svc:` namespace, and the retired `bot:` prefix, so
//! host code never asserts either as a built-in name:
//!
//! ```
//! use lepton_identity::service_users::{is_managed_service_name, ServiceUserId};
//! use valence::Actor;
//!
//! let registered = ServiceUserId::new_v4();
//! assert_eq!(ServiceUserId::from_actor(&registered.actor()), Some(registered.clone()));
//!
//! let cron = Actor::ServiceUser { service_name: "cron".into() };
//! assert_eq!(ServiceUserId::from_actor(&cron), None);
//! assert!(!is_managed_service_name("cron"));
//!
//! // The retired `bot:<uuid>` form is reserved but never recognized.
//! let legacy = Actor::ServiceUser { service_name: format!("bot:{}", registered.as_str()) };
//! assert_eq!(ServiceUserId::from_actor(&legacy), None);
//! assert!(is_managed_service_name(&format!("bot:{}", registered.as_str())));
//! ```

mod gate;
mod handle;
mod id;
mod resolve;
mod rules;

pub use gate::{
    install_service_user_gate, installed_service_user_gate, ServiceUserGate,
    ServiceUserGateAlreadyInstalled, ServiceUserGateError,
};
pub use handle::{ServiceUserHandle, ServiceUserHandleError, MAX_HANDLE_LEN, MIN_HANDLE_LEN};
pub use id::{is_managed_service_name, InvalidServiceUserId, ServiceUserId, SERVICE_USER_PREFIX};
pub use resolve::active_service_user_owner;
pub use rules::{
    ServiceUserActiveRule, ServiceUserCreateGateRule, ServiceUserIdentityImmutableRule,
    ServiceUserManageAnyRule, SERVICE_USER_ACTIVE, SERVICE_USER_CREATE_GATE,
    SERVICE_USER_IDENTITY_IMMUTABLE, SERVICE_USER_MANAGE_ANY,
};
