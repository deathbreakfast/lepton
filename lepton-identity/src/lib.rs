//! Identity Valence models and Argon2 password hashing for headless and SSR hosts.
//!
//! Generated tables (`user`, `account`, memberships, contacts, devices) ship without Leptos so
//! workers and adapters can share one schema surface. Hash passwords with [`auth::hash_password`],
//! assign signup ownership with [`ownership`], then wire sessions in
//! [`lepton_host_adapter`](../lepton_host_adapter/index.html).
//!
//! # Features
//!
//! - **Identity models** — Exposes [`generated`] Valence types for users, accounts,
//!   contacts, and devices so workers and hosts share one schema surface
//!   ([Model overview](#model-overview)).
//! - **Password hashing** — Provides Argon2 PHC strings from [`auth::hash_password`]
//!   when persisting credentials at signup or reset ([Hash a password](#hash-a-password)).
//! - **Signup ownership** — Assigns the founding user with
//!   [`ownership::ensure_signup_identity_ownership`] after anonymous signup creates
//!   bare ids ([Signup ownership](#signup-ownership)).
//! - **Product composition** — Lets a product row hop to [`generated::User`] when the
//!   schema points at Lepton `user` ([Product composition](#product-composition)).
//! - **Storage constants** — Names router logical DBs in [`embedded_surreal`] for
//!   host Valence wiring ([Model overview](#model-overview)).
//! - **Session / axum-login** — Points hosts at session boot on
//!   [`lepton_host_adapter`](../lepton_host_adapter/index.html#host-wiring) when login
//!   cookies and higgs snapshots are required.
//!
//! # Getting started
//!
//! ## Hash a password
//!
//! Provides Argon2 PHC password hashes for signup and reset so workers and SSR hosts
//! persist comparable credentials.
//!
//! Prerequisites: none beyond this crate.
//!
//! 1. Call [`auth::hash_password`] with the plaintext password.
//! 2. Persist the returned PHC string on the user row.
//! 3. Assert the string starts with `$argon2` (or verify later with Argon2).
//!
//! ```rust
//! use lepton_identity::auth::hash_password;
//!
//! let phc = hash_password("ValidPass123!").expect("hash");
//! assert!(phc.starts_with("$argon2"));
//! ```
//!
//! ## Model overview
//!
//! [`generated`] holds the Valence models (from `schemas/` via `valence_codegen`):
//!
//! - `Account` — legal identity with a required founding `user` FK (set at signup/OAuth),
//!   optional primaries, and Cascade `emails` / `phones`. Product shape today is one
//!   founding User + Owner membership.
//! - `AccountEmail` / `AccountPhone` — contacts owned by `Account` (unique `address` /
//!   `e164`, per-row `verified_at`).
//!
//! ### `AccountEmail` read privacy
//!
//! Email addresses are owner and System readable. Entity `read` uses
//! `always_allow: [SYSTEM_ONLY]` plus `defer_to_edge: "account"` (Account founding
//! user). There is no field-level read policy on `address`: Valence sync field
//! filtering does not honor field `defer_to_edge`, so a `SYSTEM_ONLY` field policy
//! would hide the address from owners who already passed entity defer.
//!
//! | Actor | `AccountEmail::get` |
//! |-------|---------------------|
//! | System | Reads address |
//! | Account owner (via Account.user) | Reads address |
//! | Other authenticated user | Denied (`Ok(None)` or Privacy error) |
//!
//! Auth flows (login, signup, reset) mint System Valence explicitly. UI labels
//! should use display name + short user id, not email, under viewer Valence.
//! Validating tests: `lepton-auth` `account_email_owner_privacy` and
//! `lepton-identity` `account_email_owner_policy_contract`.
//!
//! - `User.primary_email` / `primary_phone` — login FKs only (no email/phone collections
//!   on `User`).
//! - `AccountMembership`, `LinkedIdentity`, `AuthDevice` / `AuthDeviceCeremony` — membership,
//!   OAuth, and trusted devices.
//!
//! Password hashing: [`auth`]. Session types live in `lepton-host-adapter`. Signup ownership
//! and membership side effects: [`ownership`], [`side_effects`]. Router constants:
//! [`embedded_surreal`].
//!
//! ## Product composition
//!
//! Point a product Valence model at Lepton's `user` table with a `Record("user")` field
//! and a `HasOne` connection whose `model` is `lepton_identity::generated::User` (same
//! pattern host-adapter token schemas use). After codegen, hop with the instance method
//! `get_user(&valence)` (and `user_thing()` for the raw [`RecordId`](valence::RecordId)).
//!
//! Prerequisites: product schema codegen that emits the `get_user` hop; a loaded product
//! row and Valence handle. Errors: Valence load failures bubble from `get_user`.
//! Next: apply `OWNER_BY_USER_FIELD` when the product row is owned by that user (privacy
//! choice, separate from the hop API).
//!
//! ```rust,ignore
//! // Schema sketch (valence_schema!): FieldType::Record("user") + HasOne connection
//! // model: "lepton_identity::generated::User"
//! use valence::Valence;
//!
//! async fn load_owner(order: &Order, valence: &Valence) -> valence::Result<()> {
//!     let user = order.get_user(valence).await?;
//!     let expected = "user:demo";
//!     assert_eq!(user.id().to_string(), expected);
//!     Ok(())
//! }
//! ```
//!
//! ## Signup ownership
//!
//! After anonymous signup creates bare user and account ids, call
//! [`ownership::ensure_signup_identity_ownership`] so the founding user owns the account.
//! On success the function returns `Ok(())`; Valence errors surface as
//! [`valence::Result`].
//!
//! Prerequisites: bare user and account ids already inserted. Next: continue signup
//! confirmation / session creation in the host.
//!
//! ```rust,no_run
//! use lepton_identity::ownership::ensure_signup_identity_ownership;
//! use valence::Valence;
//!
//! async fn after_signup(valence: &Valence, user_bare: &str, account_bare: &str) -> valence::Result<()> {
//!     let result = ensure_signup_identity_ownership(valence, user_bare, account_bare, &[]).await;
//!     assert!(matches!(result, Ok(())));
//!     result
//! }
//! ```
//!
//! # Feature flags
//!
//! | Feature | Engine id on [`embedded_surreal::IDENTITY_DEFAULT_STORAGE`] |
//! |---------|--------------------------------------------------------------|
//! | `db-sqlite` (default) | `valence::SQLITE_ENGINE_ID` — local / embedded `SQLite` |
//! | `db-hybrid` | `valence::HYBRID_ENGINE_ID` — host router with mixed backends |
//! | `test-utils` | Fault-injection hooks for side-effect contract tests |
//!
//! Pick one storage feature per binary. Worker crates that only need models can disable
//! default features and omit both when they do not open Valence storage.
//!
//! # Further reading
//!
//! - [Hash a password](#hash-a-password) / [Product composition](#product-composition) / [Signup ownership](#signup-ownership)
//! - [`generated`] — Valence identity models
//! - [`auth::hash_password`] — Argon2 PHC helper
//! - [`ownership`] / [`side_effects`] — signup ownership and mutation hooks
//! - [`lepton_host_adapter`](../lepton_host_adapter/index.html) — axum-login session bridge

/// Argon2 password hashing shared by SSR and worker crates.
pub mod auth;
/// Logical database name/storage constants for identity schemas.
pub mod embedded_surreal;
/// Build-generated Valence models for identity tables (see the [crate-level
/// overview](self)).
pub mod generated;
/// Signup-time row ownership assignment for identity models.
pub mod ownership;
/// Valence mutation side effects for identity models.
pub mod side_effects;

mod schemas;
