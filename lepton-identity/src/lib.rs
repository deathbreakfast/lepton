//! Identity Valence models and Argon2 password hashing for headless and SSR hosts.
//!
//! Generated tables (`user`, `account`, memberships, contacts, devices, bots) ship without Leptos so
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
//! - **Bot accounts** — Gives a user non-human accounts they own. Each bot acts in Valence
//!   as its own service actor, so what it does is attributed to the bot, and the host
//!   decides who may create bots ([Install the bot gate](#install-the-bot-gate)).
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
//! ## Install the bot gate
//!
//! A bot is a non-human account that a user owns. The bot gate is the host's answer to two
//! questions: who may create bots, and who may manage every bot whoever owns it (usually
//! super users). Install it once at host boot, before serving requests; until a gate is
//! installed, nobody can create bots and nobody can manage a bot they do not own. Valence
//! consults the gate on every write to the `bot` table, so server functions, background
//! tasks, and scheduled jobs all get the same answer.
//!
//! Prerequisites: a Valence handle per request whose actor is the signed-in user. A gate
//! that reads permission tables must use raw backend reads, since it runs inside privacy
//! checks, and must never switch the caller to `Actor::System`.
//!
//! 1. Implement [`bots::BotGate`]: `may_create_bot` and `may_manage_any_bot`, both reading
//!    the caller from `valence.actor()`.
//! 2. Call [`bots::install_bot_gate`] once at boot. A second call returns
//!    [`bots::BotGateAlreadyInstalled`] and keeps the first gate.
//! 3. Create and manage bots through `lepton_auth::bots` with the request Valence.
//!
//! Hosts that use Gauge don't need to write a gate: `gauge::bots::GaugeBotGate` answers from
//! the `lepton.bot.create` and `lepton.bot.manage_any` permissions and a seeded "Bot
//! creators" group. The example below is a hand-written gate for a host without Gauge.
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use lepton_identity::bots::{install_bot_gate, installed_bot_gate, BotGate, BotGateError};
//! use valence::Valence;
//!
//! /// Named users may create bots; nobody manages other people's bots.
//! struct BotCreators(Vec<String>);
//!
//! #[async_trait::async_trait]
//! impl BotGate for BotCreators {
//!     async fn may_create_bot(&self, v: &Valence) -> Result<bool, BotGateError> {
//!         Ok(v.actor().user_id().is_some_and(|id| self.0.iter().any(|c| c == id)))
//!     }
//!     async fn may_manage_any_bot(&self, _v: &Valence) -> Result<bool, BotGateError> {
//!         Ok(false)
//!     }
//! }
//!
//! install_bot_gate(Arc::new(BotCreators(vec!["alice".into()]))).expect("first install");
//! assert!(installed_bot_gate().is_some());
//! assert!(install_bot_gate(Arc::new(BotCreators(vec![]))).is_err());
//! ```
//!
//! A bot acts as `Actor::ServiceUser { service_name: "bot:<id>" }`; [`bots::BotId`] builds
//! and parses that actor, and [`bots::BotHandle`] validates handles such as `spectra-bot`.
//! Bot and service-user actors pass none of the bot rules, so a bot never manages itself.
//! Next: create and manage bots with `lepton_auth::bots`
//! ([Create and manage a bot](../lepton_auth/index.html#create-and-manage-a-bot)).
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
//! - `Bot` — a bot account: owner (`user`), handle, display name, description, and status
//!   (`active` / `suspended`). Only the owner, and users the bot gate lets manage any bot,
//!   can read or change it. Owner, creator, and handle never change after creation, and
//!   deleting the owner's user deletes their bots ([`bots`]).
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
//! Prerequisites: product schema codegen that emits the `get_user_used` hop; a loaded product
//! row and Valence handle. Errors: Valence load failures bubble from `get_user_used`.
//! Next: apply `OWNER_BY_USER_FIELD` when the product row is owned by that user (privacy
//! choice, separate from the hop API).
//!
//! ```rust,ignore
//! // Schema sketch (valence_schema!): FieldType::Record("user") + HasOne connection
//! // model: "lepton_identity::generated::User"
//! use valence::Valence;
//!
//! async fn load_owner(order: &Order, valence: &Valence) -> valence::Result<()> {
//!     let user = order
//!         .get_user(
//!             valence,
//!             valence::use_!(r#"In this **docs example**, we **follow the order’s user link** so the sample can show how product rows load their owner. Readers of the crate docs only."#),
//!         )
//!         .await?;
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
//! - [`bots`] — bot ids, handles, the bot gate, and the `bot` table's privacy rules
//! - [`lepton_host_adapter`](../lepton_host_adapter/index.html) — axum-login session bridge

/// Argon2 password hashing shared by SSR and worker crates.
pub mod auth;
/// Bot accounts: ids, handles, the host bot gate, and `bot` table privacy rules.
pub mod bots;
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
