//! Bot accounts: non-human accounts owned by a user.
//!
//! A bot has its own [`BotId`] and acts in Valence as
//! `Actor::ServiceUser { service_name: "bot:<id>" }`, so audit rows and privacy
//! checks name the bot, not the person who owns it. Its profile lives in the
//! `bot` table ([`generated::Bot`](crate::generated::Bot)): owner, a
//! [`BotHandle`] such as `spectra-bot`, display name, description, and status
//! (`active` or `suspended`).
//!
//! The owner can edit, suspend, resume, and delete the bot. A bot never manages
//! itself, and it gains no permissions just by existing. Deleting the owner's
//! user deletes their bots.
//!
//! Who may create bots, and who may manage every bot, is a host decision made by a
//! [`BotGate`] installed once at boot. Until one is installed, nobody can create bots
//! and nobody can manage bots they do not own. The crate root walks through it:
//! [Install the bot gate](crate#install-the-bot-gate).
//!
//! # Privacy
//!
//! | Actor | Read | Create | Update / suspend | Delete |
//! |-------|------|--------|------------------|--------|
//! | Owner | own bots | when the gate allows | own bots | own bots |
//! | Gate's manage-any user | all bots | own bots, when allowed | all bots | all bots |
//! | Other user | nothing | own bots, when allowed | nothing | nothing |
//! | Bot or other service user | nothing | nothing | nothing | nothing |
//! | System | all | nothing | all | all |
//!
//! Nobody can change a bot's owner, creator, or handle after creation
//! ([`BOT_IDENTITY_IMMUTABLE`]).
//!
//! The lifecycle calls (create, suspend, delete, …) are in `lepton_auth::bots`.

mod gate;
mod handle;
mod id;
mod rules;

pub use gate::{
    install_bot_gate, installed_bot_gate, BotGate, BotGateAlreadyInstalled, BotGateError,
};
pub use handle::{BotHandle, BotHandleError, MAX_HANDLE_LEN, MIN_HANDLE_LEN};
pub use id::{BotId, InvalidBotId, BOT_SERVICE_PREFIX};
pub use rules::{
    BotCreateGateRule, BotIdentityImmutableRule, BotManageAnyRule, BOT_CREATE_GATE,
    BOT_IDENTITY_IMMUTABLE, BOT_MANAGE_ANY,
};
