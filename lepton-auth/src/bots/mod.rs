//! Bot accounts: create, edit, suspend, resume, and delete.
//!
//! A bot is a non-human account owned by a user. It has its own id and acts in
//! Valence as its own service actor, so what it does is attributed to the bot,
//! not to the person who owns it. Model, handle rules, and the host gate live in
//! [`lepton_identity::bots`].
//!
//! Every call takes the **request** Valence (`ctx.valence()` after
//! [`require_auth_user`](crate::require_auth_user)); the caller must be a
//! signed-in user. Owners manage their own bots, and users the host's
//! [`BotGate`](lepton_identity::bots::BotGate) grants manage-any can manage
//! every bot. Nobody else can see a bot: they get [`BotError::NotFound`].
//!
//! The crate root walks through the full lifecycle with an example:
//! [Create and manage a bot](crate#create-and-manage-a-bot).
//!
//! # Handle clashes
//!
//! Handles are pseudo-unique. When another bot already uses the handle (ignoring
//! case and dashes), [`create_bot`] fails with [`BotError::HandleTaken`] and a
//! free suggestion such as `spectra-2-bot`. [`suggest_bot_handle`] turns free
//! text into a free handle before the form is submitted.
//!
//! # Limit per owner
//!
//! One owner can have at most [`MAX_BOTS_PER_OWNER`] bots, active or suspended.
//! [`create_bot`] fails with [`BotError::QuotaReached`] past that; deleting a bot
//! frees its slot at once.
//!
//! # Deletion
//!
//! [`delete_bot`] uses the standard Valence delete: the bot disappears from reads
//! at once, and the deletion run the host's dispatcher starts (valence-platform's
//! Chronon deletion orchestrator) removes the row. Deleting the owner's user
//! ([`identity_delete`](crate::identity_delete)) deletes their bots too.

mod api;
pub(crate) mod erase;
mod error;
mod handle_lookup;

pub use api::{
    create_bot, delete_bot, get_bot, list_my_bots, resume_bot, suggest_bot_handle, suspend_bot,
    update_bot, BotProfileUpdate, NewBot, MAX_BOTS_PER_OWNER,
};
pub use error::BotError;
