//! Password-reset token seed helpers.

use chrono::{Duration, Utc};
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::PasswordResetToken;
use valence::{Model, RecordId, Valence};

use crate::error::SeedError;

pub(super) async fn seed_reset_token(
    valence: &Valence,
    user_id: &RecordId,
) -> Result<String, SeedError> {
    let token_id = lepton_auth::security::random_token_part(16);
    let secret_hash = hash_password(&token_id).map_err(|_| SeedError::Crypto {
        operation: "hash_reset_token",
    })?;
    let token = PasswordResetToken::new(
        user_id.clone(),
        secret_hash,
        Utc::now() + Duration::minutes(30),
        None,
        Utc::now(),
    )
    .map_err(|_| SeedError::Persistence {
        operation: "reset_token_new",
    })?;
    PasswordResetToken::upsert_used(&token_id, token, valence, valence::use_!("upsert PasswordResetToken in src/builder/reset.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| SeedError::Persistence {
            operation: "reset_token_upsert",
        })?;
    Ok(token_id)
}
