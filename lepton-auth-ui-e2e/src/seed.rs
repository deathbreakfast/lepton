//! Thin mount of [`lepton_test_support`] seed HTTP for Playwright.
//!
//! Domain logic lives in `lepton-test-support`. Do not mount this route on
//! production product hosts.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use lepton_auth::service_users::{create_service_user, NewServiceUser};
use lepton_test_support::{
    seed_error_status, SeedError, SeedValence, TestUserBuilder, DEFAULT_PASSWORD,
};
use serde::{Deserialize, Serialize};
use valence::{Actor, Valence};

use crate::boot::{system_valence, AppState};
use crate::service_user_gate::allow_manage_any;

pub use lepton_test_support::{seed_data, SeedRequest, SeedResponse};

impl SeedValence for AppState {
    fn seed_valence(&self) -> Result<Valence, SeedError> {
        system_valence(Arc::clone(&self.valence_router), &self.default_backend_key).map_err(|_| {
            SeedError::Persistence {
                operation: "system_valence",
            }
        })
    }
}

/// One owner and the service users to create for them.
#[derive(Debug, Deserialize)]
pub struct SeedServiceUserOwner {
    /// Owner sign-in email.
    pub email: String,
    /// Handles of the service users the owner creates.
    pub handles: Vec<String>,
}

/// Body of `POST /api/test/seed-service-users`.
#[derive(Debug, Deserialize)]
pub struct SeedServiceUsersRequest {
    /// Email of a seeded user the gate grants manage-any.
    pub admin_email: String,
    /// Owners to seed, each with their service users.
    pub owners: Vec<SeedServiceUserOwner>,
}

/// Response of `POST /api/test/seed-service-users`.
#[derive(Debug, Serialize)]
pub struct SeedServiceUsersResponse {
    /// Plaintext password every seeded user signs in with.
    pub password: String,
    /// Bare user id per owner, in request order.
    pub owner_ids: Vec<String>,
}

async fn seed_user(valence: &Valence, email: &str) -> Result<String, (StatusCode, String)> {
    let seeded = TestUserBuilder::new()
        .email(email)
        .password(DEFAULT_PASSWORD)
        .verified_email()
        .build(valence)
        .await
        .map_err(|e| seed_error_status(&e))?;
    Ok(seeded.user_id.id().to_string())
}

/// `POST /api/test/seed-service-users`: seed an admin and owners with service users.
///
/// Harness only. Service users are created through the real
/// [`create_service_user`] as each owner.
///
/// # Errors
///
/// A status and opaque message when seeding a user or creating a service user fails.
pub async fn seed_service_users(
    State(state): State<AppState>,
    Json(body): Json<SeedServiceUsersRequest>,
) -> Result<Json<SeedServiceUsersResponse>, (StatusCode, String)> {
    let system = state.seed_valence().map_err(|e| seed_error_status(&e))?;
    let admin_id = seed_user(&system, &body.admin_email).await?;
    allow_manage_any(&admin_id);
    let mut owner_ids = Vec::with_capacity(body.owners.len());
    for owner in &body.owners {
        let owner_id = seed_user(&system, &owner.email).await?;
        let as_owner = system.with_actor(Actor::User {
            user_id: owner_id.clone(),
        });
        for handle in &owner.handles {
            create_service_user(
                &as_owner,
                NewServiceUser {
                    handle,
                    display_name: handle,
                    description: None,
                },
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        owner_ids.push(owner_id);
    }
    Ok(Json(SeedServiceUsersResponse {
        password: DEFAULT_PASSWORD.to_string(),
        owner_ids,
    }))
}
