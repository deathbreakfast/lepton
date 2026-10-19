//! Service user test fixtures: a prefix-based `ServiceUserGate` and seeded users and service users.

#![allow(dead_code, clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Once};

use async_trait::async_trait;
use chrono::Utc;
use lepton_auth::service_users::{create_service_user, NewServiceUser};
use lepton_host_adapter::generated::{ServiceUserAccount, User, UserStatus, UserUserType};
use lepton_identity::service_users::{
    install_service_user_gate, ServiceUserGate, ServiceUserGateError, ServiceUserId,
};
use valence::{Model, Valence};

use crate::support::user_valence;

/// Users whose id starts with this may create service users.
pub const MAKER: &str = "maker";
/// Users whose id starts with this may create service users and manage every service user.
pub const SUPER: &str = "super";
/// The gate errors for users whose id starts with this.
pub const GATE_FAILS: &str = "gatefail";

/// Decides from the user id prefix, so parallel tests share one installed gate.
struct PrefixGate;

fn user_id(v: &Valence) -> String {
    let id = v.actor().user_id().unwrap_or_default();
    id.split_once(':').map_or(id, |(_, bare)| bare).to_string()
}

#[async_trait]
impl ServiceUserGate for PrefixGate {
    async fn may_create_service_user(&self, v: &Valence) -> Result<bool, ServiceUserGateError> {
        let id = user_id(v);
        if id.starts_with(GATE_FAILS) {
            return Err(ServiceUserGateError {
                reason_class: "store",
            });
        }
        Ok(id.starts_with(MAKER) || id.starts_with(SUPER))
    }

    async fn may_manage_any_service_user(&self, v: &Valence) -> Result<bool, ServiceUserGateError> {
        let id = user_id(v);
        if id.starts_with(GATE_FAILS) {
            return Err(ServiceUserGateError {
                reason_class: "store",
            });
        }
        Ok(id.starts_with(SUPER))
    }
}

/// Install [`PrefixGate`] once per test binary.
pub fn install_test_gate() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        install_service_user_gate(Arc::new(PrefixGate)).expect("first gate install in this binary");
    });
}

/// **Test:** seed an active person user with a chosen id (System fixture only).
pub async fn seed_user(system: &Valence, id: &str) {
    let now = Utc::now();
    let user = User::new(
        Some(UserUserType::Person),
        None,
        Some(UserStatus::Active),
        None,
        None,
        None,
        None,
        None,
        now,
        now,
    )
    .expect("user");
    User::upsert(id, user, system, valence::use_!(r"**Test:** Fixture **User** save for `service_users` tests so the suite can create service users owned by a known user id. CI and developers running the suite only."))
        .await
        .expect("seed user");
}

/// Seed `owner` and create one service user through the service as that owner.
pub async fn seed_service_user(
    system: &Valence,
    owner: &str,
    handle: &str,
) -> (Valence, ServiceUserId, ServiceUserAccount) {
    seed_user(system, owner).await;
    let owner_v = user_valence(system, owner);
    let service_user = create_service_user(
        &owner_v,
        NewServiceUser {
            handle,
            display_name: "Test service user",
            description: Some("Fixture"),
        },
    )
    .await
    .expect("owner creates service user");
    let id = ServiceUserId::parse(service_user.id().expect("id").id()).expect("service user id");
    (owner_v, id, service_user)
}

/// **Test:** raw stored row, bypassing privacy, to assert what actually persisted.
pub async fn stored_service_user(
    system: &Valence,
    id: &ServiceUserId,
) -> Option<serde_json::Value> {
    let backend = system
        .backend_for_table("service_user_account")
        .expect("backend");
    valence::get_record(backend.as_ref(), "service_user_account", id.as_str(), valence::use_!(r"**Test:** Fixture read of a **service user** row for `service_users` tests so the suite can assert what was stored, independent of privacy. CI and developers running the suite only."))
        .await
        .expect("raw read")
}

/// **Test:** number of stored `service_user_account` rows owned by `owner`.
pub async fn stored_service_user_count(system: &Valence, owner: &str) -> usize {
    ServiceUserAccount::get_from_user_id(owner, system, valence::use_!(r"**Test:** Fixture count of **service users** per owner for `service_users` tests so the suite can assert creates and deletes. CI and developers running the suite only."))
        .await
        .expect("count")
        .len()
}
