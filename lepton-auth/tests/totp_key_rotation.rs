//! TOTP key rotation: an authenticator enrolled under an old seal-key version keeps
//! verifying after the key rotates, and the row re-seals under the new current key.
//!
//! Own test binary: it installs the process-wide key ring.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_auth::security::random_token_part;
use lepton_auth::step_up::{verify_code_against_factor, StepUpError};
use lepton_auth::totp::key_ring::{clear_key_ring, install_key_ring, TotpKeyRing};
use lepton_auth::totp::{envelope_key_version, seal_totp_secret};
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{TotpFactor, User, UserStatus, UserUserType};
use support::system_valence;
use totp_rs::{Algorithm, Secret, TOTP};
use valence::{Model, RecordId};

/// The key ring is process-wide, so the tests in this binary take turns.
static RING_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn ring(current: u32, versions: &[u32]) -> TotpKeyRing {
    TotpKeyRing::new(
        current,
        versions
            .iter()
            .map(|v| (*v, [u8::try_from(*v).unwrap() + 40; 32])),
    )
    .expect("ring")
}

async fn seed_user(valence: &valence::Valence) -> RecordId {
    let now = Utc::now();
    let user = User::new(
        Some(UserUserType::Person),
        Some(hash_password("CorrectHorseBattery1!").expect("hash")),
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
    User::create(user, valence, valence::use_!(r"**Test:** Fixture **User** save for `tests` so the suite can seed a signed-in user to verify key rotation against. CI and developers running the suite only."))
        .await
        .expect("create user")
        .id()
        .cloned()
        .expect("user id")
}

async fn seed_factor(
    valence: &valence::Valence,
    user: &RecordId,
    sealed: String,
) -> (String, TotpFactor) {
    let now = Utc::now();
    let id = random_token_part(12);
    let factor = TotpFactor::new(
        user.clone(),
        sealed,
        None,
        None,
        None,
        Some(now),
        Some(now),
        now,
        now,
    )
    .expect("factor");
    TotpFactor::upsert(&id, factor, valence, valence::use_!(r"**Test:** Fixture **Totp Factor** save for `tests` so the suite can seed an enabled factor to rotate the seal key under. CI and developers running the suite only."))
        .await
        .expect("upsert");
    let loaded = reload(valence, &id).await;
    (id, loaded)
}

async fn reload(valence: &valence::Valence, id: &str) -> TotpFactor {
    TotpFactor::get(id, valence, valence::use_!(r"**Test:** Fixture **Totp Factor** reload for `tests` so the suite can assert the stored seal after key rotation. CI and developers running the suite only."))
        .await
        .expect("get")
        .expect("present")
}

fn code_at(t: u64) -> String {
    let secret = Secret::Encoded(SECRET_B32.to_string()).to_bytes().unwrap();
    TOTP::new(Algorithm::SHA1, 6, 1, 30, secret)
        .unwrap()
        .generate(t)
}

#[tokio::test]
async fn code_verifies_and_reseals_after_key_rotation_happy() {
    let _turn = RING_LOCK.lock().await;
    install_key_ring(ring(1, &[1]));
    let valence = system_valence("totp_rotation_reseal").await;
    let user = seed_user(&valence).await;
    let sealed = seal_totp_secret(SECRET_B32).expect("seal");
    assert_eq!(envelope_key_version(&sealed), Some(1));
    let (id, factor) = seed_factor(&valence, &user, sealed.clone()).await;

    // Rotate: version 2 becomes current, version 1 stays in the ring.
    install_key_ring(ring(2, &[1, 2]));

    let now = Utc::now();
    let code = code_at(now.timestamp().cast_unsigned());
    verify_code_against_factor(&valence, &factor, &code, now)
        .await
        .expect("existing authenticator still verifies");

    let after = reload(&valence, &id).await;
    assert_eq!(envelope_key_version(after.secret_sealed()), Some(2));
    assert_ne!(after.secret_sealed(), &sealed);

    // The re-sealed row keeps working in a later step.
    let later = now + chrono::Duration::seconds(30);
    let code = code_at(later.timestamp().cast_unsigned());
    verify_code_against_factor(&valence, &after, &code, later)
        .await
        .expect("verifies after re-seal");
    assert_eq!(
        envelope_key_version(reload(&valence, &id).await.secret_sealed()),
        Some(2)
    );
    clear_key_ring();
}

#[tokio::test]
async fn dropped_key_version_fails_closed_and_leaves_row_sad() {
    let _turn = RING_LOCK.lock().await;
    install_key_ring(ring(1, &[1]));
    let valence = system_valence("totp_rotation_dropped").await;
    let user = seed_user(&valence).await;
    let sealed = seal_totp_secret(SECRET_B32).expect("seal");
    let (id, factor) = seed_factor(&valence, &user, sealed.clone()).await;

    // A ring that no longer holds version 1 cannot open the row.
    install_key_ring(ring(3, &[3]));

    let now = Utc::now();
    let code = code_at(now.timestamp().cast_unsigned());
    let err = verify_code_against_factor(&valence, &factor, &code, now)
        .await
        .expect_err("unknown key version");
    assert!(matches!(err, StepUpError::TotpSecret));
    assert_eq!(reload(&valence, &id).await.secret_sealed(), &sealed);
    clear_key_ring();
}
