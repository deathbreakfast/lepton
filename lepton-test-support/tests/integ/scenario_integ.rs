//! Scenario catalog integration tests (TM-3, TM-4).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use lepton_e2e::boot::boot_valence;
use lepton_test_support::http::SeedRequest;
use lepton_test_support::scenario::{
    run_seed, AUTH_BASIC_USER, AUTH_RESET_TOKEN, AUTH_USER_WITH_TOTP,
};
use lepton_test_support::SeedError;

#[tokio::test]
async fn scenario_unknown_sad() {
    let v = boot_valence("scenario_unknown").await.expect("boot");
    let err = run_seed(
        &v,
        SeedRequest {
            scenario: "not_a_real_scenario".into(),
            email: None,
            password: None,
        },
    )
    .await
    .expect_err("unknown");
    match err {
        SeedError::UnknownScenario { scenario } => {
            assert_eq!(scenario, "not_a_real_scenario");
        }
        other => panic!("expected UnknownScenario, got {other:?}"),
    }
}

#[tokio::test]
async fn scenario_catalog_shape_happy() {
    let v = boot_valence("scenario_shapes").await.expect("boot");

    let basic = run_seed(
        &v,
        SeedRequest {
            scenario: AUTH_BASIC_USER.into(),
            email: Some("basic@example.test".into()),
            password: None,
        },
    )
    .await
    .expect("basic");
    assert_eq!(basic.scenario, AUTH_BASIC_USER);
    assert_eq!(basic.email, "basic@example.test");
    assert!(!basic.password.is_empty());
    assert!(basic.reset_token.is_none());
    assert!(basic.totp_secret.is_none());

    let reset = run_seed(
        &v,
        SeedRequest {
            scenario: AUTH_RESET_TOKEN.into(),
            email: Some("reset-shape@example.test".into()),
            password: Some("CorrectHorseBattery1!".into()),
        },
    )
    .await
    .expect("reset");
    assert!(reset.reset_token.is_some());
    assert!(reset.totp_secret.is_none());

    let totp = run_seed(
        &v,
        SeedRequest {
            scenario: AUTH_USER_WITH_TOTP.into(),
            email: Some("totp-shape@example.test".into()),
            password: None,
        },
    )
    .await
    .expect("totp");
    assert!(totp.totp_secret.is_some());
    assert!(totp.reset_token.is_none());
}
