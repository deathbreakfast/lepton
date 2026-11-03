//! Validating auth funnel counters and failure events against in-memory Spectra.
//!
//! Runs on the shared runtime in `spectra_rt`, which owns the process-global Spectra sink.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::spectra_rt::{block_on, metric_points, spectra};
use lepton_spectra_telemetry::{
    log_auth_failure, record_account, record_contact, record_device, record_identity_delete,
    record_oauth, record_password_reset, record_service_user, record_signin, record_signup,
    record_step_up, record_totp, record_verify, AccountOperation, AuthFactor, AuthFailureFlow,
    AuthOutcome, ContactOperation, DeviceKind, DeviceOperation, IdentityDeleteOperation,
    OAuthIntentLabel, OAuthProviderLabel, OAuthStage, PasswordResetStage, ServiceUserOperation,
    SigninStage, StepUpPath, TotpOperation, VerifyChannel, VerifyStage,
};
use spectra::SchemaRegistry;

async fn assert_metric_bumped(name: &str, emit: impl FnOnce()) {
    let before = metric_points(name).await;
    emit();
    let after = metric_points(name).await;
    assert!(
        after > before,
        "expected {name} points to increase (before={before}, after={after})"
    );
}

#[test]
#[allow(clippy::too_many_lines)] // one serial test covers the full auth catalog
fn auth_catalog_with_mem_spectra_happy() {
    block_on(async {
        let _ = spectra();

        let registry = SchemaRegistry::auto_discover();
        for name in [
            "lepton_signup",
            "lepton_signin",
            "lepton_oauth",
            "lepton_verify",
            "lepton_password_reset",
            "lepton_totp",
            "lepton_device",
            "lepton_contact",
            "lepton_account",
            "lepton_identity_delete",
            "lepton_step_up",
            "lepton_service_user",
            "lepton_auth_failure",
            "lepton_email_send",
            "lepton_sms_send",
        ] {
            assert!(
                registry.has_schema(name),
                "{name} must register via inventory; have {:?}",
                registry.list_schemas()
            );
        }

        assert_metric_bumped("lepton_signup", || {
            record_signup(AuthOutcome::Success, "none");
        })
        .await;
        assert_metric_bumped("lepton_signin", || {
            record_signin(
                SigninStage::Password,
                AuthOutcome::NeedsMfa,
                "none",
                AuthFactor::None,
            );
        })
        .await;
        assert_metric_bumped("lepton_oauth", || {
            record_oauth(
                OAuthProviderLabel::Mock,
                OAuthIntentLabel::Login,
                OAuthStage::Complete,
                AuthOutcome::Success,
                "none",
            );
        })
        .await;
        assert_metric_bumped("lepton_verify", || {
            record_verify(
                VerifyChannel::Email,
                VerifyStage::Consume,
                AuthOutcome::Success,
                "none",
            );
        })
        .await;
        assert_metric_bumped("lepton_password_reset", || {
            record_password_reset(PasswordResetStage::Request, AuthOutcome::Success, "none");
        })
        .await;
        assert_metric_bumped("lepton_totp", || {
            record_totp(TotpOperation::ConfirmEnroll, AuthOutcome::Success, "none");
        })
        .await;
        assert_metric_bumped("lepton_device", || {
            record_device(
                DeviceKind::TrustedBrowser,
                DeviceOperation::Confirm,
                AuthOutcome::Success,
                "none",
            );
        })
        .await;
        assert_metric_bumped("lepton_contact", || {
            record_contact(
                VerifyChannel::Email,
                ContactOperation::Add,
                AuthOutcome::Success,
                "none",
            );
        })
        .await;
        assert_metric_bumped("lepton_account", || {
            record_account(AccountOperation::Logout, AuthOutcome::Success, "none");
        })
        .await;
        assert_metric_bumped("lepton_identity_delete", || {
            record_identity_delete(
                IdentityDeleteOperation::EraseAccount,
                AuthOutcome::Success,
                "none",
            );
        })
        .await;
        assert_metric_bumped("lepton_step_up", || {
            record_step_up(StepUpPath::Totp, AuthOutcome::Success, "none");
        })
        .await;
        assert_metric_bumped("lepton_service_user", || {
            record_service_user(ServiceUserOperation::Create, AuthOutcome::Success, "none");
        })
        .await;
        assert_metric_bumped("lepton_service_user", || {
            record_service_user(
                ServiceUserOperation::Create,
                AuthOutcome::Failure,
                "handle_taken",
            );
        })
        .await;

        log_auth_failure(AuthFailureFlow::Signup, "signup", "validation", None, None);
    });
}
