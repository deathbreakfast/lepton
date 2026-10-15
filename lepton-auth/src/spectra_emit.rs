//! Best-effort Spectra auth funnel counters (`feature = "spectra"`).
//!
//! Ops-id labels only — never pass emails, phones, passwords, OTPs, tokens, or
//! free-form error text into these helpers.
//!
//! Some helpers are only called from feature-gated call sites (`totp`, `email`, …);
//! keep them available whenever `spectra` is on.
#![allow(dead_code)]

use lepton_spectra_telemetry::{
    log_auth_failure, record_account, record_bot, record_contact, record_device,
    record_identity_delete, record_oauth, record_password_reset, record_signin, record_signup,
    record_step_up, record_totp, record_verify, AuthFailureFlow,
};

pub use lepton_spectra_telemetry::{
    AccountOperation, AuthFactor, AuthOutcome, BotOperation, ContactOperation, DeviceKind,
    DeviceOperation, IdentityDeleteOperation, OAuthIntentLabel, OAuthProviderLabel, OAuthStage,
    PasswordResetStage, SigninStage, StepUpPath, TotpOperation, VerifyChannel, VerifyStage,
};

pub fn signup(ok: bool, error_class: &'static str) {
    if ok {
        record_signup(AuthOutcome::Success, "none");
    } else {
        record_signup(AuthOutcome::Failure, error_class);
        log_auth_failure(AuthFailureFlow::Signup, "signup", error_class, None, None);
    }
}

pub fn signin(
    stage: SigninStage,
    outcome: AuthOutcome,
    error_class: &'static str,
    factor: AuthFactor,
) {
    record_signin(stage, outcome, error_class, factor);
    if matches!(outcome, AuthOutcome::Failure) {
        log_auth_failure(
            AuthFailureFlow::Signin,
            stage.as_str(),
            error_class,
            None,
            None,
        );
    }
}

pub fn oauth(
    provider: OAuthProviderLabel,
    intent: OAuthIntentLabel,
    stage: OAuthStage,
    outcome: AuthOutcome,
    error_class: &'static str,
) {
    record_oauth(provider, intent, stage, outcome, error_class);
    if matches!(outcome, AuthOutcome::Failure) {
        log_auth_failure(
            AuthFailureFlow::Oauth,
            stage.as_str(),
            error_class,
            Some(provider.as_str()),
            None,
        );
    }
}

pub fn verify(
    channel: VerifyChannel,
    stage: VerifyStage,
    outcome: AuthOutcome,
    error_class: &'static str,
) {
    record_verify(channel, stage, outcome, error_class);
    if matches!(outcome, AuthOutcome::Failure) {
        log_auth_failure(
            AuthFailureFlow::Verify,
            stage.as_str(),
            error_class,
            None,
            Some(channel.as_str()),
        );
    }
}

pub fn password_reset(stage: PasswordResetStage, outcome: AuthOutcome, error_class: &'static str) {
    record_password_reset(stage, outcome, error_class);
    if matches!(outcome, AuthOutcome::Failure) {
        log_auth_failure(
            AuthFailureFlow::PasswordReset,
            stage.as_str(),
            error_class,
            None,
            None,
        );
    }
}

pub fn totp(operation: TotpOperation, outcome: AuthOutcome, error_class: &'static str) {
    record_totp(operation, outcome, error_class);
    if matches!(outcome, AuthOutcome::Failure) {
        log_auth_failure(
            AuthFailureFlow::Totp,
            operation.as_str(),
            error_class,
            None,
            Some("totp"),
        );
    }
}

pub fn device(
    kind: DeviceKind,
    operation: DeviceOperation,
    outcome: AuthOutcome,
    error_class: &'static str,
) {
    record_device(kind, operation, outcome, error_class);
    if matches!(outcome, AuthOutcome::Failure) {
        log_auth_failure(
            AuthFailureFlow::Device,
            operation.as_str(),
            error_class,
            None,
            None,
        );
    }
}

pub fn contact(
    channel: VerifyChannel,
    operation: ContactOperation,
    outcome: AuthOutcome,
    error_class: &'static str,
) {
    record_contact(channel, operation, outcome, error_class);
    if matches!(outcome, AuthOutcome::Failure) {
        log_auth_failure(
            AuthFailureFlow::Contact,
            operation.as_str(),
            error_class,
            None,
            Some(channel.as_str()),
        );
    }
}

pub fn account(operation: AccountOperation, outcome: AuthOutcome, error_class: &'static str) {
    record_account(operation, outcome, error_class);
    if matches!(outcome, AuthOutcome::Failure) {
        log_auth_failure(
            AuthFailureFlow::Account,
            operation.as_str(),
            error_class,
            None,
            None,
        );
    }
}

pub fn identity_delete(
    operation: IdentityDeleteOperation,
    outcome: AuthOutcome,
    error_class: &'static str,
) {
    record_identity_delete(operation, outcome, error_class);
    if matches!(outcome, AuthOutcome::Failure) {
        log_auth_failure(
            AuthFailureFlow::IdentityDelete,
            operation.as_str(),
            error_class,
            None,
            None,
        );
    }
}

pub fn step_up(path: StepUpPath, outcome: AuthOutcome, error_class: &'static str) {
    record_step_up(path, outcome, error_class);
    if matches!(outcome, AuthOutcome::Failure) {
        log_auth_failure(AuthFailureFlow::StepUp, "step_up", error_class, None, None);
    }
}

/// Map oauth provider enum to Spectra label.
#[must_use]
pub const fn oauth_provider_label(provider: crate::oauth::OAuthProvider) -> OAuthProviderLabel {
    match provider {
        crate::oauth::OAuthProvider::Google => OAuthProviderLabel::Google,
        crate::oauth::OAuthProvider::GitHub => OAuthProviderLabel::Github,
    }
}

/// Map oauth intent to Spectra label.
#[must_use]
pub const fn oauth_intent_label(intent: crate::oauth::OAuthIntent) -> OAuthIntentLabel {
    match intent {
        crate::oauth::OAuthIntent::Login => OAuthIntentLabel::Login,
        crate::oauth::OAuthIntent::Signup => OAuthIntentLabel::Signup,
        crate::oauth::OAuthIntent::Link => OAuthIntentLabel::Link,
    }
}

/// Bot lifecycle counter; `error_class` is `"none"` on success.
pub fn bot(operation: BotOperation, error_class: &'static str) {
    let outcome = if error_class == "none" {
        AuthOutcome::Success
    } else {
        AuthOutcome::Failure
    };
    record_bot(operation, outcome, error_class);
}
