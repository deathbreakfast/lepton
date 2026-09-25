//! Signup → email verify → phone verify → confirm (+ device / TOTP) orchestration.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use lepton_auth::contacts::{mark_account_email_verified, set_primary_email};
use lepton_auth::devices::{
    confirm_auth_device, list_auth_devices, register_auth_device, AuthDeviceKind,
};
use lepton_auth::factor::FactorChallengeService;
use lepton_auth::services::LeptonAuthServices;
use lepton_auth::signup_api::ssr::{create_pending_user, SignupRequest};
use lepton_auth::token_helpers::{
    ensure_token_lifecycle_valid, try_consume_email_verification_token, verify_token_secret,
};
use lepton_auth::totp::{begin_totp_enroll, confirm_totp_enroll};
use lepton_auth::trust::{confirm_user, primary_email_verified, primary_phone_verified};
use lepton_host_adapter::generated::{AccountEmail, EmailVerificationToken, User, UserStatus};
use lepton_sms::TestSmsAdapter;
use lepton_smtp::{verification_email_envelope_named, VerificationEmailFlow};
use totp_rs::{Algorithm, Secret, TOTP};
use tracing::{info, warn};
use valence::{Model, RecordId, Valence};

use crate::error::LiveVerifyError;
use crate::parse::{
    email_token_from_input, totp_manual_entry_from_otpauth_uri, totp_secret_from_otpauth_uri,
};

/// Supplies email token / SMS OTP for a flow step.
#[async_trait]
pub trait CodeSource: Send + Sync {
    /// Email verification token (bare id).
    async fn email_token(&self, issued_token_id: &str) -> Result<String, LiveVerifyError>;
    /// SMS OTP digits for `challenge_id`.
    async fn sms_otp(&self, challenge_id: &str) -> Result<String, LiveVerifyError>;
}

/// Test code source: email token from issue return; SMS OTP from [`TestSmsAdapter`].
pub struct TestCodeSource {
    test_sms: Arc<TestSmsAdapter>,
}

impl TestCodeSource {
    /// Capture OTP from the shared test SMS adapter.
    #[must_use]
    pub fn new(test_sms: Arc<TestSmsAdapter>) -> Self {
        Self { test_sms }
    }
}

#[async_trait]
impl CodeSource for TestCodeSource {
    async fn email_token(&self, issued_token_id: &str) -> Result<String, LiveVerifyError> {
        Ok(issued_token_id.to_string())
    }

    async fn sms_otp(&self, _challenge_id: &str) -> Result<String, LiveVerifyError> {
        // Durable Boson send returns before TestSmsAdapter records; poll briefly.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(last) = self.test_sms.recorded().last() {
                if let Some(otp) = parse_otp_from_sms_body(&last.body) {
                    return Ok(otp);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(LiveVerifyError::CodeSource);
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }
}

/// Stdin prompts for live operator verification.
pub struct StdinCodeSource;

#[async_trait]
impl CodeSource for StdinCodeSource {
    async fn email_token(&self, _issued_token_id: &str) -> Result<String, LiveVerifyError> {
        println!("Paste the email verification code, then press Enter:");
        let line = read_stdin_line()?;
        email_token_from_input(&line).ok_or(LiveVerifyError::CodeRejected)
    }

    async fn sms_otp(&self, _challenge_id: &str) -> Result<String, LiveVerifyError> {
        println!("Paste the SMS verification code, then press Enter:");
        let line = read_stdin_line()?;
        let code = line.trim();
        if code.is_empty() {
            return Err(LiveVerifyError::CodeRejected);
        }
        Ok(code.to_string())
    }
}

/// Supplies TOTP enroll / challenge codes (test generator or live authenticator paste).
#[async_trait]
pub trait TotpCodeSource: Send + Sync {
    /// Present the otpauth URI to the operator (no-op for test source).
    async fn present_otpauth(&self, otpauth_uri: &str) -> Result<(), LiveVerifyError>;
    /// Code used to confirm TOTP enrollment.
    async fn enroll_code(&self, otpauth_uri: &str) -> Result<String, LiveVerifyError>;
    /// Code used for the post-enroll challenge verify.
    async fn challenge_code(&self, otpauth_uri: &str) -> Result<String, LiveVerifyError>;
}

/// Test authenticator: generate codes from the otpauth secret via `totp-rs`.
pub struct TestTotpCodeSource;

#[async_trait]
impl TotpCodeSource for TestTotpCodeSource {
    async fn present_otpauth(&self, _otpauth_uri: &str) -> Result<(), LiveVerifyError> {
        Ok(())
    }

    async fn enroll_code(&self, otpauth_uri: &str) -> Result<String, LiveVerifyError> {
        test_totp_code_from_otpauth(otpauth_uri)
    }

    async fn challenge_code(&self, otpauth_uri: &str) -> Result<String, LiveVerifyError> {
        test_totp_code_from_otpauth(otpauth_uri)
    }
}

/// Live authenticator: print otpauth URI, then read enroll + challenge codes from stdin.
pub struct StdinTotpCodeSource;

#[async_trait]
impl TotpCodeSource for StdinTotpCodeSource {
    async fn present_otpauth(&self, otpauth_uri: &str) -> Result<(), LiveVerifyError> {
        use std::io::IsTerminal;

        println!();
        println!("Add this account in Google Authenticator (or another TOTP app).");
        println!();

        // The manual-entry key and otpauth URI both encode the raw TOTP shared
        // secret. Print them only when the operator explicitly opts in, and never
        // to a redirected/piped stream where they could be captured in a log.
        let reveal = matches!(
            std::env::var("UF_LEPTON_LIVE_REVEAL_SECRET")
                .ok()
                .as_deref(),
            Some("1") | Some("true") | Some("yes")
        );
        if !reveal {
            println!("The TOTP secret is hidden. To display the manual-entry key and otpauth URI,");
            println!("re-run in an interactive terminal with UF_LEPTON_LIVE_REVEAL_SECRET=1.");
            println!();
            return Ok(());
        }
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            return Err(LiveVerifyError::config(
                "UF_LEPTON_LIVE_REVEAL_SECRET=1 requires an interactive terminal; refusing to print the TOTP secret to a non-tty",
            ));
        }

        if let Some(entry) = totp_manual_entry_from_otpauth_uri(otpauth_uri) {
            println!("Manual entry (recommended):");
            println!("  1. Open the app → + → Enter a setup key");
            if !entry.issuer.is_empty() {
                println!("  2. Account name:  {} ({})", entry.account, entry.issuer);
            } else {
                println!("  2. Account name:  {}", entry.account);
            }
            println!("  3. Your key:      {}", entry.secret);
            println!("  4. Type:          Time-based");
            println!();
        }
        println!("otpauth URI (apps only — not a browser link):");
        println!("{otpauth_uri}");
        println!();
        Ok(())
    }

    async fn enroll_code(&self, _otpauth_uri: &str) -> Result<String, LiveVerifyError> {
        println!(
            "Paste the 6-digit code from your authenticator to confirm enroll, then press Enter:"
        );
        read_totp_stdin_code()
    }

    async fn challenge_code(&self, _otpauth_uri: &str) -> Result<String, LiveVerifyError> {
        println!("Paste a current 6-digit authenticator code for the challenge, then press Enter:");
        read_totp_stdin_code()
    }
}

fn read_totp_stdin_code() -> Result<String, LiveVerifyError> {
    let line = read_stdin_line()?;
    let code = line.trim();
    if code.is_empty() {
        return Err(LiveVerifyError::CodeRejected);
    }
    Ok(code.to_string())
}

/// Outcome of [`run_signup_verify_flow`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignupVerifyOutcome {
    /// Confirmed user id (for chaining device / TOTP e2e steps).
    pub user_id: RecordId,
    /// Primary email verified.
    pub email_verified: bool,
    /// Primary phone verified.
    pub phone_verified: bool,
    /// `confirm_user` succeeded.
    pub confirmed: bool,
}

/// Outcome of [`run_device_totp_challenge_flow`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceTotpOutcome {
    /// Trusted browser device id.
    pub device_id: String,
    /// Device has `trusted_at` set.
    pub device_trusted: bool,
    /// TOTP enroll confirmed (challenge verify succeeded implies enabled).
    pub totp_enabled: bool,
    /// [`FactorChallengeService::verify_totp_code`] succeeded.
    pub challenge_ok: bool,
}

/// Harness-only knobs for [`run_signup_verify_flow`] (not product auth behavior).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignupVerifyOpts {
    /// Skip live email send + stdin paste; consume the issued token immediately.
    ///
    /// Use when exercising SMS against Twilio without waiting on mailbox entry.
    pub auto_verify_email: bool,
}

/// Create a pending user, verify email + phone via `codes`, then confirm.
#[allow(clippy::too_many_arguments)]
pub async fn run_signup_verify_flow(
    valence: &Valence,
    services: &Arc<LeptonAuthServices>,
    codes: &dyn CodeSource,
    legal_name: &str,
    email: &str,
    phone_e164: &str,
    password: &str,
    opts: SignupVerifyOpts,
) -> Result<SignupVerifyOutcome, LiveVerifyError> {
    let span = tracing::info_span!("lepton_e2e.live_verify");
    let _guard = span.enter();

    info!(phase = "signup", "live_verify");
    let pending = create_pending_user(
        valence,
        SignupRequest {
            legal_name: legal_name.to_string(),
            display_name: legal_name.to_string(),
            email: email.to_string(),
            password: password.to_string(),
            confirm: password.to_string(),
        },
    )
    .await
    .map_err(|_| LiveVerifyError::Signup)?;

    if opts.auto_verify_email {
        info!(phase = "email_auto_verify", "live_verify");
        verify_email_token(valence, &pending.email_token_id).await?;
    } else {
        info!(phase = "email_issue", "live_verify");
        let envelope = verification_email_envelope_named(
            &pending.email,
            Some(pending.legal_name.as_str()),
            &pending.email_token_id,
            VerificationEmailFlow::Signup,
        );
        services.email.send(&envelope).await.map_err(|e| {
            warn!(channel = "email", reason_class = "delivery", "live_verify");
            LiveVerifyError::delivery("email", e.to_string())
        })?;

        info!(phase = "email_verify", "live_verify");
        let presented = codes.email_token(&pending.email_token_id).await?;
        verify_email_token(valence, &presented).await?;
    }

    let factors = FactorChallengeService::new(Arc::clone(services));
    info!(phase = "sms_issue", "live_verify");
    let challenge_id = factors
        .issue_sms_otp(valence, pending.user_id.clone(), phone_e164)
        .await
        .map_err(|e| {
            if e.reason_class() == "delivery" {
                warn!(channel = "sms", reason_class = "delivery", "live_verify");
                LiveVerifyError::delivery("sms", e.to_string())
            } else {
                LiveVerifyError::Token
            }
        })?;

    info!(phase = "sms_verify", "live_verify");
    let otp = codes.sms_otp(&challenge_id).await?;
    let ok = factors
        .verify_sms_otp(&challenge_id, &otp, valence)
        .await
        .map_err(|_| LiveVerifyError::Token)?;
    if !ok {
        return Err(LiveVerifyError::CodeRejected);
    }

    info!(phase = "confirm", "live_verify");
    let email_verified = primary_email_verified(valence, &pending.user_id)
        .await
        .map_err(|_| LiveVerifyError::Token)?;
    let phone_verified = primary_phone_verified(valence, &pending.user_id)
        .await
        .map_err(|_| LiveVerifyError::Token)?;
    if !email_verified || !phone_verified {
        return Err(LiveVerifyError::ConfirmBlocked);
    }
    confirm_user(valence, &pending.user_id)
        .await
        .map_err(|_| LiveVerifyError::ConfirmBlocked)?;

    info!(phase = "done", "live_verify");
    Ok(SignupVerifyOutcome {
        user_id: pending.user_id,
        email_verified,
        phone_verified,
        confirmed: true,
    })
}

/// Register a trusted browser, enroll TOTP, then verify a TOTP challenge.
///
/// Expects a confirmed user (e.g. after [`run_signup_verify_flow`]). `codes` supplies enroll /
/// challenge digits ([`TestTotpCodeSource`] or [`StdinTotpCodeSource`]).
/// `account_label` (e.g. email) and `issuer` (site/product name) appear in the otpauth URI.
pub async fn run_device_totp_challenge_flow(
    valence: &Valence,
    services: &Arc<LeptonAuthServices>,
    user: &RecordId,
    device_label: &str,
    account_label: &str,
    issuer: &str,
    codes: &dyn TotpCodeSource,
) -> Result<DeviceTotpOutcome, LiveVerifyError> {
    let span = tracing::info_span!("lepton_e2e.device_totp");
    let _guard = span.enter();

    info!(phase = "device_register", "device_totp");
    let pending_device =
        register_auth_device(valence, user, AuthDeviceKind::TrustedBrowser, device_label)
            .await
            .map_err(|e| {
                warn!(reason_class = e.reason_class(), "device_totp");
                LiveVerifyError::device(e.reason_class())
            })?;

    info!(phase = "device_confirm", "device_totp");
    confirm_auth_device(
        valence,
        user,
        &pending_device.device_id,
        &pending_device.confirm_code,
    )
    .await
    .map_err(|e| {
        warn!(reason_class = e.reason_class(), "device_totp");
        LiveVerifyError::device(e.reason_class())
    })?;

    let devices = list_auth_devices(valence, user).await.map_err(|e| {
        warn!(reason_class = e.reason_class(), "device_totp");
        LiveVerifyError::device(e.reason_class())
    })?;
    let device_trusted = devices
        .iter()
        .any(|d| d.id == pending_device.device_id && d.trusted_at.is_some());
    if !device_trusted {
        return Err(LiveVerifyError::device("device_pending"));
    }

    info!(phase = "totp_begin", "device_totp");
    let pending_totp = begin_totp_enroll(valence, user, account_label, issuer)
        .await
        .map_err(|e| {
            warn!(reason_class = e.reason_class(), "device_totp");
            LiveVerifyError::totp(e.reason_class())
        })?;

    codes.present_otpauth(&pending_totp.otpauth_uri).await?;

    info!(phase = "totp_confirm", "device_totp");
    let enroll_code = codes.enroll_code(&pending_totp.otpauth_uri).await?;
    confirm_totp_enroll(valence, user, &pending_totp.factor_id, &enroll_code)
        .await
        .map_err(|e| {
            warn!(reason_class = e.reason_class(), "device_totp");
            LiveVerifyError::totp(e.reason_class())
        })?;

    info!(phase = "totp_challenge", "device_totp");
    let challenge_code = codes.challenge_code(&pending_totp.otpauth_uri).await?;
    let factors = FactorChallengeService::new(Arc::clone(services));
    factors
        .verify_totp_code(valence, user, &challenge_code)
        .await
        .map_err(|e| {
            warn!(reason_class = e.reason_class(), "device_totp");
            LiveVerifyError::totp(e.reason_class())
        })?;

    info!(phase = "done", "device_totp");
    Ok(DeviceTotpOutcome {
        device_id: pending_device.device_id,
        device_trusted: true,
        totp_enabled: true,
        challenge_ok: true,
    })
}

fn test_totp_code_from_otpauth(otpauth_uri: &str) -> Result<String, LiveVerifyError> {
    let secret_b32 =
        totp_secret_from_otpauth_uri(otpauth_uri).ok_or(LiveVerifyError::CodeRejected)?;
    let secret = Secret::Encoded(secret_b32)
        .to_bytes()
        .map_err(|_| LiveVerifyError::totp("totp_secret"))?;
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret)
        .map_err(|_| LiveVerifyError::totp("totp_secret"))?;
    totp.generate_current()
        .map_err(|_| LiveVerifyError::totp("totp_secret"))
}

/// Issue SMS only (after email already verified) — used by sad-path tests.
pub async fn issue_sms_challenge(
    valence: &Valence,
    services: &Arc<LeptonAuthServices>,
    user_id: valence::RecordId,
    phone_e164: &str,
) -> Result<String, LiveVerifyError> {
    let factors = FactorChallengeService::new(Arc::clone(services));
    factors
        .issue_sms_otp(valence, user_id, phone_e164)
        .await
        .map_err(|e| LiveVerifyError::delivery("sms", e.to_string()))
}

/// Consume an email verification token and mark the contact + user Active (CI e2e / CLI).
pub async fn verify_email_token(valence: &Valence, token_id: &str) -> Result<(), LiveVerifyError> {
    let token_id = token_id.trim();
    if token_id.is_empty() {
        return Err(LiveVerifyError::CodeRejected);
    }
    let token_record = EmailVerificationToken::get(token_id, valence, valence::use_!(r#"**Test:** Fixture **Email Verification Token** load for `flow` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .map_err(|_| LiveVerifyError::Token)?
        .ok_or(LiveVerifyError::CodeRejected)?;

    ensure_token_lifecycle_valid(&token_record).map_err(|_| LiveVerifyError::CodeRejected)?;
    verify_token_secret(token_id, token_record.token_hash())
        .map_err(|_| LiveVerifyError::CodeRejected)?;

    let consumed = try_consume_email_verification_token(token_id, valence)
        .await
        .map_err(|_| LiveVerifyError::Token)?;
    if !consumed {
        return Err(LiveVerifyError::CodeRejected);
    }

    let email_bare = valence::extract_id_from_record(token_record.user_email())
        .map_err(|_| LiveVerifyError::UserMissing)?;
    let email_row = AccountEmail::get(&email_bare, valence, valence::use_!(r#"**Test:** Fixture **Account Email** load for `flow` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .map_err(|_| LiveVerifyError::Token)?
        .ok_or(LiveVerifyError::UserMissing)?;

    mark_account_email_verified(valence, &email_row)
        .await
        .map_err(|_| LiveVerifyError::Token)?;
    if let Some(email_id) = email_row.id().cloned() {
        let _ = set_primary_email(valence, token_record.user(), &email_id).await;
    }

    let user_bare = valence::extract_id_from_record(token_record.user())
        .map_err(|_| LiveVerifyError::UserMissing)?;
    let user = User::get(&user_bare, valence, valence::use_!(r#"**Test:** Fixture **User** load for `flow` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .map_err(|_| LiveVerifyError::Token)?
        .ok_or(LiveVerifyError::UserMissing)?;
    user.get_mutable(valence, valence::use_!(r#"**Test:** Fixture **this data** access in `flow` so the suite can arrange and assert persistence. CI and developers running the suite only."#))
        .set_status(UserStatus::Active)
        .map_err(|_| LiveVerifyError::Token)?
        .set_updated_at(Utc::now())
        .map_err(|_| LiveVerifyError::Token)?
        .commit()
        .await
        .map_err(|_| LiveVerifyError::Token)?;

    Ok(())
}

fn parse_otp_from_sms_body(body: &str) -> Option<String> {
    const PREFIX: &str = "Your verification code is: ";
    body.strip_prefix(PREFIX)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn read_stdin_line() -> Result<String, LiveVerifyError> {
    use std::io::{self, BufRead};
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|_| LiveVerifyError::CodeSource)?;
    Ok(line)
}
