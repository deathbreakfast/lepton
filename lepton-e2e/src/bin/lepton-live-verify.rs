//! Interactive live Twilio signup → email → phone → confirm.
//!
//! Gate: `UF_LEPTON_LIVE_TWILIO=1`. Secrets from env (see mailpit.env.example).

use std::process::ExitCode;

use lepton_e2e::{
    boot_lab_twilio, run_signup_verify_flow, LiveVerifyError, SignupVerifyOpts, StdinCodeSource,
};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => {
            println!("lepton-live-verify: OK — account created, email+phone verified, confirmed");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("lepton-live-verify: FAIL {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), LiveVerifyError> {
    if std::env::var("UF_LEPTON_LIVE_TWILIO").ok().as_deref() != Some("1") {
        return Err(LiveVerifyError::config("UF_LEPTON_LIVE_TWILIO must be 1"));
    }

    let legal_name = std::env::var("UF_LIVE_VERIFY_LEGAL_NAME")
        .map_err(|_| LiveVerifyError::config("missing UF_LIVE_VERIFY_LEGAL_NAME"))?;
    let email = std::env::var("UF_LIVE_VERIFY_EMAIL")
        .map_err(|_| LiveVerifyError::config("missing UF_LIVE_VERIFY_EMAIL"))?;
    let phone = std::env::var("UF_LIVE_VERIFY_PHONE")
        .map_err(|_| LiveVerifyError::config("missing UF_LIVE_VERIFY_PHONE"))?;
    let password = std::env::var("UF_LIVE_VERIFY_PASSWORD")
        .map_err(|_| LiveVerifyError::config("missing UF_LIVE_VERIFY_PASSWORD"))?;

    let auto_verify_email = matches!(
        std::env::var("UF_LIVE_VERIFY_SKIP_EMAIL").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    );
    let opts = SignupVerifyOpts { auto_verify_email };

    let lab = boot_lab_twilio("lepton_live_verify").await?;
    let codes = StdinCodeSource;

    if auto_verify_email {
        println!(
            "UF_LIVE_VERIFY_SKIP_EMAIL set — email will be auto-verified (SMS still interactive)"
        );
    }
    let reveal_pii = matches!(
        std::env::var("UF_LEPTON_LIVE_REVEAL_PII").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    );
    if reveal_pii {
        println!("Creating account for {email} / {phone} …");
    } else {
        println!(
            "Creating account for {} / {} … (set UF_LEPTON_LIVE_REVEAL_PII=1 to show full values)",
            mask_email(&email),
            mask_phone(&phone)
        );
    }
    let outcome = run_signup_verify_flow(
        &lab.valence,
        &lab.services,
        &codes,
        legal_name.trim(),
        email.trim(),
        phone.trim(),
        password.trim(),
        opts,
    )
    .await?;

    if !(outcome.email_verified && outcome.phone_verified && outcome.confirmed) {
        return Err(LiveVerifyError::ConfirmBlocked);
    }
    Ok(())
}

/// Mask an email for console output: keep the first local-part char and the
/// domain's TLD, hide everything else (`jane@example.com` → `j***@***.com`).
fn mask_email(raw: &str) -> String {
    let email = raw.trim();
    match email.split_once('@') {
        Some((local, domain)) => {
            let first = local.chars().next().map_or_else(String::new, String::from);
            let tld = domain.rsplit_once('.').map(|(_, t)| t).unwrap_or("");
            if tld.is_empty() {
                format!("{first}***@***")
            } else {
                format!("{first}***@***.{tld}")
            }
        }
        None => "***".to_string(),
    }
}

/// Mask a phone for console output: keep only the last two digits
/// (`+15551234567` → `•••••••••67`).
fn mask_phone(raw: &str) -> String {
    let digits: Vec<char> = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() <= 2 {
        return "•".repeat(digits.len().max(1));
    }
    let last_two: String = digits[digits.len() - 2..].iter().collect();
    format!("{}{}", "•".repeat(digits.len() - 2), last_two)
}
