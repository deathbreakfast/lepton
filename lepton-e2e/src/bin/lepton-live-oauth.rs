//! Interactive live Google or GitHub OAuth signup + login.
//!
//! Binds a loopback callback, prints authorize URLs, exchanges codes with the
//! provider, and asserts signup then login for the same user.
//! Gate: `UF_LEPTON_LIVE_OAUTH=1`. Provider: `UF_OAUTH_PROVIDER=google|github`
//! (default `google`).

use std::process::ExitCode;

use lepton_auth::oauth::{OAuthClientConfig, OAuthProvider};
use lepton_e2e::{
    boot_valence, run_oauth_signup_login_flow, LiveVerifyError, LocalhostOAuthCodeSource,
    OAuthSignupLoginOpts,
};
use tracing::info;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(provider) => {
            println!(
                "lepton-live-oauth: OK — {} signup + login",
                provider.as_label()
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("lepton-live-oauth: FAIL {err}");
            ExitCode::FAILURE
        }
    }
}

trait ProviderLabel {
    fn as_label(self) -> &'static str;
}

impl ProviderLabel for OAuthProvider {
    fn as_label(self) -> &'static str {
        match self {
            OAuthProvider::Google => "Google",
            OAuthProvider::GitHub => "GitHub",
        }
    }
}

async fn run() -> Result<OAuthProvider, LiveVerifyError> {
    if std::env::var("UF_LEPTON_LIVE_OAUTH").ok().as_deref() != Some("1") {
        return Err(LiveVerifyError::config("UF_LEPTON_LIVE_OAUTH must be 1"));
    }

    let provider_raw = std::env::var("UF_OAUTH_PROVIDER").ok();
    let provider_norm = provider_raw
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase());
    let provider = match provider_norm.as_deref() {
        None => {
            eprintln!(
                "lepton-live-oauth: UF_OAUTH_PROVIDER unset; defaulting to google \
                 (set UF_OAUTH_PROVIDER=github for GitHub)"
            );
            OAuthProvider::Google
        }
        Some("google") => OAuthProvider::Google,
        Some("github") => OAuthProvider::GitHub,
        Some(other) => {
            return Err(LiveVerifyError::config(format!(
                "UF_OAUTH_PROVIDER must be google or github (got {other})"
            )));
        }
    };

    let redirect_path = std::env::var("UF_OAUTH_REDIRECT_PATH")
        .unwrap_or_else(|_| "/auth/oauth/callback".to_string());
    let port: u16 = std::env::var("UF_OAUTH_CALLBACK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8765);

    let span = tracing::info_span!("lepton_e2e.live_oauth", provider = provider.as_label());
    let _guard = span.enter();

    info!(phase = "callback_listen", "live_oauth");
    let codes = LocalhostOAuthCodeSource::bind(port, redirect_path.clone()).await?;
    let callback = codes.callback_url()?;
    println!(
        "Listening for {} OAuth callback on {callback}",
        provider.as_label()
    );
    // Always use the loopback listener as redirect base so authorize `redirect_uri`
    // matches where we accept the callback (env `UF_PUBLIC_BASE_URL` is often :3000).
    let listen_base = format!("http://{}", codes.listen_addr()?);
    if let Ok(env_base) = std::env::var("UF_PUBLIC_BASE_URL") {
        let trimmed = env_base.trim_end_matches('/');
        if trimmed != listen_base {
            println!(
                "Note: UF_PUBLIC_BASE_URL={trimmed} ignored for OAuth redirect; using {listen_base}"
            );
        }
    }
    println!();
    println!("Register this exact redirect URI on the OAuth app: {callback}");
    println!();

    let public_base_url = listen_base;

    let cfg = match provider {
        OAuthProvider::Google => {
            let client_id = std::env::var("UF_OAUTH_GOOGLE_CLIENT_ID")
                .map_err(|_| LiveVerifyError::config("missing UF_OAUTH_GOOGLE_CLIENT_ID"))?;
            let client_secret = std::env::var("UF_OAUTH_GOOGLE_CLIENT_SECRET")
                .map_err(|_| LiveVerifyError::config("missing UF_OAUTH_GOOGLE_CLIENT_SECRET"))?;
            OAuthClientConfig {
                public_base_url,
                redirect_path,
                google_client_id: Some(client_id),
                google_client_secret: Some(client_secret),
                github_client_id: None,
                github_client_secret: None,
                use_mock_provider: false,
                mock_oidc_issuer_url: None,
                google_token_url: None,
                google_userinfo_url: None,
                github_token_url: None,
                github_user_url: None,
                github_emails_url: None,
                microsoft_client_id: None,
                microsoft_client_secret: None,
                microsoft_tenant: None,
                microsoft_token_url: None,
                microsoft_userinfo_url: None,
            }
        }
        OAuthProvider::GitHub => {
            let client_id = std::env::var("UF_OAUTH_GITHUB_CLIENT_ID")
                .map_err(|_| LiveVerifyError::config("missing UF_OAUTH_GITHUB_CLIENT_ID"))?;
            let client_secret = std::env::var("UF_OAUTH_GITHUB_CLIENT_SECRET")
                .map_err(|_| LiveVerifyError::config("missing UF_OAUTH_GITHUB_CLIENT_SECRET"))?;
            OAuthClientConfig {
                public_base_url,
                redirect_path,
                google_client_id: None,
                google_client_secret: None,
                github_client_id: Some(client_id),
                github_client_secret: Some(client_secret),
                use_mock_provider: false,
                mock_oidc_issuer_url: None,
                google_token_url: None,
                google_userinfo_url: None,
                github_token_url: None,
                github_user_url: None,
                github_emails_url: None,
                microsoft_client_id: None,
                microsoft_client_secret: None,
                microsoft_tenant: None,
                microsoft_token_url: None,
                microsoft_userinfo_url: None,
            }
        }
    };

    info!(phase = "signup", "live_oauth");
    let valence = boot_valence("lepton_live_oauth").await?;
    let outcome = run_oauth_signup_login_flow(
        &valence,
        &cfg,
        provider,
        &codes,
        OAuthSignupLoginOpts { verbose: true },
    )
    .await?;

    if outcome.signup_user_id != outcome.login_user_id {
        return Err(LiveVerifyError::oauth("oauth_user_mismatch"));
    }

    info!(phase = "done", "live_oauth");
    Ok(provider)
}
