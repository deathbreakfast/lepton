//! OAuth signup → login orchestration (mock provider or live Google/GitHub).

use async_trait::async_trait;
use lepton_auth::oauth::{
    begin_oauth, complete_oauth, list_linked_identities, OAuthClientConfig, OAuthCompletion,
    OAuthIntent, OAuthProvider,
};
use tracing::info;
use valence::{RecordId, Valence};

use crate::error::LiveVerifyError;

/// Which OAuth step is requesting an authorization code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OAuthPhase {
    /// Create user + link identity.
    Signup,
    /// Sign in existing linked identity.
    Login,
}

/// Supplies an authorization code after [`begin_oauth`] (mock fixture or localhost callback).
#[async_trait]
pub trait OAuthCodeSource: Send + Sync {
    /// Present `authorize_url` (optional) and return the authorization `code`.
    ///
    /// `expected_state` is the CSRF state from [`begin_oauth`]; live sources must reject mismatch.
    async fn authorization_code(
        &self,
        phase: OAuthPhase,
        authorize_url: &str,
        expected_state: &str,
    ) -> Result<String, LiveVerifyError>;
}

/// CI / mock provider: any non-empty code (same code → same provider subject).
pub struct MockOAuthCodeSource;

#[async_trait]
impl OAuthCodeSource for MockOAuthCodeSource {
    async fn authorization_code(
        &self,
        _phase: OAuthPhase,
        _authorize_url: &str,
        _expected_state: &str,
    ) -> Result<String, LiveVerifyError> {
        Ok("mock-code".into())
    }
}

/// Outcome of [`run_oauth_signup_login_flow`].
#[derive(Debug, Clone)]
pub struct OAuthSignupLoginOutcome {
    /// User created (or returned) by signup completion.
    pub signup_user_id: RecordId,
    /// User returned by login completion (must equal signup).
    pub login_user_id: RecordId,
}

/// Options for [`run_oauth_signup_login_flow`].
#[derive(Clone, Copy, Debug, Default)]
pub struct OAuthSignupLoginOpts {
    /// Print operator-facing stdout (live CLI). CI e2e keeps this false.
    pub verbose: bool,
}

fn provider_label(provider: OAuthProvider) -> &'static str {
    match provider {
        OAuthProvider::Google => "Google",
        OAuthProvider::GitHub => "GitHub",
        OAuthProvider::Microsoft => "Microsoft",
    }
}

/// Signup with `provider`, then login with the same identity; assert same `user_id`.
///
/// # Errors
///
/// Config / OAuth / link mismatch.
pub async fn run_oauth_signup_login_flow(
    valence: &Valence,
    cfg: &OAuthClientConfig,
    provider: OAuthProvider,
    codes: &dyn OAuthCodeSource,
    opts: OAuthSignupLoginOpts,
) -> Result<OAuthSignupLoginOutcome, LiveVerifyError> {
    let label = provider_label(provider);
    let span = tracing::info_span!("lepton_e2e.oauth_mock", provider = label);
    let _guard = span.enter();

    info!(phase = "signup", "oauth_mock");
    if opts.verbose {
        println!("=== {label} signup ===");
    }
    let start = begin_oauth(cfg, valence, provider, OAuthIntent::Signup)
        .await
        .map_err(|e| LiveVerifyError::oauth(e.reason_class()))?;
    let code = codes
        .authorization_code(OAuthPhase::Signup, &start.authorize_url, &start.state)
        .await?;
    let signed_up = complete_oauth(cfg, valence, provider, &start.state, &code)
        .await
        .map_err(|e| LiveVerifyError::oauth(e.reason_class()))?
        .completion;
    let OAuthCompletion::SignedUp {
        user_id: signup_user_id,
    } = signed_up
    else {
        return Err(LiveVerifyError::oauth("oauth_expected_signed_up"));
    };
    let links = list_linked_identities(valence, &signup_user_id)
        .await
        .map_err(|e| LiveVerifyError::oauth(e.reason_class()))?;
    if links.is_empty() {
        return Err(LiveVerifyError::oauth("oauth_link_missing"));
    }
    if opts.verbose {
        println!("Signup OK — {label} identity linked (user created).");
        println!();
    }

    info!(phase = "login", "oauth_mock");
    if opts.verbose {
        println!("=== {label} login ===");
    }
    let start = begin_oauth(cfg, valence, provider, OAuthIntent::Login)
        .await
        .map_err(|e| LiveVerifyError::oauth(e.reason_class()))?;
    let code = codes
        .authorization_code(OAuthPhase::Login, &start.authorize_url, &start.state)
        .await?;
    let logged_in = complete_oauth(cfg, valence, provider, &start.state, &code)
        .await
        .map_err(|e| LiveVerifyError::oauth(e.reason_class()))?
        .completion;
    let OAuthCompletion::LoggedIn {
        user_id: login_user_id,
    } = logged_in
    else {
        return Err(LiveVerifyError::oauth("oauth_expected_logged_in"));
    };
    if login_user_id != signup_user_id {
        return Err(LiveVerifyError::oauth("oauth_user_mismatch"));
    }
    if opts.verbose {
        println!("Login OK — same user as signup.");
        println!();
    }

    info!(phase = "done", "oauth_mock");
    Ok(OAuthSignupLoginOutcome {
        signup_user_id,
        login_user_id,
    })
}
