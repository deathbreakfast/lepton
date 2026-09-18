//! OAuth begin / complete / link / unlink.

use chrono::Utc;
use lepton_host_adapter::generated::{AccountEmail, LinkedIdentity, LinkedIdentityProvider};
use valence::{Model, RecordId, StringPredicate, Valence};

use super::error::OAuthError;
use super::mock::exchange_mock_code;
use super::provision::create_oauth_user;
use super::state_store::{put_state, take_state, PendingState};
use crate::security::random_token_part;

fn bare_id(record: &RecordId) -> String {
    valence::extract_id_from_record(record).unwrap_or_else(|_| record.id().to_string())
}

/// Supported OAuth providers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OAuthProvider {
    /// Google.
    Google,
    /// GitHub.
    GitHub,
}

impl OAuthProvider {
    /// Stable lowercase provider key (`google` / `github`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::GitHub => "github",
        }
    }

    const fn to_generated(self) -> LinkedIdentityProvider {
        match self {
            Self::Google => LinkedIdentityProvider::Google,
            Self::GitHub => LinkedIdentityProvider::Github,
        }
    }

    const fn feature_enabled(self) -> bool {
        match self {
            Self::Google => cfg!(feature = "oauth-google"),
            Self::GitHub => cfg!(feature = "oauth-github"),
        }
    }
}

/// OAuth flow intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OAuthIntent {
    /// Sign in an existing linked user.
    Login,
    /// Create user if needed.
    Signup,
    /// Link to an authenticated user.
    Link,
}

/// Host-supplied OAuth client configuration (secrets stay on host).
#[derive(Clone, Debug)]
pub struct OAuthClientConfig {
    /// Public site URL (redirect base).
    pub public_base_url: String,
    /// Redirect path (e.g. `/auth/oauth/callback`).
    pub redirect_path: String,
    /// Google client id (optional).
    pub google_client_id: Option<String>,
    /// Google client secret (optional).
    pub google_client_secret: Option<String>,
    /// GitHub client id (optional).
    pub github_client_id: Option<String>,
    /// GitHub client secret (optional).
    pub github_client_secret: Option<String>,
    /// Use mock provider (CI / tests); skips live Google/GitHub HTTP.
    pub use_mock_provider: bool,
    /// Lab mock OIDC issuer base URL (e.g. `http://127.0.0.1:5556`).
    ///
    /// When set with [`Self::use_mock_provider`], authorize redirects to the issuer and
    /// code exchange uses token + userinfo HTTP. When `None`, code exchange stays
    /// in-process (`exchange_mock_code`) for unit tests without a sidecar.
    pub mock_oidc_issuer_url: Option<String>,
    /// Override Google token endpoint (wiremock / tests). Default: production Google.
    pub google_token_url: Option<String>,
    /// Override Google userinfo endpoint (wiremock / tests). Default: production Google.
    pub google_userinfo_url: Option<String>,
    /// Override GitHub token endpoint (wiremock / tests). Default: production GitHub.
    pub github_token_url: Option<String>,
    /// Override GitHub user endpoint (wiremock / tests). Default: production GitHub.
    pub github_user_url: Option<String>,
    /// Override GitHub emails endpoint (wiremock / tests). Default: production GitHub.
    pub github_emails_url: Option<String>,
}

impl OAuthClientConfig {
    /// Absolute redirect URI (`public_base_url` + `redirect_path`).
    #[must_use]
    pub fn redirect_uri(&self) -> String {
        format!(
            "{}{}",
            self.public_base_url.trim_end_matches('/'),
            if self.redirect_path.starts_with('/') {
                self.redirect_path.clone()
            } else {
                format!("/{}", self.redirect_path)
            }
        )
    }
}

/// Result of [`begin_oauth`].
#[derive(Clone, Debug)]
pub struct OAuthStart {
    /// Browser redirect URL.
    pub authorize_url: String,
    /// Opaque CSRF state.
    pub state: String,
}

/// Pending link payload when [`complete_oauth`] needs an authenticated user.
#[derive(Clone, Debug)]
pub struct PendingOAuthLink {
    /// Provider.
    pub provider: OAuthProvider,
    /// Provider subject.
    pub provider_subject: String,
    /// Optional email hint from the identity provider.
    pub email_hint: Option<String>,
}

/// Outcome of [`complete_oauth`] (`OAuthCompleteResult::completion`).
#[derive(Clone, Debug)]
pub enum OAuthCompletion {
    /// Existing user signed in.
    LoggedIn {
        /// User record id.
        user_id: RecordId,
    },
    /// New user created.
    SignedUp {
        /// User record id.
        user_id: RecordId,
    },
    /// Linked to authenticated user during complete (Link intent with user in state).
    Linked {
        /// User record id.
        user_id: RecordId,
    },
    /// Needs authenticated link step.
    NeedsLink {
        /// Pending provider subject to link.
        pending: PendingOAuthLink,
    },
}

/// Result of [`complete_oauth`]: completion plus optional post-auth redirect path from pending state.
#[derive(Clone, Debug)]
pub struct OAuthCompleteResult {
    /// Sign-in / signup / link outcome.
    pub completion: OAuthCompletion,
    /// Sanitized redirect path stored at OAuth begin (when provided).
    pub referer: Option<String>,
}

fn pkce_s256_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(verifier.as_bytes());
    base64_url_no_pad(&digest)
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = u32::from(bytes[i]) << 16 | u32::from(bytes[i + 1]) << 8 | u32::from(bytes[i + 2]);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = u32::from(bytes[i]) << 16;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
    } else if rem == 2 {
        let n = u32::from(bytes[i]) << 16 | u32::from(bytes[i + 1]) << 8;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
    }
    out
}

fn append_pkce_params(url: &str, code_challenge: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!(
        "{url}{sep}code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(code_challenge)
    )
}

/// Begin an OAuth authorization redirect.
///
/// # Errors
///
/// [`OAuthError::Config`] when provider feature/config missing (unless mock provider).
pub async fn begin_oauth(
    cfg: &OAuthClientConfig,
    valence: &Valence,
    provider: OAuthProvider,
    intent: OAuthIntent,
) -> Result<OAuthStart, OAuthError> {
    begin_oauth_for_user(cfg, valence, provider, intent, None, None).await
}

/// Begin OAuth, optionally binding Link intent to `user`.
///
/// # Errors
///
/// Config / store.
pub async fn begin_oauth_for_user(
    cfg: &OAuthClientConfig,
    valence: &Valence,
    provider: OAuthProvider,
    intent: OAuthIntent,
    link_user: Option<&RecordId>,
    referer: Option<String>,
) -> Result<OAuthStart, OAuthError> {
    if !cfg.use_mock_provider && !provider.feature_enabled() {
        #[cfg(feature = "spectra")]
        crate::spectra_emit::oauth(
            crate::spectra_emit::oauth_provider_label(provider),
            crate::spectra_emit::oauth_intent_label(intent),
            crate::spectra_emit::OAuthStage::Begin,
            crate::spectra_emit::AuthOutcome::Failure,
            "oauth_config",
        );
        return Err(OAuthError::Config);
    }
    let pkce_verifier = random_token_part(32);
    let code_challenge = pkce_s256_challenge(&pkce_verifier);
    let state = put_state(
        valence,
        PendingState {
            provider,
            intent,
            link_user: link_user.map(bare_id),
            pkce_verifier,
            referer,
        },
    )
    .await?;
    let authorize_url = if cfg.use_mock_provider {
        let issuer = cfg
            .mock_oidc_issuer_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("http://127.0.0.1:5556")
            .trim_end_matches('/');
        format!(
            "{issuer}/authorize?provider={}&state={}&redirect_uri={}",
            provider.as_str(),
            urlencoding::encode(&state),
            urlencoding::encode(&cfg.redirect_uri()),
        )
    } else {
        live_authorize_url(cfg, provider, &state, &code_challenge)?
    };
    #[cfg(feature = "spectra")]
    crate::spectra_emit::oauth(
        crate::spectra_emit::oauth_provider_label(provider),
        crate::spectra_emit::oauth_intent_label(intent),
        crate::spectra_emit::OAuthStage::Begin,
        crate::spectra_emit::AuthOutcome::Success,
        "none",
    );
    Ok(OAuthStart {
        authorize_url,
        state,
    })
}

fn live_authorize_url(
    cfg: &OAuthClientConfig,
    provider: OAuthProvider,
    state: &str,
    code_challenge: &str,
) -> Result<String, OAuthError> {
    let redirect = cfg.redirect_uri();
    let base = match provider {
        OAuthProvider::Google => {
            let client_id = cfg.google_client_id.as_deref().ok_or(OAuthError::Config)?;
            format!(
                "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}",
                urlencoding::encode(client_id),
                urlencoding::encode(&redirect),
                urlencoding::encode(state),
            )
        }
        OAuthProvider::GitHub => {
            let client_id = cfg.github_client_id.as_deref().ok_or(OAuthError::Config)?;
            format!(
                "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=read:user%20user:email&state={}",
                urlencoding::encode(client_id),
                urlencoding::encode(&redirect),
                urlencoding::encode(state),
            )
        }
    };
    Ok(append_pkce_params(&base, code_challenge))
}

/// Complete OAuth using authorization `code` + CSRF `state`.
///
/// Mock provider: in-process exchange when `mock_oidc_issuer_url` is unset; otherwise
/// HTTP against the lab issuer.
///
/// # Errors
///
/// State / account taken / provider / store.
#[allow(clippy::too_many_lines)] // complete ladder + optional Spectra emit
pub async fn complete_oauth(
    cfg: &OAuthClientConfig,
    valence: &Valence,
    provider: OAuthProvider,
    state: &str,
    code: &str,
) -> Result<OAuthCompleteResult, OAuthError> {
    let Some(pending) = take_state(valence, state).await? else {
        #[cfg(feature = "spectra")]
        crate::spectra_emit::oauth(
            crate::spectra_emit::oauth_provider_label(provider),
            crate::spectra_emit::OAuthIntentLabel::Login,
            crate::spectra_emit::OAuthStage::Complete,
            crate::spectra_emit::AuthOutcome::Failure,
            "oauth_state",
        );
        return Err(OAuthError::State);
    };
    let stored_referer = pending.referer.clone();
    let pkce_verifier = pending.pkce_verifier.clone();
    let finish = |completion: OAuthCompletion| OAuthCompleteResult {
        completion,
        referer: stored_referer.clone(),
    };
    if pending.provider != provider {
        #[cfg(feature = "spectra")]
        crate::spectra_emit::oauth(
            crate::spectra_emit::oauth_provider_label(provider),
            crate::spectra_emit::oauth_intent_label(pending.intent),
            crate::spectra_emit::OAuthStage::Complete,
            crate::spectra_emit::AuthOutcome::Failure,
            "oauth_state",
        );
        return Err(OAuthError::State);
    }
    let (subject, email_hint, name_hint) = if cfg.use_mock_provider {
        match cfg
            .mock_oidc_issuer_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(issuer) => {
                crate::oauth::mock_http::exchange_mock_http(issuer, provider, code).await?
            }
            None => exchange_mock_code(provider, code)?,
        }
    } else {
        exchange_live_code(cfg, provider, code, &pkce_verifier).await?
    };

    if let Some(existing) = find_link(valence, provider, &subject).await? {
        // Link intent must not silently sign the operator into another account when the
        // provider subject is already owned elsewhere.
        if pending.intent == OAuthIntent::Link {
            let Some(ref link_user) = pending.link_user else {
                #[cfg(feature = "spectra")]
                crate::spectra_emit::oauth(
                    crate::spectra_emit::oauth_provider_label(provider),
                    crate::spectra_emit::OAuthIntentLabel::Link,
                    crate::spectra_emit::OAuthStage::Complete,
                    crate::spectra_emit::AuthOutcome::NeedsLink,
                    "none",
                );
                return Ok(finish(OAuthCompletion::NeedsLink {
                    pending: PendingOAuthLink {
                        provider,
                        provider_subject: subject,
                        email_hint,
                    },
                }));
            };
            if bare_id(existing.user()) == *link_user {
                let user_id = existing.user().clone();
                #[cfg(feature = "spectra")]
                crate::spectra_emit::oauth(
                    crate::spectra_emit::oauth_provider_label(provider),
                    crate::spectra_emit::OAuthIntentLabel::Link,
                    crate::spectra_emit::OAuthStage::Complete,
                    crate::spectra_emit::AuthOutcome::Success,
                    "none",
                );
                return Ok(finish(OAuthCompletion::Linked { user_id }));
            }
            #[cfg(feature = "spectra")]
            crate::spectra_emit::oauth(
                crate::spectra_emit::oauth_provider_label(provider),
                crate::spectra_emit::OAuthIntentLabel::Link,
                crate::spectra_emit::OAuthStage::Complete,
                crate::spectra_emit::AuthOutcome::Failure,
                "oauth_account_taken",
            );
            return Err(OAuthError::AccountTaken);
        }
        let user_id = existing.user().clone();
        #[cfg(feature = "spectra")]
        crate::spectra_emit::oauth(
            crate::spectra_emit::oauth_provider_label(provider),
            crate::spectra_emit::oauth_intent_label(pending.intent),
            crate::spectra_emit::OAuthStage::Complete,
            crate::spectra_emit::AuthOutcome::Success,
            "none",
        );
        return Ok(finish(OAuthCompletion::LoggedIn { user_id }));
    }

    match pending.intent {
        OAuthIntent::Login => {
            #[cfg(feature = "spectra")]
            crate::spectra_emit::oauth(
                crate::spectra_emit::oauth_provider_label(provider),
                crate::spectra_emit::OAuthIntentLabel::Login,
                crate::spectra_emit::OAuthStage::Complete,
                crate::spectra_emit::AuthOutcome::NeedsLink,
                "none",
            );
            Ok(finish(OAuthCompletion::NeedsLink {
                pending: PendingOAuthLink {
                    provider,
                    provider_subject: subject,
                    email_hint,
                },
            }))
        }
        OAuthIntent::Signup => {
            if let Some(ref email) = email_hint {
                let taken = AccountEmail::query_used(valence, valence::use_!(r"In **OAuth account linking**, we **list Account Email** so the product can show or process the matching set for this workflow. Callers allowed for **OAuth account linking** use the list; it is not a public dump of every field to anonymous visitors."))
                    .where_address(StringPredicate::Equals(email.clone()))
                    .first()
                    .await
                    .map_err(|_| OAuthError::Store)?
                    .is_some();
                if taken {
                    tracing::info!(
                        reason_class = "oauth_signup_email_collision",
                        provider = ?provider,
                        "oauth signup email already registered; NeedsLink"
                    );
                    #[cfg(feature = "spectra")]
                    crate::spectra_emit::oauth(
                        crate::spectra_emit::oauth_provider_label(provider),
                        crate::spectra_emit::OAuthIntentLabel::Signup,
                        crate::spectra_emit::OAuthStage::Complete,
                        crate::spectra_emit::AuthOutcome::NeedsLink,
                        "oauth_signup_email_collision",
                    );
                    return Ok(finish(OAuthCompletion::NeedsLink {
                        pending: PendingOAuthLink {
                            provider,
                            provider_subject: subject,
                            email_hint,
                        },
                    }));
                }
            }
            let user_id =
                create_oauth_user(valence, email_hint.as_deref(), name_hint.as_deref()).await?;
            insert_link(valence, &user_id, provider, &subject, email_hint.as_deref()).await?;
            #[cfg(feature = "spectra")]
            crate::spectra_emit::oauth(
                crate::spectra_emit::oauth_provider_label(provider),
                crate::spectra_emit::OAuthIntentLabel::Signup,
                crate::spectra_emit::OAuthStage::Complete,
                crate::spectra_emit::AuthOutcome::Success,
                "none",
            );
            Ok(finish(OAuthCompletion::SignedUp { user_id }))
        }
        OAuthIntent::Link => {
            let Some(uid) = pending.link_user else {
                return Ok(finish(OAuthCompletion::NeedsLink {
                    pending: PendingOAuthLink {
                        provider,
                        provider_subject: subject,
                        email_hint,
                    },
                }));
            };
            let user_id = RecordId::new("user", &uid);
            insert_link(valence, &user_id, provider, &subject, email_hint.as_deref()).await?;
            #[cfg(feature = "spectra")]
            crate::spectra_emit::oauth(
                crate::spectra_emit::oauth_provider_label(provider),
                crate::spectra_emit::OAuthIntentLabel::Link,
                crate::spectra_emit::OAuthStage::Complete,
                crate::spectra_emit::AuthOutcome::Success,
                "none",
            );
            Ok(finish(OAuthCompletion::Linked { user_id }))
        }
    }
}

#[allow(clippy::unused_async)] // awaits only when oauth-google / oauth-github are enabled
async fn exchange_live_code(
    cfg: &OAuthClientConfig,
    provider: OAuthProvider,
    code: &str,
    code_verifier: &str,
) -> Result<(String, Option<String>, Option<String>), OAuthError> {
    match provider {
        OAuthProvider::Google => {
            #[cfg(feature = "oauth-google")]
            {
                super::google::exchange_google_code(cfg, code, code_verifier).await
            }
            #[cfg(not(feature = "oauth-google"))]
            {
                let _ = (cfg, code, code_verifier);
                Err(OAuthError::Config)
            }
        }
        OAuthProvider::GitHub => {
            #[cfg(feature = "oauth-github")]
            {
                super::github::exchange_github_code(cfg, code, code_verifier).await
            }
            #[cfg(not(feature = "oauth-github"))]
            {
                let _ = (cfg, code, code_verifier);
                Err(OAuthError::Config)
            }
        }
    }
}

async fn find_link(
    valence: &Valence,
    provider: OAuthProvider,
    subject: &str,
) -> Result<Option<LinkedIdentity>, OAuthError> {
    let gen = provider.to_generated();
    let rows = LinkedIdentity::query_used(valence, valence::use_!(r"In **OAuth account linking**, we **list Linked Identity** so the product can show or process the matching set for this workflow. Callers allowed for **OAuth account linking** use the list; it is not a public dump of every field to anonymous visitors."))
        .where_provider_subject(StringPredicate::Equals(subject.to_string()))
        .await
        .map_err(|_| OAuthError::Store)?;
    Ok(rows.into_iter().find(|r| *r.provider() == gen))
}

async fn insert_link(
    valence: &Valence,
    user: &RecordId,
    provider: OAuthProvider,
    subject: &str,
    email_hint: Option<&str>,
) -> Result<(), OAuthError> {
    if find_link(valence, provider, subject).await?.is_some() {
        return Err(OAuthError::AccountTaken);
    }
    let now = Utc::now();
    let row = LinkedIdentity::new(
        user.clone(),
        provider.to_generated(),
        subject.to_string(),
        email_hint.map(str::to_string),
        now,
        now,
        now,
    )
    .map_err(|_| OAuthError::Store)?;
    let id = random_token_part(12);
    LinkedIdentity::upsert_used(&id, row, valence, valence::use_!(r"When **OAuth account linking** needs to persist work, we **save Linked Identity** so the next step in that feature can continue with the latest values. People and services allowed for **OAuth account linking** use this data for that workflow—not as a general export of unrelated personal fields."))
        .await
        .map_err(|_| OAuthError::Store)?;
    Ok(())
}

/// Link a pending OAuth identity to an authenticated user.
///
/// # Errors
///
/// Account taken / store.
pub async fn link_oauth_identity(
    valence: &Valence,
    user: &RecordId,
    pending: &PendingOAuthLink,
) -> Result<(), OAuthError> {
    insert_link(
        valence,
        user,
        pending.provider,
        &pending.provider_subject,
        pending.email_hint.as_deref(),
    )
    .await
}

/// Unlink a [`LinkedIdentity`] owned by `user`.
///
/// Uses an in-process physical delete (same approach as TOTP disable / account wipe)
/// so hosts without a Valence Model deletion dispatcher still succeed.
///
/// # Errors
///
/// Missing / store.
pub async fn unlink_oauth_identity(
    valence: &Valence,
    user: &RecordId,
    linked_id: &RecordId,
) -> Result<(), OAuthError> {
    let id = bare_id(linked_id);
    let row = LinkedIdentity::get_used(&id, valence, valence::use_!(r"In **OAuth account linking**, we **load Linked Identity** so the application can decide what to do next in this workflow. The result is used by **OAuth account linking** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await
        .map_err(|_| OAuthError::Store)?
        .ok_or(OAuthError::LinkMissing)?;
    if bare_id(row.user()) != bare_id(user) {
        return Err(OAuthError::LinkMissing);
    }
    let backend = valence
        .backend_for_table("linked_identity")
        .map_err(|_| OAuthError::Store)?;
    backend
        .delete_record("linked_identity", &id)
        .await
        .map_err(|_| OAuthError::Store)?;
    valence::read_cache::invalidate("linked_identity", &id);
    Ok(())
}

/// List linked identities for `user`.
///
/// # Errors
///
/// Store.
pub async fn list_linked_identities(
    valence: &Valence,
    user: &RecordId,
) -> Result<Vec<LinkedIdentity>, OAuthError> {
    let uid = bare_id(user);
    LinkedIdentity::get_from_user_id(&uid, valence)
        .await
        .map_err(|_| OAuthError::Store)
}

#[cfg(all(test, not(feature = "oauth-github")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn github_live_exchange_requires_feature_config_sad() {
        let cfg = OAuthClientConfig {
            public_base_url: "http://127.0.0.1:8765".into(),
            redirect_path: "/auth/oauth/callback".into(),
            google_client_id: None,
            google_client_secret: None,
            github_client_id: Some("gh-id".into()),
            github_client_secret: Some("gh-secret".into()),
            use_mock_provider: false,
            mock_oidc_issuer_url: None,
            google_token_url: None,
            google_userinfo_url: None,
            github_token_url: None,
            github_user_url: None,
            github_emails_url: None,
        };
        let err = exchange_live_code(&cfg, OAuthProvider::GitHub, "code", "verifier")
            .await
            .expect_err("github live needs oauth-github");
        assert_eq!(err.reason_class(), "oauth_config");
        assert!(!err.to_string().contains("gh-secret"));
    }
}
