//! Authentication types and axum-login backend.

use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use async_trait::async_trait;
use axum_login::{AuthUser, AuthnBackend, UserId};
use higgs_core::HiggsValenceFactory;
use higgs_identity::{SessionIdentity, SessionSnapshot, SessionUserId};
use lepton_identity::generated::{AccountEmail, User as GeneratedUser, UserUserType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use valence::{Actor, Model, RecordPredicate, StringPredicate, Valence};

/// Precomputed Argon2id PHC for missing-user timing padding (not a real credential).
const DUMMY_PASSWORD_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$itH21fPrT2KJ49+mfM8E5Q$xKW+gYDIctGTVbpm818PWbAYb5acoWFTTZ9MZTpuSyw";

fn valence_from_factory(
    factory: &dyn HiggsValenceFactory,
    operation: &str,
) -> Result<Valence, std::io::Error> {
    let actor = Actor::System {
        operation: operation.to_string(),
    };
    let actor_json = serde_json::to_value(&actor)
        .map_err(|e| std::io::Error::other(format!("actor serialize: {e}")))?;
    factory
        .build(&actor_json)
        .map_err(|e| std::io::Error::other(format!("valence factory build: {e}")))
}

/// Derive an opaque session stamp from a password PHC string.
///
/// The stamp changes when the password hash changes (invalidating sessions) but is
/// safe to place in `SessionSnapshot` / request extensions — unlike the full PHC.
pub fn opaque_session_stamp(password_hash: &str) -> Vec<u8> {
    Sha256::digest(password_hash.as_bytes()).to_vec()
}

/// Mask an email for audit logs (`a***@example.com`). Never log full addresses.
fn mask_email_for_audit(email: &str) -> String {
    let trimmed = email.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return "***".to_string();
    };
    let first = local.chars().next().unwrap_or('*');
    format!("{first}***@{domain}")
}

fn verify_password_with_dummy(password: &str, stored_phc: Option<&str>) -> bool {
    let phc = stored_phc.unwrap_or(DUMMY_PASSWORD_PHC);
    let Ok(parsed_hash) = PasswordHash::new(phc) else {
        let Ok(dummy_parsed) = PasswordHash::new(DUMMY_PASSWORD_PHC) else {
            return false;
        };
        let _ = Argon2::default().verify_password(password.as_bytes(), &dummy_parsed);
        return false;
    };
    let matches = Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();
    stored_phc.is_some() && matches
}

fn bare_user_id(record: &valence::RecordId) -> String {
    valence::extract_id_from_record(record).unwrap_or_else(|_| record.id().to_string())
}

/// Auth-specific User wrapper around the generated model.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    /// Stable session identifier, used as the axum-login [`AuthUser::Id`].
    pub session_id: SessionUserId,
    /// Underlying Valence record id for the `user` table row.
    pub id: valence::RecordId,
    /// User's primary (or login) email address.
    pub email: String,
    /// Opaque session stamp derived from the password hash (never the PHC itself).
    pub session_stamp: Vec<u8>,
    /// Display name resolved from the user's first `user_profile` row, if any.
    #[serde(default)]
    pub display_name: Option<String>,
    /// First account id the user has a membership in, if any.
    #[serde(default)]
    pub account_id: Option<String>,
    /// Membership roles across the user's accounts.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Whether the primary email contact has `verified_at` set.
    #[serde(default)]
    pub email_verified: bool,
}

impl User {
    /// Build a session [`User`] from the generated Valence model plus resolved contact/profile data.
    pub fn from_generated(
        generated: &GeneratedUser,
        email: String,
        email_verified: bool,
        display_name: Option<String>,
        account_id: Option<String>,
        roles: Vec<String>,
    ) -> Self {
        let id = generated
            .id()
            .cloned()
            .unwrap_or_else(|| valence::RecordId::new("user", "unknown"));
        let session_id = id.to_string();
        let session_stamp = opaque_session_stamp(
            generated
                .password_hash()
                .map_or("", std::string::String::as_str),
        );

        Self {
            session_id,
            id,
            email,
            session_stamp,
            display_name,
            account_id,
            roles,
            email_verified,
        }
    }
}

impl AuthUser for User {
    type Id = SessionUserId;

    fn id(&self) -> Self::Id {
        self.session_id.clone()
    }

    fn session_auth_hash(&self) -> &[u8] {
        &self.session_stamp
    }
}

#[async_trait]
impl SessionIdentity for User {
    fn session_user_id(&self) -> &SessionUserId {
        &self.session_id
    }

    fn session_auth_hash(&self) -> &[u8] {
        AuthUser::session_auth_hash(self)
    }
}

/// `axum_login::AuthnBackend` implementation backed by the `lepton-identity` generated `User` model.
///
/// Register with `axum-login`'s session layer to enable [`Credentials`]-based
/// sign-in and session lookup via [`get_user`](AuthnBackend::get_user).
///
/// Construct with the same [`HiggsValenceFactory`] installed on host `HiggsConfig`
/// (for example `higgs.valence_factory().clone()`). The factory must allow
/// System-shaped actors for authenticate / session rehydrate.
#[derive(Clone)]
pub struct Backend {
    valence_factory: Arc<dyn HiggsValenceFactory>,
}

impl Backend {
    /// Construct a [`Backend`] from the host [`HiggsValenceFactory`].
    ///
    /// Prefer the same `Arc` wired into `HiggsConfig` so sign-in and SSR share one
    /// Valence entry point. Do not pass an external-trust factory that rejects System.
    pub fn new(valence_factory: Arc<dyn HiggsValenceFactory>) -> Self {
        Self { valence_factory }
    }
}

/// Sign-in credentials passed to [`Backend::authenticate`] via `axum-login`.
#[derive(Clone, Debug)]
pub struct Credentials {
    /// Email address supplied at sign-in.
    pub email: String,
    /// Plaintext password to verify against the stored Argon2 hash.
    pub password: String,
}

async fn resolve_session_fields(
    generated_user: &GeneratedUser,
    valence: &Valence,
    login_email: Option<&str>,
) -> Result<(String, bool, Option<String>, Option<String>, Vec<String>), std::io::Error> {
    let primary = if let Some(pid) = generated_user.primary_email() {
        let bare = bare_user_id(pid);
        AccountEmail::get_used(&bare, valence, valence::use_!(r"In **lepton host adapter**, we **load Account Email** so the application can decide what to do next in this workflow. The result is used by **lepton host adapter** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
            .await
            .map_err(|e| std::io::Error::other(format!("Get primary email: {e}")))?
    } else {
        None
    };

    let email = primary
        .as_ref()
        .map(|e| e.address().clone())
        .or_else(|| login_email.map(str::to_string))
        .unwrap_or_default();
    let email_verified = primary.as_ref().is_some_and(|e| e.verified_at().is_some());

    let display_name = generated_user
        .get_profile(valence)
        .await
        .unwrap_or_default()
        .into_iter()
        .next()
        .map(|p| p.display_name().clone());

    let memberships = generated_user
        .get_memberships(valence)
        .await
        .unwrap_or_default();
    let account_id = memberships.first().map(|m| m.account().to_string());
    let roles = memberships
        .into_iter()
        .map(|m| m.role().to_string())
        .collect::<Vec<_>>();

    Ok((email, email_verified, display_name, account_id, roles))
}

impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = std::io::Error;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        let email_for_audit = creds.email.trim().to_string();
        let valence = valence_from_factory(self.valence_factory.as_ref(), "authenticate")?;

        let email = creds.email.trim().to_string();
        let email_row = AccountEmail::query_used(&valence, valence::use_!(r"In **lepton host adapter**, we **list Account Email** so the product can show or process the matching set for this workflow. Callers allowed for **lepton host adapter** use the list; it is not a public dump of every field to anonymous visitors."))
            .where_address(StringPredicate::Equals(email.clone()))
            .first()
            .await
            .map_err(|e| std::io::Error::other(format!("Query error: {e}")))?;

        let generated_user = if let Some(row) = email_row.as_ref() {
            let Some(email_id) = row.id().cloned() else {
                return Ok(None);
            };
            GeneratedUser::query_used(&valence, valence::use_!(r"In **lepton host adapter**, we **list Generated User** so the product can show or process the matching set for this workflow. Callers allowed for **lepton host adapter** use the list; it is not a public dump of every field to anonymous visitors."))
                .where_primary_email(RecordPredicate::Equals(email_id))
                .first()
                .await
                .map_err(|e| std::io::Error::other(format!("Get user error: {e}")))?
        } else {
            None
        };

        let person_user = generated_user
            .as_ref()
            .filter(|u| matches!(u.user_type().cloned(), Some(UserUserType::Person)));
        let stored_phc = person_user.and_then(|u| u.password_hash().map(String::as_str));
        let password_ok = verify_password_with_dummy(&creds.password, stored_phc);

        if let Some(generated_user) = person_user.filter(|_| password_ok) {
            let (email, email_verified, display_name, account_id, roles) =
                resolve_session_fields(generated_user, &valence, Some(&email)).await?;
            let user = User::from_generated(
                generated_user,
                email,
                email_verified,
                display_name,
                account_id,
                roles,
            );
            let masked = mask_email_for_audit(&email_for_audit);
            leptos::logging::log!(
                "[audit][credential] event=signin email={masked} outcome=success detail=password_verified"
            );
            Ok(Some(user))
        } else {
            let masked = mask_email_for_audit(&email_for_audit);
            leptos::logging::log!(
                "[audit][credential] event=signin email={masked} outcome=failure detail=authentication_failed"
            );
            Ok(None)
        }
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        let valence = valence_from_factory(self.valence_factory.as_ref(), "get_user")?;

        let record_id = user_id.split(':').next_back().unwrap_or(user_id.as_str());
        let generated_user = GeneratedUser::get_used(record_id, &valence, valence::use_!(r"In **lepton host adapter**, we **load Generated User** so the application can decide what to do next in this workflow. The result is used by **lepton host adapter** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
            .await
            .map_err(|e| std::io::Error::other(format!("Get user error: {e}")))?;

        if let Some(generated_user) = generated_user {
            let (email, email_verified, display_name, account_id, roles) =
                resolve_session_fields(&generated_user, &valence, None).await?;
            let user = User::from_generated(
                &generated_user,
                email,
                email_verified,
                display_name,
                account_id,
                roles,
            );
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }
}

impl User {
    /// Convert to a [`SessionSnapshot`] for storage in Axum request extensions.
    pub fn to_session_snapshot(&self) -> SessionSnapshot {
        SessionIdentity::to_snapshot(self)
    }
}

pub use lepton_identity::auth::hash_password;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use valence::{
        register_backend_logical_names_slices, router_key, DatabaseBackend, DatabaseRouter,
        InMemoryBackend, RegisterBackendLogicalNamesOptions, MEM_ENGINE_ID,
    };

    #[test]
    fn opaque_session_stamp_is_stable() {
        let a = opaque_session_stamp("phc");
        let b = opaque_session_stamp("phc");
        assert_eq!(a, b);
        assert_ne!(a, opaque_session_stamp("other"));
    }

    #[test]
    fn mask_email_for_audit_keeps_domain() {
        assert_eq!(
            mask_email_for_audit("alice@example.com"),
            "a***@example.com"
        );
    }

    struct CaptureFactory {
        router: Arc<DatabaseRouter>,
        default_backend_key: String,
        builds: Mutex<Vec<serde_json::Value>>,
        fail: bool,
    }

    impl HiggsValenceFactory for CaptureFactory {
        fn build(&self, actor_json: &serde_json::Value) -> anyhow::Result<Valence> {
            self.builds
                .lock()
                .expect("builds lock")
                .push(actor_json.clone());
            if self.fail {
                anyhow::bail!("capture factory forced failure");
            }
            let actor: Actor = serde_json::from_value(actor_json.clone())
                .map_err(|e| anyhow::anyhow!("actor deserialize: {e}"))?;
            Valence::builder()
                .database_router(Arc::clone(&self.router))
                .default_backend_key(self.default_backend_key.clone())
                .with_actor(actor)
                .build()
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
    }

    fn mem_router() -> (Arc<DatabaseRouter>, String) {
        let backend: Arc<dyn DatabaseBackend> = Arc::new(InMemoryBackend::new());
        let mut router = DatabaseRouter::new();
        register_backend_logical_names_slices(
            &mut router,
            backend,
            &[&["default"]],
            RegisterBackendLogicalNamesOptions::default(),
        );
        (Arc::new(router), router_key("default", MEM_ENGINE_ID))
    }

    #[tokio::test]
    async fn backend_uses_higgs_valence_factory_happy() {
        let (router, key) = mem_router();
        let factory = Arc::new(CaptureFactory {
            router,
            default_backend_key: key,
            builds: Mutex::new(Vec::new()),
            fail: false,
        });
        let backend = Backend::new(factory.clone());
        let result = backend
            .authenticate(Credentials {
                email: "nobody@example.com".into(),
                password: "x".into(),
            })
            .await
            .expect("authenticate should not fail when factory succeeds");
        assert!(result.is_none());
        let first_build = {
            let builds = factory.builds.lock().expect("builds lock");
            assert_eq!(builds.len(), 1);
            builds[0].clone()
        };
        let actor: Actor = serde_json::from_value(first_build).expect("actor json from factory");
        assert!(matches!(
            actor,
            Actor::System {
                operation
            } if operation == "authenticate"
        ));
    }

    #[tokio::test]
    async fn backend_uses_higgs_valence_factory_sad() {
        let (router, key) = mem_router();
        let factory = Arc::new(CaptureFactory {
            router,
            default_backend_key: key,
            builds: Mutex::new(Vec::new()),
            fail: true,
        });
        let backend = Backend::new(factory);
        let err = backend
            .authenticate(Credentials {
                email: "nobody@example.com".into(),
                password: "x".into(),
            })
            .await
            .expect_err("factory failure must surface");
        assert!(err.to_string().contains("valence factory build"));
    }
}
