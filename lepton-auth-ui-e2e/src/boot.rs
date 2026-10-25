//! Valence + Higgs boot for the auth UI e2e host.
//!
//! Uses tolerant in-memory Valence (same pattern as `lepton-e2e` / auth integration
//! tests). `SQLite` rejects Surreal-shaped `SELECT VALUE` unique probes.

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use higgs::{HiggsConfig, HiggsValenceFactory};
use lepton_auth::services::LeptonAuthServicesBuilder;
use lepton_host_adapter::Backend;
use lepton_sms::{HttpCaptureSmsConfig, SmsServiceBuilder};
use lepton_smtp::{EmailServiceBuilder, SmtpConfig};
use valence::{
    register_backend_logical_names_slices, router_key, Actor, CompiledQuery, DatabaseBackend,
    DatabaseRouter, InMemoryBackend, RecordId, RegisterBackendLogicalNamesOptions, Valence,
    MEM_ENGINE_ID,
};

/// Shared process state for Axum + Leptos.
#[derive(Clone)]
pub struct AppState {
    /// Leptos configuration.
    pub leptos_options: leptos::config::LeptosOptions,
    /// Higgs boot config (Valence factory).
    pub higgs: Arc<HiggsConfig>,
    /// Valence router (also Axum `Extension`).
    pub valence_router: Arc<DatabaseRouter>,
    /// Default backend key (`mem`).
    pub default_backend_key: String,
}

impl axum::extract::FromRef<AppState> for leptos::config::LeptosOptions {
    fn from_ref(state: &AppState) -> Self {
        state.leptos_options.clone()
    }
}

struct MemHiggsFactory {
    router: Arc<DatabaseRouter>,
    default_backend_key: String,
}

impl HiggsValenceFactory for MemHiggsFactory {
    fn build(&self, actor_json: &serde_json::Value) -> anyhow::Result<Valence> {
        // Internal trust: allow System-shaped actors for `unsafe_system_valence`
        // (signup / reset). Do not install `external_actor_json_policy` here.
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

/// Wraps [`InMemoryBackend`] and treats unsupported unique-index DDL as success.
#[derive(Debug)]
struct TolerantMemBackend {
    inner: InMemoryBackend,
}

impl TolerantMemBackend {
    fn new() -> Self {
        Self {
            inner: InMemoryBackend::new(),
        }
    }
}

#[async_trait]
impl DatabaseBackend for TolerantMemBackend {
    fn engine_id(&self) -> &'static str {
        self.inner.engine_id()
    }

    fn capabilities(&self) -> valence::BackendCapabilities {
        self.inner.capabilities()
    }

    async fn use_namespace(&self, ns: &str, db_name: &str) -> valence::Result<()> {
        self.inner.use_namespace(ns, db_name).await
    }

    async fn execute_compiled_query(
        &self,
        compiled: &CompiledQuery,
    ) -> valence::Result<Vec<serde_json::Value>> {
        let rows = self.inner.execute_compiled_query(compiled).await?;
        if compiled
            .query_string
            .to_ascii_uppercase()
            .contains("SELECT VALUE")
        {
            return Ok(rows
                .into_iter()
                .map(|row| match row {
                    serde_json::Value::Object(mut obj)
                        if obj.len() == 1 && obj.contains_key("id") =>
                    {
                        obj.remove("id").unwrap_or(serde_json::Value::Null)
                    }
                    other => other,
                })
                .collect());
        }
        Ok(rows)
    }

    async fn ensure_schemaless_table(&self, table: &str) -> valence::Result<()> {
        self.inner.ensure_schemaless_table(table).await
    }

    async fn get_record(
        &self,
        table: &str,
        id: &str,
    ) -> valence::Result<Option<serde_json::Value>> {
        self.inner.get_record(table, id).await
    }

    async fn create_record(
        &self,
        table: &str,
        content: serde_json::Value,
    ) -> valence::Result<serde_json::Value> {
        self.inner.create_record(table, content).await
    }

    async fn update_record(
        &self,
        table: &str,
        id: &str,
        content: serde_json::Value,
    ) -> valence::Result<serde_json::Value> {
        self.inner.update_record(table, id, content).await
    }

    async fn merge_record(
        &self,
        table: &str,
        id: &str,
        patch: serde_json::Value,
    ) -> valence::Result<serde_json::Value> {
        self.inner.merge_record(table, id, patch).await
    }

    async fn upsert_record(
        &self,
        table: &str,
        id: &str,
        content: serde_json::Value,
    ) -> valence::Result<serde_json::Value> {
        self.inner.upsert_record(table, id, content).await
    }

    async fn delete_record(&self, table: &str, id: &str) -> valence::Result<()> {
        self.inner.delete_record(table, id).await
    }

    async fn relate_edge(
        &self,
        from: &RecordId,
        edge_table: &str,
        to: &RecordId,
    ) -> valence::Result<()> {
        self.inner.relate_edge(from, edge_table, to).await
    }

    async fn unrelate_edge(
        &self,
        from: &RecordId,
        edge_table: &str,
        to: &RecordId,
    ) -> valence::Result<()> {
        self.inner.unrelate_edge(from, edge_table, to).await
    }

    async fn get_edge_targets(
        &self,
        from: &RecordId,
        edge_table: &str,
    ) -> valence::Result<Vec<RecordId>> {
        self.inner.get_edge_targets(from, edge_table).await
    }

    async fn define_unique_index(&self, table: &str, field: &str) -> valence::Result<()> {
        match self.inner.define_unique_index(table, field).await {
            Ok(()) => Ok(()),
            // uf-valence-backend-mem 0.1.3+: "unique indexes not supported on in-memory backend"
            Err(valence::Error::Internal(msg))
                if msg.contains("define_unique_index")
                    || msg.contains("unique indexes not supported") =>
            {
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    fn ttl_capability(&self) -> valence::ttl::BackendTtlCapability {
        self.inner.ttl_capability()
    }

    async fn apply_ttl_policy(
        &self,
        table: &str,
        policy: &valence::ttl::SchemaTtlPolicy,
    ) -> valence::Result<()> {
        self.inner.apply_ttl_policy(table, policy).await
    }
}

/// A lab setting from the environment, or `default` when it's unset or
/// blank. The defaults match a single local host; the lane runner sets one
/// value per lane so each host gets its own mail, SMS and OIDC sidecars.
pub fn lab_env(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| default.to_owned())
}

/// Open in-memory Valence, register identity schemas, build Higgs + auth services.
#[allow(clippy::too_many_lines)] // platform boot: valence + schemas + Higgs + auth services
pub fn boot_platform() -> anyhow::Result<(
    AppState,
    Backend,
    Arc<lepton_auth::services::LeptonAuthServices>,
)> {
    // Force-link identity inventory schemas.
    let _ = lepton_identity::generated::UserStatus::Active;

    if std::env::var_os("VALENCE_OWNERSHIP_UNIFIED_FETCH").is_none() {
        std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
    }
    if std::env::var_os("VALENCE_OWNERSHIP_COLOCATE").is_none() {
        std::env::set_var("VALENCE_OWNERSHIP_COLOCATE", "0");
    }

    let backend: Arc<dyn DatabaseBackend> = Arc::new(TolerantMemBackend::new());
    let mut router = DatabaseRouter::new();
    register_backend_logical_names_slices(
        &mut router,
        backend,
        &[&["default"]],
        RegisterBackendLogicalNamesOptions::default(),
    );
    let default_backend_key = router_key("default", MEM_ENGINE_ID);
    let valence_router = Arc::new(router);

    let factory: Arc<dyn HiggsValenceFactory> = Arc::new(MemHiggsFactory {
        router: Arc::clone(&valence_router),
        default_backend_key: default_backend_key.clone(),
    });
    let higgs = Arc::new(
        HiggsConfig::builder()
            .valence_factory_arc(Arc::clone(&factory))
            .build()
            .context("HiggsConfig")?,
    );

    // Mailpit SMTP (plain) for confirm-funnel Playwright; see infra/mailpit.
    let email = EmailServiceBuilder::new()
        .smtp(
            SmtpConfig::builder()
                .host("127.0.0.1")
                .port(
                    lab_env("UF_SMTP_PORT", "1025")
                        .parse()
                        .context("UF_SMTP_PORT")?,
                )
                .use_tls(false)
                .from_email("noreply@example.test")
                .from_name("Lepton Auth")
                .build()?,
        )
        .build()?;
    // SMS HTTP sink (spawned from main, `UF_SMS_SINK_URL`, default :8099);
    // HttpCapture adapter for OTP asserts.
    let sms = SmsServiceBuilder::new()
        .http_capture(HttpCaptureSmsConfig::new(lab_env(
            "UF_SMS_SINK_URL",
            "http://127.0.0.1:8099",
        ))?)
        .build()?;
    #[cfg(feature = "boson-delivery")]
    {
        use boson_backend_mem::MemQueueBackend;
        use boson_runtime::{configure, Boson};
        use boson_valence_identity::{
            router_config_reject_external_system, ValenceExecutionContextFactory,
        };
        use lepton_auth::delivery::DeliveryRuntime;
        use valence::ActorTrust;

        DeliveryRuntime::install(DeliveryRuntime::builder().email(Arc::clone(&email)).build())
            .context("DeliveryRuntime::install")?;
        let mut factory_cfg = router_config_reject_external_system(&default_backend_key);
        factory_cfg.actor_trust = ActorTrust::Internal;
        let valence_factory =
            valence::RouterValenceFactory::arc(Arc::clone(&valence_router), factory_cfg);
        let exec_factory = ValenceExecutionContextFactory::new(valence_factory);
        let boson = Boson::builder()
            .queue_backend(Arc::new(MemQueueBackend::new()))
            .execution_context_factory(exec_factory)
            .auto_registry()
            .build()
            .context("Boson build")?;
        configure(boson);
    }
    let mock_issuer = lab_env("UF_MOCK_OIDC_URL", "http://127.0.0.1:5556");
    // The Playwright origin. A lane runner sets it per lane.
    let public_base_url = lab_env("UF_PUBLIC_BASE_URL", "http://localhost:3120");
    let oauth = lepton_auth::oauth::OAuthClientConfig {
        public_base_url: public_base_url.clone(),
        redirect_path: "/auth/oauth/callback".into(),
        google_client_id: None,
        google_client_secret: None,
        github_client_id: None,
        github_client_secret: None,
        use_mock_provider: true,
        mock_oidc_issuer_url: Some(mock_issuer),
        google_token_url: None,
        google_userinfo_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    };
    let auth_services = Arc::new(
        LeptonAuthServicesBuilder::new()
            .email(email)
            .sms(sms)
            .public_base_url(public_base_url.clone())
            .oauth(oauth)
            .webauthn_rp(lepton_auth::devices::WebauthnRpConfig {
                // Match the Playwright origin (`UF_PUBLIC_BASE_URL`).
                rp_id: "localhost".into(),
                rp_origin: public_base_url,
                rp_name: "Lepton".into(),
            })
            .build()?,
    );

    let auth_backend = Backend::new(factory);

    let conf = leptos::config::get_configuration(Some("Cargo.toml"))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let state = AppState {
        leptos_options: conf.leptos_options,
        higgs,
        valence_router,
        default_backend_key,
    };
    Ok((state, auth_backend, auth_services))
}

/// System Valence for seed / bootstrap.
pub fn system_valence(
    router: Arc<DatabaseRouter>,
    default_backend_key: &str,
) -> anyhow::Result<Valence> {
    Valence::builder()
        .database_router(router)
        .default_backend_key(default_backend_key.to_owned())
        .with_actor(Actor::System {
            operation: "lepton_auth_ui_e2e".to_string(),
        })
        .build()
        .map_err(|e| anyhow::anyhow!("{e}"))
}
