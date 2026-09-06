//! In-process Valence + auth service boot for CI e2e and live CLI.

use std::sync::Arc;

use async_trait::async_trait;
use lepton_auth::services::{LeptonAuthServices, LeptonAuthServicesBuilder};
use lepton_sms::{SmsDeliveryService, SmsServiceBuilder, TestSmsAdapter};
use lepton_smtp::EmailServiceBuilder;
use valence::{
    register_backend_logical_names_slices, router_key, Actor, CompiledQuery, DatabaseBackend,
    DatabaseRouter, InMemoryBackend, RecordId, RegisterBackendLogicalNamesOptions, Valence,
    MEM_ENGINE_ID,
};

use crate::error::LiveVerifyError;

#[cfg(feature = "boson-delivery")]
static BOSON_LAB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Test services: Noop email + shared [`TestSmsAdapter`] for OTP capture.
pub struct TestServices {
    /// Injected auth services bundle.
    pub services: Arc<LeptonAuthServices>,
    /// Same test SMS adapter behind `services.sms` (for `recorded()`).
    pub test_sms: Arc<TestSmsAdapter>,
}

/// Shared Valence + auth services (+ Boson worker when `boson-delivery`).
///
/// Hold this for the whole test when durable delivery is on: the guard serializes
/// process-global [`boson_runtime::configure`] / [`DeliveryRuntime`](lepton_auth::delivery::DeliveryRuntime).
pub struct Lab {
    /// System-actor Valence on the lab mem router.
    pub valence: Valence,
    /// Injected auth services bundle.
    pub services: Arc<LeptonAuthServices>,
    /// Same test SMS adapter behind `services.sms` (for `recorded()`).
    pub test_sms: Arc<TestSmsAdapter>,
    #[cfg(feature = "boson-delivery")]
    _boson_guard: tokio::sync::MutexGuard<'static, ()>,
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
        // Git-tagged mem may wrap SELECT VALUE rows as `{"id": RecordId}`; unwrap so
        // unique-check ID parsing succeeds on update.
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

fn apply_valence_env_defaults() {
    if std::env::var_os("VALENCE_OWNERSHIP_UNIFIED_FETCH").is_none() {
        // SAFETY: e2e harness sets process defaults before any Valence build; not concurrent with other env mutation in this crate.
        unsafe {
            std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
        }
    }
    if std::env::var_os("VALENCE_OWNERSHIP_COLOCATE").is_none() {
        // SAFETY: same as above.
        unsafe {
            std::env::set_var("VALENCE_OWNERSHIP_COLOCATE", "0");
        }
    }
    // Sealed TOTP secrets require a key; CI/local e2e use the non-production test key.
    if std::env::var_os("LEPTON_TOTP_SEAL_KEY").is_none()
        && std::env::var_os("LEPTON_TOTP_ALLOW_TEST_SEAL_KEY").is_none()
    {
        // SAFETY: same as above — set once before the e2e host serves requests.
        unsafe {
            std::env::set_var("LEPTON_TOTP_ALLOW_TEST_SEAL_KEY", "1");
        }
    }
}

struct MemRouter {
    router: Arc<DatabaseRouter>,
    default_backend_key: String,
}

fn new_mem_router() -> MemRouter {
    let backend: Arc<dyn DatabaseBackend> = Arc::new(TolerantMemBackend::new());
    let mut router = DatabaseRouter::new();
    register_backend_logical_names_slices(
        &mut router,
        backend,
        &[&["default"]],
        RegisterBackendLogicalNamesOptions::default(),
    );
    MemRouter {
        router: Arc::new(router),
        default_backend_key: router_key("default", MEM_ENGINE_ID),
    }
}

/// System-actor Valence on tolerant in-memory storage.
pub async fn boot_valence(operation: &str) -> std::result::Result<Valence, LiveVerifyError> {
    apply_valence_env_defaults();
    let mem = new_mem_router();
    Valence::builder()
        .database_router(mem.router)
        .default_backend_key(mem.default_backend_key)
        .with_actor(Actor::System {
            operation: operation.to_string(),
        })
        .build()
        .map_err(|_| LiveVerifyError::config("valence_build"))
}

/// Noop email + Test SMS (shared adapter for OTP capture).
///
/// For durable enqueue (`boson-delivery`), use [`boot_lab`] so Valence and the Boson
/// worker share one mem router. This helper stays sync-path only.
pub fn boot_services_test() -> std::result::Result<TestServices, LiveVerifyError> {
    let test_sms = Arc::new(TestSmsAdapter::new());
    let sms: Arc<dyn SmsDeliveryService> = Arc::clone(&test_sms) as Arc<dyn SmsDeliveryService>;
    let email = EmailServiceBuilder::new()
        .noop()
        .build()
        .map_err(|_| LiveVerifyError::config("email_noop"))?;
    let services = Arc::new(
        LeptonAuthServicesBuilder::new()
            .email(email)
            .sms(
                SmsServiceBuilder::new()
                    .adapter(sms)
                    .build()
                    .map_err(|_| LiveVerifyError::config("sms_test"))?,
            )
            .public_base_url("http://127.0.0.1:3000")
            .build()
            .map_err(|_| LiveVerifyError::config("auth_services"))?,
    );
    Ok(TestServices { services, test_sms })
}

/// Boot Valence + test services; with `boson-delivery`, also wire MemQueue Boson on the
/// same router and install [`lepton_auth::delivery::DeliveryRuntime`].
pub async fn boot_lab(operation: &str) -> std::result::Result<Lab, LiveVerifyError> {
    apply_valence_env_defaults();

    #[cfg(feature = "boson-delivery")]
    let _boson_guard = BOSON_LAB_LOCK.lock().await;

    let mem = new_mem_router();
    let valence = Valence::builder()
        .database_router(Arc::clone(&mem.router))
        .default_backend_key(mem.default_backend_key.clone())
        .with_actor(Actor::System {
            operation: operation.to_string(),
        })
        .build()
        .map_err(|_| LiveVerifyError::config("valence_build"))?;

    let test_sms = Arc::new(TestSmsAdapter::new());
    let sms: Arc<dyn SmsDeliveryService> = Arc::clone(&test_sms) as Arc<dyn SmsDeliveryService>;
    let email = EmailServiceBuilder::new()
        .noop()
        .build()
        .map_err(|_| LiveVerifyError::config("email_noop"))?;

    #[cfg(feature = "boson-delivery")]
    {
        wire_boson_delivery(
            Arc::clone(&mem.router),
            &mem.default_backend_key,
            Arc::clone(&email),
            Some(Arc::clone(&sms)),
        )?;
    }

    let services = Arc::new(
        LeptonAuthServicesBuilder::new()
            .email(email)
            .sms(
                SmsServiceBuilder::new()
                    .adapter(sms)
                    .build()
                    .map_err(|_| LiveVerifyError::config("sms_test"))?,
            )
            .public_base_url("http://127.0.0.1:3000")
            .build()
            .map_err(|_| LiveVerifyError::config("auth_services"))?,
    );

    Ok(Lab {
        valence,
        services,
        test_sms,
        #[cfg(feature = "boson-delivery")]
        _boson_guard,
    })
}

/// Install [`DeliveryRuntime`](lepton_auth::delivery::DeliveryRuntime) + MemQueue Boson worker
/// on the given Valence router (same store the lab Valence uses).
#[cfg(feature = "boson-delivery")]
pub fn wire_boson_delivery(
    router: Arc<DatabaseRouter>,
    default_backend_key: &str,
    email: Arc<dyn lepton_smtp::EmailDeliveryService>,
    sms: Option<Arc<dyn SmsDeliveryService>>,
) -> std::result::Result<(), LiveVerifyError> {
    use boson_backend_mem::MemQueueBackend;
    use boson_runtime::{configure, Boson};
    use boson_valence_identity::{
        router_config_reject_external_system, ValenceExecutionContextFactory,
    };
    use lepton_auth::delivery::DeliveryRuntime;
    use valence::{ActorTrust, RouterValenceFactory};

    let mut builder = DeliveryRuntime::builder().email(email);
    if let Some(sms) = sms {
        builder = builder.sms(sms);
    }
    DeliveryRuntime::install(builder.build())
        .map_err(|_| LiveVerifyError::config("delivery_runtime"))?;

    let mut factory_cfg = router_config_reject_external_system(default_backend_key);
    factory_cfg.actor_trust = ActorTrust::Internal;
    let valence_factory = RouterValenceFactory::arc(router, factory_cfg);
    let exec_factory = ValenceExecutionContextFactory::new(valence_factory);
    let boson = Boson::builder()
        .queue_backend(Arc::new(MemQueueBackend::new()))
        .execution_context_factory(exec_factory)
        .auto_registry()
        .build()
        .map_err(|_| LiveVerifyError::config("boson_build"))?;
    configure(boson);
    Ok(())
}

/// Live Twilio email (SendGrid) + SMS from process env.
///
/// # Errors
///
/// [`LiveVerifyError::Config`] when required Twilio / from env vars are missing.
#[cfg(feature = "live-twilio")]
pub fn boot_services_twilio() -> std::result::Result<Arc<LeptonAuthServices>, LiveVerifyError> {
    use lepton_sms::{TwilioSmsConfig, TwilioVerifyConfig, TWILIO_VERIFY_SERVICE_SID_ENV};

    let email = EmailServiceBuilder::from_env()
        .map_err(|e| LiveVerifyError::config(format!("email_from_env: {e}")))?
        .build()
        .map_err(|e| LiveVerifyError::config(format!("email_build: {e}")))?;

    let verify_sid = std::env::var(TWILIO_VERIFY_SERVICE_SID_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let sms = if verify_sid.is_some() {
        let cfg = TwilioVerifyConfig::from_env()
            .map_err(|e| LiveVerifyError::config(format!("twilio_verify_env: {e}")))?;
        tracing::info!(
            sms_auth = %cfg.auth_fingerprint(),
            "boot_services_twilio"
        );
        eprintln!("lepton-live-verify: sms {}", cfg.auth_fingerprint());
        SmsServiceBuilder::new()
            .twilio_verify(cfg)
            .build()
            .map_err(|e| LiveVerifyError::config(format!("twilio_verify_build: {e}")))?
    } else {
        let cfg = TwilioSmsConfig::from_env()
            .map_err(|e| LiveVerifyError::config(format!("twilio_sms_env: {e}")))?;
        tracing::info!(
            sms_auth = %cfg.auth_fingerprint(),
            "boot_services_twilio"
        );
        eprintln!("lepton-live-verify: sms {}", cfg.auth_fingerprint());
        SmsServiceBuilder::new()
            .twilio(cfg)
            .build()
            .map_err(|e| LiveVerifyError::config(format!("twilio_sms_build: {e}")))?
    };

    let public_base_url =
        std::env::var("UF_PUBLIC_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
    LeptonAuthServicesBuilder::new()
        .email(email)
        .sms(sms)
        .public_base_url(public_base_url)
        .build()
        .map(Arc::new)
        .map_err(|e| LiveVerifyError::config(format!("auth_services: {e}")))
}

/// Valence + Twilio services (+ Boson worker when `boson-delivery`).
#[cfg(feature = "live-twilio")]
pub struct TwilioLab {
    /// System-actor Valence on the lab mem router.
    pub valence: Valence,
    /// Live Twilio email + SMS services.
    pub services: Arc<LeptonAuthServices>,
    #[cfg(feature = "boson-delivery")]
    _boson_guard: tokio::sync::MutexGuard<'static, ()>,
}

/// Boot shared Valence + Twilio adapters for `lepton-live-verify`.
#[cfg(feature = "live-twilio")]
pub async fn boot_lab_twilio(operation: &str) -> std::result::Result<TwilioLab, LiveVerifyError> {
    apply_valence_env_defaults();

    #[cfg(feature = "boson-delivery")]
    let _boson_guard = BOSON_LAB_LOCK.lock().await;

    let mem = new_mem_router();
    let valence = Valence::builder()
        .database_router(Arc::clone(&mem.router))
        .default_backend_key(mem.default_backend_key.clone())
        .with_actor(Actor::System {
            operation: operation.to_string(),
        })
        .build()
        .map_err(|_| LiveVerifyError::config("valence_build"))?;

    let services = boot_services_twilio()?;

    #[cfg(feature = "boson-delivery")]
    {
        wire_boson_delivery(
            Arc::clone(&mem.router),
            &mem.default_backend_key,
            Arc::clone(&services.email),
            Some(Arc::clone(&services.sms)),
        )?;
    }

    Ok(TwilioLab {
        valence,
        services,
        #[cfg(feature = "boson-delivery")]
        _boson_guard,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lepton_smtp::EmailDriver;

    #[test]
    fn boot_services_test_drivers_happy() {
        let svc = boot_services_test().expect("test services");
        assert_eq!(svc.services.email.driver(), EmailDriver::Noop);
        assert_eq!(svc.services.sms.driver_name(), "test");
    }

    #[cfg(feature = "live-twilio")]
    #[test]
    fn boot_services_twilio_missing_env_sad() {
        // Clear Twilio vars for this process slice (test isolation).
        for key in [
            "UF_EMAIL_DRIVER",
            "UF_TWILIO_EMAIL_API_KEY",
            "UF_TWILIO_ACCOUNT_SID",
            "UF_TWILIO_API_KEY",
            "UF_TWILIO_API_SECRET",
            "UF_TWILIO_AUTH_TOKEN",
            "UF_TWILIO_VERIFY_SERVICE_SID",
            "UF_TWILIO_FROM",
            "UF_EMAIL_FROM",
        ] {
            std::env::remove_var(key);
        }
        match boot_services_twilio() {
            Ok(_) => panic!("expected config error"),
            Err(err) => {
                assert_eq!(err.reason_class(), "config");
                let msg = err.to_string();
                assert!(!msg.contains("SG."));
                assert!(!msg.contains("AC"));
            }
        }
    }
}
