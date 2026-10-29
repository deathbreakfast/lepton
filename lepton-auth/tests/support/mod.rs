//! Shared Valence test helpers for integration tests.

#![allow(dead_code, clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use valence::{
    register_backend_logical_names_slices, router_key, Actor, CompiledQuery, DatabaseBackend,
    DatabaseRouter, InMemoryBackend, RecordId, RegisterBackendLogicalNamesOptions, Result, Valence,
    MEM_ENGINE_ID,
};

/// Wraps [`InMemoryBackend`] and treats unsupported unique-index DDL as success.
///
/// Git-tagged Valence mem returns `Internal` from `define_unique_index`; unique
/// probes still run via `SELECT VALUE id`, which mem understands.
#[derive(Debug)]
pub struct TolerantMemBackend {
    inner: InMemoryBackend,
    queries: QueryLog,
}

/// Every compiled query string a [`TolerantMemBackend`] ran, in order.
pub type QueryLog = Arc<Mutex<Vec<String>>>;

impl TolerantMemBackend {
    pub fn new() -> Self {
        Self::with_query_log(QueryLog::default())
    }

    pub fn with_query_log(queries: QueryLog) -> Self {
        Self {
            inner: InMemoryBackend::new(),
            queries,
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

    async fn use_namespace(&self, ns: &str, db_name: &str) -> Result<()> {
        self.inner.use_namespace(ns, db_name).await
    }

    async fn execute_compiled_query(
        &self,
        compiled: &CompiledQuery,
    ) -> Result<Vec<serde_json::Value>> {
        if let Ok(mut log) = self.queries.lock() {
            log.push(compiled.query_string.clone());
        }
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

    async fn ensure_schemaless_table(&self, table: &str) -> Result<()> {
        self.inner.ensure_schemaless_table(table).await
    }

    async fn get_record(&self, table: &str, id: &str) -> Result<Option<serde_json::Value>> {
        self.inner.get_record(table, id).await
    }

    async fn create_record(
        &self,
        table: &str,
        content: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.inner.create_record(table, content).await
    }

    async fn update_record(
        &self,
        table: &str,
        id: &str,
        content: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.inner.update_record(table, id, content).await
    }

    async fn merge_record(
        &self,
        table: &str,
        id: &str,
        patch: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.inner.merge_record(table, id, patch).await
    }

    async fn upsert_record(
        &self,
        table: &str,
        id: &str,
        content: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.inner.upsert_record(table, id, content).await
    }

    async fn delete_record(&self, table: &str, id: &str) -> Result<()> {
        self.inner.delete_record(table, id).await
    }

    async fn relate_edge(&self, from: &RecordId, edge_table: &str, to: &RecordId) -> Result<()> {
        self.inner.relate_edge(from, edge_table, to).await
    }

    async fn unrelate_edge(&self, from: &RecordId, edge_table: &str, to: &RecordId) -> Result<()> {
        self.inner.unrelate_edge(from, edge_table, to).await
    }

    async fn get_edge_targets(&self, from: &RecordId, edge_table: &str) -> Result<Vec<RecordId>> {
        self.inner.get_edge_targets(from, edge_table).await
    }

    async fn define_unique_index(&self, table: &str, field: &str) -> Result<()> {
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
    ) -> Result<()> {
        self.inner.apply_ttl_policy(table, policy).await
    }
}

/// System-actor Valence on tolerant in-memory storage.
pub async fn system_valence(operation: &str) -> Valence {
    valence_for_actor(
        Actor::System {
            operation: operation.to_string(),
        },
        operation,
    )
    .await
}

/// System-actor Valence whose backend records every compiled query it runs.
pub fn system_valence_with_query_log(operation: &str) -> (Valence, QueryLog) {
    let queries = QueryLog::default();
    let valence = build_valence(
        Actor::System {
            operation: operation.to_string(),
        },
        TolerantMemBackend::with_query_log(Arc::clone(&queries)),
    );
    (valence, queries)
}

/// Build a Valence handle with the given actor on a fresh tolerant mem router.
#[allow(clippy::unused_async)] // kept async so call sites can `.await` uniformly with other helpers
pub async fn valence_for_actor(actor: Actor, _label: &str) -> Valence {
    build_valence(actor, TolerantMemBackend::new())
}

fn build_valence(actor: Actor, backend: TolerantMemBackend) -> Valence {
    std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
    std::env::set_var("VALENCE_OWNERSHIP_COLOCATE", "0");

    let backend: Arc<dyn DatabaseBackend> = Arc::new(backend);
    let mut router = DatabaseRouter::new();
    register_backend_logical_names_slices(
        &mut router,
        backend,
        &[&["default"]],
        RegisterBackendLogicalNamesOptions::default(),
    );
    let default_backend_key = router_key("default", MEM_ENGINE_ID);
    Valence::builder()
        .database_router(Arc::new(router))
        .default_backend_key(default_backend_key)
        .with_actor(actor)
        .build()
        .expect("valence")
}

/// Clone `base` with a User actor whose `user_id` matches the record id (bare or `user:…`).
pub fn user_valence(base: &Valence, user_id: impl Into<String>) -> Valence {
    base.with_actor(Actor::User {
        user_id: user_id.into(),
    })
}
