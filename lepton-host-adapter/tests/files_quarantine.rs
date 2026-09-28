//! Profile photo upload through meson's virus-scan quarantine.
//!
//! Drives `files_routes` over axum-login with a signed-in user on SQLite
//! `:memory:` and temp-dir `LocalDiskBlobStore`s. There is no Boson runtime
//! here, so [`run_scan_step`] makes the same adapter / promote calls meson's
//! `meson_virus_scan` task makes, under the System actor that task is
//! enqueued with.
//!
//! ```bash
//! cargo test -p lepton-host-adapter --features ssr --test files_quarantine
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::Extension;
use axum::http::{header, Request, StatusCode};
use axum::routing::post;
use axum::Router;
use axum_login::{AuthManagerLayerBuilder, AuthnBackend};
use chrono::Utc;
use higgs_core::HiggsValenceFactory;
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::files::{
    blob_stores_from_env, files_routes, BlobStoreConfigError, BlobStoreLayout, FileByteBackend,
    FileStoreError, FilesConfig, LocalDiskBlobStore, E2E_INFECTED_ENV, PROFILE_PHOTO_TABLE,
};
use lepton_host_adapter::{AuthSession, Backend, User};
use lepton_identity::generated::{
    Account, AccountEmail, AccountPlan, AccountStatus, FileFileStatus, ProfilePhoto,
    User as IdentityUser, UserStatus, UserUserType,
};
use meson::{FileFileStatus as MesonFileStatus, ScanVerdict};
use tokio::sync::{Mutex, MutexGuard};
use tower::ServiceExt;
use tower_sessions::{MemoryStore, SessionManagerLayer};
use valence::{
    register_backend_logical_names_slices, router_key, Actor, DatabaseBackend, DatabaseRouter,
    Model, RecordPredicate, RegisterBackendLogicalNamesOptions, SqliteBackend, Valence,
    SQLITE_ENGINE_ID,
};

const EMAIL: &str = "photo-owner@example.com";

/// 1x1 PNG.
const TINY_PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
    0xde, 0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41, 0x54, 0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00,
    0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x05, 0xfe, 0xd4, 0xef, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
    0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

/// Meson stores, scanner, adapters, and the `MESON_*` env are process-wide.
async fn global_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::const_new(());
    LOCK.lock().await
}

struct TestFactory {
    router: Arc<DatabaseRouter>,
    default_backend_key: String,
}

impl HiggsValenceFactory for TestFactory {
    fn build(&self, actor_json: &serde_json::Value) -> anyhow::Result<Valence> {
        let actor: Actor = serde_json::from_value(actor_json.clone())?;
        Ok(Valence::builder()
            .database_router(Arc::clone(&self.router))
            .default_backend_key(self.default_backend_key.clone())
            .with_actor(actor)
            .build()?)
    }
}

struct Harness {
    app: Router,
    cookie: String,
    user: User,
    /// Fixture seeding and inspection, and the actor the scan task runs as.
    system: Valence,
    available_root: PathBuf,
    quarantine_root: PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.available_root);
        let _ = std::fs::remove_dir_all(&self.quarantine_root);
    }
}

fn temp_root(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("lepton-files-{tag}-{nanos}"))
}

async fn seed_user(system: &Valence) -> valence::RecordId {
    let now = Utc::now();
    let user = IdentityUser::new(
        Some(UserUserType::Person),
        Some(hash_password("CorrectHorseBattery1!").unwrap()),
        Some(UserStatus::Active),
        None,
        None,
        None,
        None,
        None,
        now,
        now,
    )
    .unwrap();
    let user = IdentityUser::create(user, system, valence::use_!(r"**Test:** the profile photo quarantine suite seeds a signed-in **user** so uploads have an owner."))
        .await
        .unwrap();
    let user_id = user.id().cloned().unwrap();

    let account = Account::new(
        EMAIL.to_string(),
        user_id.clone(),
        Some(AccountPlan::Free),
        Some(AccountStatus::Active),
        None,
        None,
        now,
        now,
    )
    .unwrap();
    let account = Account::create(account, system, valence::use_!(r"**Test:** the profile photo quarantine suite seeds an **account** for the test user so the session carries an email."))
        .await
        .unwrap();
    let email = AccountEmail::new(
        account.id().cloned().unwrap(),
        EMAIL.to_string(),
        Some(now),
        now,
        now,
    )
    .unwrap();
    let email = AccountEmail::create(email, system, valence::use_!(r"**Test:** the profile photo quarantine suite seeds the test user's **email address**, which the upload uses to create a profile."))
        .await
        .unwrap();
    user.get_mutable(system, valence::use_!(r"**Test:** the profile photo quarantine suite links the seeded **email address** to the test user."))
        .set_primary_email(email.id().cloned().unwrap())
        .unwrap()
        .commit()
        .await
        .unwrap();
    user_id
}

async fn test_login(
    mut auth: AuthSession<Backend>,
    Extension(user): Extension<User>,
) -> StatusCode {
    match auth.login(&user).await {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Build the stores and routes, sign the seeded user in, and return the harness.
async fn harness(tag: &str) -> Harness {
    // SQLite cannot run Valence's unified ownership fetch; same as the crate example.
    std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
    meson::clear_virus_scanner_for_test();

    let db: Arc<dyn DatabaseBackend> = Arc::new(SqliteBackend::connect_memory().await.unwrap());
    let mut router = DatabaseRouter::new();
    register_backend_logical_names_slices(
        &mut router,
        db,
        &[&["default"]],
        RegisterBackendLogicalNamesOptions::default(),
    );
    let router = Arc::new(router);
    let key = router_key("default", SQLITE_ENGINE_ID);

    let system = Valence::builder()
        .database_router(Arc::clone(&router))
        .default_backend_key(key.clone())
        .with_actor(Actor::System {
            operation: "files_quarantine_test".to_string(),
        })
        .build()
        .unwrap();
    let user_id = seed_user(&system).await;

    let backend = Backend::new(Arc::new(TestFactory {
        router: Arc::clone(&router),
        default_backend_key: key.clone(),
    }));
    let user = backend
        .get_user(&user_id.to_string())
        .await
        .unwrap()
        .expect("seeded user loads through the auth backend");

    let available_root = temp_root(&format!("{tag}-available"));
    let quarantine_root = temp_root(&format!("{tag}-quarantine"));
    let layout = BlobStoreLayout {
        available: Arc::new(LocalDiskBlobStore::new(available_root.clone()))
            as Arc<dyn FileByteBackend>,
        quarantine: Arc::new(LocalDiskBlobStore::new(quarantine_root.clone())),
    };

    let session_layer = SessionManagerLayer::new(MemoryStore::default()).with_secure(false);
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();
    let app = Router::new()
        .route("/test-login", post(test_login))
        .merge(files_routes(layout, FilesConfig::new(key)))
        .layer(Extension(user.clone()))
        .layer(Extension(router))
        .layer(auth_layer);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let cookie = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(!cookie.is_empty(), "login must set a session cookie");

    Harness {
        app,
        cookie,
        user,
        system,
        available_root,
        quarantine_root,
    }
}

const BOUNDARY: &str = "lepton-files-test-boundary";

fn multipart_png(name: &str) -> Vec<u8> {
    let mut body = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: image/png\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(TINY_PNG);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

async fn upload(h: &Harness, cookie: Option<&str>) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/files/upload")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        );
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    let res = h
        .app
        .clone()
        .oneshot(req.body(Body::from(multipart_png("avatar.png"))).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::Value::String(String::from_utf8_lossy(&bytes).into()));
    (status, json)
}

async fn serve(h: &Harness, bare_id: &str) -> (StatusCode, Vec<u8>) {
    let res = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/files/{bare_id}"))
                .header(header::COOKIE, &h.cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, bytes.to_vec())
}

fn bare(record_id: &str) -> String {
    record_id.rsplit(':').next().unwrap().to_string()
}

async fn load_photo(h: &Harness, bare_id: &str) -> ProfilePhoto {
    ProfilePhoto::get(bare_id, &h.system, valence::use_!(r"**Test:** the profile photo quarantine suite reads back an uploaded **photo record** to check its scan status and storage location."))
        .await
        .unwrap()
        .expect("uploaded photo row exists")
}

async fn read_store(root: &Path, key: &str) -> Result<Vec<u8>, FileStoreError> {
    LocalDiskBlobStore::new(root.to_path_buf()).get(key).await
}

/// One pass of meson's `meson_virus_scan` task body, minus Boson.
///
/// Returns `true` when the installed scanner reported the bytes clean.
async fn run_scan_step(h: &Harness, bare_id: &str) -> bool {
    let snap = meson::load_file_for_scan(&h.system, PROFILE_PHOTO_TABLE, bare_id)
        .await
        .unwrap();
    assert!(matches!(
        snap.file_status,
        MesonFileStatus::PendingVirusScan
    ));
    let bytes = meson::installed_quarantine_store()
        .unwrap()
        .get(&snap.storage_path)
        .await
        .unwrap();
    match meson::resolve_virus_scanner().scan(&bytes).await.unwrap() {
        ScanVerdict::Clean => {
            let path = meson::promote_to_available(&snap.storage_path)
                .await
                .unwrap();
            meson::commit_file_available(&h.system, PROFILE_PHOTO_TABLE, bare_id, path)
                .await
                .unwrap();
            true
        }
        ScanVerdict::Infected { .. } => {
            meson::commit_file_quarantined(&h.system, PROFILE_PHOTO_TABLE, bare_id)
                .await
                .unwrap();
            false
        }
    }
}

#[tokio::test]
async fn upload_lands_in_quarantine_and_is_not_served_happy() {
    let _g = global_lock().await;
    std::env::remove_var("MESON_VIRUS_SCAN");
    let h = harness("quarantine-put").await;

    let (status, json) = upload(&h, Some(&h.cookie)).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["file_status"], "pending_virus_scan");
    let id = bare(json["id"].as_str().unwrap());

    let photo = load_photo(&h, &id).await;
    assert!(matches!(
        photo.file_status(),
        FileFileStatus::PendingVirusScan
    ));
    assert_eq!(photo.uploaded_by(), &h.user.id);
    let key = photo.storage_path().clone();
    assert_eq!(
        read_store(&h.quarantine_root, &key).await.unwrap(),
        TINY_PNG
    );
    assert!(matches!(
        read_store(&h.available_root, &key).await,
        Err(FileStoreError::NotFound)
    ));

    let (status, _) = serve(&h, &id).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn clean_scan_promotes_and_serves_happy() {
    let _g = global_lock().await;
    std::env::remove_var("MESON_VIRUS_SCAN");
    std::env::remove_var(E2E_INFECTED_ENV);
    let h = harness("promote").await;

    let (status, json) = upload(&h, Some(&h.cookie)).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let id = bare(json["id"].as_str().unwrap());

    assert!(
        run_scan_step(&h, &id).await,
        "default scanner is AlwaysClean"
    );

    let photo = load_photo(&h, &id).await;
    assert!(matches!(photo.file_status(), FileFileStatus::Available));
    let key = photo.storage_path().clone();
    assert_eq!(read_store(&h.available_root, &key).await.unwrap(), TINY_PNG);
    assert!(matches!(
        read_store(&h.quarantine_root, &key).await,
        Err(FileStoreError::NotFound)
    ));

    let (status, body) = serve(&h, &id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, TINY_PNG);
}

#[tokio::test]
async fn infected_scan_stays_quarantined_sad() {
    let _g = global_lock().await;
    std::env::remove_var("MESON_VIRUS_SCAN");
    std::env::set_var(E2E_INFECTED_ENV, "1");
    let h = harness("infected").await;
    std::env::remove_var(E2E_INFECTED_ENV);

    let (status, json) = upload(&h, Some(&h.cookie)).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let id = bare(json["id"].as_str().unwrap());

    assert!(
        !run_scan_step(&h, &id).await,
        "MESON_E2E_INFECTED=1 installs AlwaysInfectedScanner"
    );

    let photo = load_photo(&h, &id).await;
    assert!(matches!(photo.file_status(), FileFileStatus::Quarantined));
    let key = photo.storage_path().clone();
    assert_eq!(
        read_store(&h.quarantine_root, &key).await.unwrap(),
        TINY_PNG
    );
    assert!(matches!(
        read_store(&h.available_root, &key).await,
        Err(FileStoreError::NotFound)
    ));

    let (status, _) = serve(&h, &id).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn missing_quarantine_store_rejects_upload_sad() {
    let _g = global_lock().await;
    std::env::remove_var("MESON_VIRUS_SCAN");
    let h = harness("no-quarantine").await;
    meson::clear_quarantine_store_for_test();

    let (status, json) = upload(&h, Some(&h.cookie)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(json, "Storage not configured");

    let row = ProfilePhoto::query(&h.system, valence::use_!(r"**Test:** the profile photo quarantine suite checks that a rejected upload left **no photo record** behind."))
        .where_uploaded_by(RecordPredicate::Equals(h.user.id.clone()))
        .first()
        .await
        .unwrap();
    assert!(row.is_none(), "no photo row without a quarantine store");
    assert!(
        !h.available_root.exists()
            || std::fs::read_dir(&h.available_root)
                .unwrap()
                .next()
                .is_none()
    );
}

#[tokio::test]
async fn unauthenticated_upload_sad() {
    let _g = global_lock().await;
    let h = harness("anon").await;
    let (status, _) = upload(&h, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn virus_scan_off_serves_immediately_happy() {
    let _g = global_lock().await;
    std::env::set_var("MESON_VIRUS_SCAN", "off");
    let h = harness("scan-off").await;

    let (status, json) = upload(&h, Some(&h.cookie)).await;
    std::env::remove_var("MESON_VIRUS_SCAN");
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["file_status"], "available");
    let id = bare(json["id"].as_str().unwrap());

    let photo = load_photo(&h, &id).await;
    let key = photo.storage_path().clone();
    assert_eq!(read_store(&h.available_root, &key).await.unwrap(), TINY_PNG);
    let (status, body) = serve(&h, &id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, TINY_PNG);
}

#[tokio::test]
async fn blob_stores_from_env_honors_quarantine_root_happy() {
    let _g = global_lock().await;
    let root = temp_root("env-quarantine");
    std::env::set_var("MESON_BLOB_BACKEND", "local");
    std::env::set_var("MESON_LOCAL_QUARANTINE_ROOT", &root);
    let layout = blob_stores_from_env();
    std::env::remove_var("MESON_LOCAL_QUARANTINE_ROOT");
    std::env::remove_var("MESON_BLOB_BACKEND");

    let layout = layout.unwrap();
    layout.quarantine.put("probe.png", TINY_PNG).await.unwrap();
    assert_eq!(read_store(&root, "probe.png").await.unwrap(), TINY_PNG);
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn blob_stores_from_env_unknown_backend_sad() {
    let _g = global_lock().await;
    std::env::set_var("MESON_BLOB_BACKEND", "nope");
    let err = blob_stores_from_env().err();
    std::env::remove_var("MESON_BLOB_BACKEND");
    assert!(matches!(err, Some(BlobStoreConfigError::UnknownBackend(_))));
}
