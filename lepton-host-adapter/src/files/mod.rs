//! Profile photo upload / serve over Axum (`/api/files/*`).
//!
//! Authenticates the caller and checks ownership before creating System Valence
//! `ProfilePhoto` records. Byte I/O runs through Meson dual stores (quarantine
//! when virus scan is on; available after a clean scan).
//!
//! # Concern → API
//!
//! | Concern | API |
//! |---------|-----|
//! | Mount routes | [`crate::files::files_routes`] |
//! | Upload | [`crate::files::upload_handler`] |
//! | Serve | [`crate::files::serve_handler`] |
//! | Bytes | [`crate::files::FileByteBackend`], [`crate::files::BlobStoreLayout`], [`crate::files::blob_stores_from_env`] |
//!
//! # Examples
//!
//! Mount upload + serve routes inside the auth / session stack:
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use lepton_host_adapter::files::{
//!     blob_stores_from_env, files_routes, FilesConfig, LocalDiskBlobStore,
//! };
//! use meson::BlobStoreLayout;
//!
//! let layout = blob_stores_from_env().unwrap_or_else(|_| BlobStoreLayout {
//!     available: Arc::new(LocalDiskBlobStore::default_uploads()),
//!     quarantine: Arc::new(LocalDiskBlobStore::new("uploads-quarantine")),
//! });
//! let app = Router::new()
//!     .merge(files_routes(layout, FilesConfig::new(default_backend_key)))
//!     .layer(session_snapshot_middleware)
//!     .layer(auth_layer)
//!     .layer(Extension(valence_router));
//! ```

mod backend;
mod scan_adapter;

pub use backend::{
    blob_store_from_env, blob_stores_from_env, BlobStoreConfigError, BlobStoreLayout,
    FileByteBackend, FileStoreError, LocalDiskBlobStore,
};
pub use scan_adapter::ProfilePhotoScanAdapter;

use crate::auth::{Backend, User};
use axum::body::Body;
use axum::extract::{Extension, Multipart, Path};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_login::AuthSession;
use chrono::Utc;
use lepton_identity::generated::{FileFileStatus, ProfilePhoto, UserProfile};
use meson::events::publish_file_updated;
use meson::{
    create_with_put, enqueue_virus_scan, get_installed_object, install_blob_store,
    install_quarantine_store, install_virus_scanner, register_file_scan_adapter,
    AlwaysCleanScanner, AlwaysInfectedScanner, FileCreateMeta, FileFileStatus as MesonFileStatus,
    FileUploadError,
};
use std::sync::{Arc, Once};
use tracing::{info_span, Instrument};
use valence::{Actor, DatabaseRouter, Model, RecordId, RecordPredicate, Valence};

const MAX_FILE_SIZE: usize = 5 * 1024 * 1024;
const ALLOWED_EXTENSIONS: &[&str] = &["png", "jpeg", "jpg", "gif", "webp"];

static PROFILE_PHOTO_SCAN_ADAPTER: Once = Once::new();

fn ensure_profile_photo_scan_adapter() {
    PROFILE_PHOTO_SCAN_ADAPTER.call_once(|| {
        register_file_scan_adapter(
            "profile_photo",
            Arc::new(ProfilePhotoScanAdapter::default()),
        );
    });
}

fn lepton_status_from_meson(status: &MesonFileStatus) -> FileFileStatus {
    FileFileStatus::from_str(status.as_str()).unwrap_or(FileFileStatus::PendingVirusScan)
}

/// Host-supplied Valence routing key for [`files_routes`].
#[derive(Clone, Debug)]
pub struct FilesConfig {
    /// Compound router key (same as Higgs / boot `default_backend_key`).
    pub default_backend_key: String,
}

impl FilesConfig {
    /// Construct from a boot-time default backend key.
    pub fn new(default_backend_key: impl Into<String>) -> Self {
        Self {
            default_backend_key: default_backend_key.into(),
        }
    }
}

/// Validate filename extension and byte length before storage.
///
/// Returns `(extension, mime)` on success.
pub fn validate_upload_meta(
    original_name: &str,
    size_bytes: usize,
) -> Result<(String, &'static str), (StatusCode, String)> {
    if size_bytes > MAX_FILE_SIZE {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("File exceeds maximum size of {MAX_FILE_SIZE} bytes"),
        ));
    }
    let extension = original_name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_lowercase();
    if !ALLOWED_EXTENSIONS.contains(&extension.as_str()) {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!(
                "File type '{extension}' not allowed. Allowed: {}",
                ALLOWED_EXTENSIONS.join(", ")
            ),
        ));
    }
    Ok((extension.clone(), extension_to_mime(&extension)))
}

/// When the client sends `profile_id`, it must match the session-owned profile bare id.
pub fn assert_profile_id_owned(
    form_profile_id: Option<&str>,
    owned_bare_id: &str,
) -> Result<(), (StatusCode, String)> {
    match form_profile_id {
        None | Some("") => Ok(()),
        Some(id) if id == owned_bare_id => Ok(()),
        Some(_) => Err((
            StatusCode::FORBIDDEN,
            "profile_id does not match the signed-in user".to_string(),
        )),
    }
}

fn extension_to_mime(ext: &str) -> &'static str {
    match ext {
        "png" => "image/png",
        "jpeg" | "jpg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        _ => "application/octet-stream",
    }
}

fn bare_id(record: &RecordId) -> String {
    valence::extract_id_from_record(record).unwrap_or_else(|_| record.id().to_string())
}

fn system_valence(
    router: Arc<DatabaseRouter>,
    default_backend_key: &str,
    operation: &str,
) -> Result<Valence, (StatusCode, String)> {
    Valence::builder()
        .database_router(router)
        .default_backend_key(default_backend_key.to_owned())
        .with_actor(Actor::System {
            operation: operation.to_string(),
        })
        .build()
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to open Valence".to_string(),
            )
        })
}

fn user_valence(
    router: Arc<DatabaseRouter>,
    default_backend_key: &str,
    user: &User,
) -> Result<Valence, (StatusCode, String)> {
    Valence::builder()
        .database_router(router)
        .default_backend_key(default_backend_key.to_owned())
        .with_actor(Actor::User {
            user_id: bare_id(&user.id),
        })
        .build()
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to open Valence".to_string(),
            )
        })
}

/// Router fragment: `POST /api/files/upload`, `GET /api/files/{id}`.
///
/// Merge inside the auth / session layer stack. Hosts must also layer
/// `Extension(Arc<DatabaseRouter>)` (already common) and pass the same
/// `default_backend_key` used for Higgs.
///
/// Installs both stores from `layout`, registers the profile-photo scan adapter,
/// and installs [`AlwaysCleanScanner`] as the default virus scanner.
///
/// When `MESON_E2E_INFECTED=1`, installs [`AlwaysInfectedScanner`] instead so
/// embedded Playwright can assert the Quarantined sad path.
pub fn files_routes<S>(layout: BlobStoreLayout, config: FilesConfig) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    ensure_profile_photo_scan_adapter();
    let _ = install_blob_store(Arc::clone(&layout.available));
    let _ = install_quarantine_store(Arc::clone(&layout.quarantine));
    if std::env::var("MESON_E2E_INFECTED").ok().as_deref() == Some("1") {
        install_virus_scanner(Arc::new(AlwaysInfectedScanner));
    } else {
        install_virus_scanner(Arc::new(AlwaysCleanScanner));
    }
    let available = Arc::clone(&layout.available);
    Router::<S>::new()
        .route("/api/files/upload", post(upload_handler))
        .route("/api/files/{id}", get(serve_handler))
        .layer(Extension(available))
        .layer(Extension(config))
}

type HttpErr = (StatusCode, String);

async fn read_upload_multipart(
    multipart: &mut Multipart,
) -> Result<(Vec<u8>, String, Option<String>), HttpErr> {
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut original_name: Option<String> = None;
    let mut form_profile_id: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "Multipart error".to_string()))?
    {
        let field_name = field.name().unwrap_or_default().to_string();
        match field_name.as_str() {
            "file" => {
                original_name = field.file_name().map(str::to_string);
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|_| (StatusCode::BAD_REQUEST, "Failed to read file".to_string()))?;
                file_bytes = Some(bytes.to_vec());
            }
            "profile_id" => {
                let text = field.text().await.map_err(|_| {
                    (
                        StatusCode::BAD_REQUEST,
                        "Failed to read profile_id".to_string(),
                    )
                })?;
                form_profile_id = Some(text);
            }
            _ => {}
        }
    }

    let file_bytes =
        file_bytes.ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'file' field".to_string()))?;
    let original_name =
        original_name.ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing filename".to_string()))?;
    Ok((file_bytes, original_name, form_profile_id))
}

async fn load_or_create_session_profile(
    session_v: &Valence,
    user: &User,
) -> Result<UserProfile, HttpErr> {
    let user_thing = user.id.clone();
    let profile = UserProfile::query(session_v)
        .where_user(RecordPredicate::Equals(user_thing.clone()))
        .first()
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to query profile".to_string(),
            )
        })?;

    if let Some(p) = profile {
        return Ok(p);
    }

    let email = user.email.clone();
    let now = Utc::now();
    let new_profile =
        UserProfile::new(user_thing, email.clone(), email, now, now, None).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build profile".to_string(),
            )
        })?;
    UserProfile::create(new_profile, session_v)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create profile".to_string(),
            )
        })
}

fn map_upload_err(err: FileUploadError) -> HttpErr {
    match err {
        FileUploadError::InvalidExtension => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Invalid file extension".to_string(),
        ),
        FileUploadError::BlobStoreNotInstalled => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage not configured".to_string(),
        ),
        FileUploadError::Store(_) | FileUploadError::Valence(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error".to_string(),
        ),
    }
}

async fn create_photo_and_set_active(
    valence_router: Arc<DatabaseRouter>,
    backend_key: &str,
    user: &User,
    profile: &UserProfile,
    original_name: String,
    extension: String,
    mime: &'static str,
    file_bytes: &[u8],
) -> Result<(RecordId, i64), HttpErr> {
    let profile_ref = profile.id().cloned().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Missing profile id".to_string(),
        )
    })?;

    let system_v = system_valence(Arc::clone(&valence_router), backend_key, "file_upload")?;
    let meta = FileCreateMeta {
        file_name: original_name,
        file_extension: extension,
        mime_type: mime.to_string(),
        uploaded_by: user.id.clone(),
    };

    let created = create_with_put(
        &system_v,
        meta,
        file_bytes,
        |meta, storage_path, size_bytes, file_status, uploaded_at| async move {
            ProfilePhoto::new(
                profile_ref,
                None,
                None,
                meta.file_name,
                meta.file_extension,
                meta.mime_type,
                size_bytes,
                storage_path,
                lepton_status_from_meson(&file_status),
                meta.uploaded_by,
                uploaded_at,
            )
            .map_err(FileUploadError::Valence)
        },
    )
    .await
    .map_err(map_upload_err)?;

    let size_bytes = *created.size_bytes();
    let photo_id = created.id().cloned().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Missing photo id".to_string(),
        )
    })?;

    if matches!(created.file_status(), FileFileStatus::PendingVirusScan) {
        let bare = bare_id(&photo_id);
        let user_bare = bare_id(&user.id);
        publish_file_updated(
            &user_bare,
            &bare,
            MesonFileStatus::PendingVirusScan.as_str(),
        )
        .await;
        if let Err(e) = enqueue_virus_scan("profile_photo", &bare).await {
            tracing::warn!(
                target: "lepton.files.upload",
                outcome = "enqueue_virus_scan_failed",
                error = %e,
                "profile photo uploaded but virus scan enqueue failed"
            );
        }
    }

    let session_v = user_valence(valence_router, backend_key, user)?;
    let profile = UserProfile::query(&session_v)
        .where_user(RecordPredicate::Equals(user.id.clone()))
        .first()
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to reload profile".to_string(),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Profile missing".to_string(),
            )
        })?;

    profile
        .get_mutable(&session_v)
        .set_active_photo(photo_id.clone())
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to set active photo".to_string(),
            )
        })?
        .commit()
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to commit active photo".to_string(),
            )
        })?;

    Ok((photo_id, size_bytes))
}

/// POST `/api/files/upload` — multipart `file` + optional `profile_id`.
pub async fn upload_handler(
    auth: AuthSession<Backend>,
    Extension(valence_router): Extension<Arc<DatabaseRouter>>,
    Extension(_backend): Extension<Arc<dyn FileByteBackend>>,
    Extension(files_config): Extension<FilesConfig>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let span = info_span!("lepton.files.upload");
    async move {
        let user = auth
            .user
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Not authenticated".to_string()))?;

        let (file_bytes, original_name, form_profile_id) =
            read_upload_multipart(&mut multipart).await?;
        let (extension, mime) = validate_upload_meta(&original_name, file_bytes.len())?;
        let backend_key = files_config.default_backend_key.as_str();

        let session_v = user_valence(Arc::clone(&valence_router), backend_key, &user)?;
        let profile = load_or_create_session_profile(&session_v, &user).await?;

        let owned_bare = profile.id().map(bare_id).ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Missing profile id".to_string(),
            )
        })?;
        assert_profile_id_owned(form_profile_id.as_deref(), &owned_bare)?;

        let (photo_id, size_bytes) = create_photo_and_set_active(
            valence_router,
            backend_key,
            &user,
            &profile,
            original_name.clone(),
            extension.clone(),
            mime,
            &file_bytes,
        )
        .await?;

        tracing::info!(
            outcome = "ok",
            size_bytes,
            extension = %extension,
            "profile photo uploaded"
        );

        let photo_url = format!("/api/files/{}", photo_id.id());
        Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "id": photo_id.to_string(),
                "url": photo_url,
                "file_name": original_name,
                "size_bytes": size_bytes,
            })),
        ))
    }
    .instrument(span)
    .await
}

/// GET `/api/files/{id}` — cookie-authenticated same-origin serve.
///
/// Refuses non-`Available` rows (403). Never reads the quarantine store.
pub async fn serve_handler(
    auth: AuthSession<Backend>,
    Extension(valence_router): Extension<Arc<DatabaseRouter>>,
    Extension(_backend): Extension<Arc<dyn FileByteBackend>>,
    Extension(files_config): Extension<FilesConfig>,
    Path(id): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let span = info_span!("lepton.files.serve");
    async move {
        let user = auth
            .user
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Not authenticated".to_string()))?;

        let backend_key = files_config.default_backend_key.as_str();
        let session_v = user_valence(Arc::clone(&valence_router), backend_key, &user)?;
        // Privacy denial is Err(Error::Privacy); treat the same as missing —
        // never elevate to System to re-fetch (uf-no-actor-elevation).
        let Ok(Some(photo)) = ProfilePhoto::get(&id, &session_v).await else {
            return Err((StatusCode::NOT_FOUND, "File not found".to_string()));
        };

        if !matches!(photo.file_status(), FileFileStatus::Available) {
            return Err((StatusCode::FORBIDDEN, "File is not available".to_string()));
        }

        let bytes = get_installed_object(photo.storage_path())
            .await
            .map_err(|e| match e {
                FileStoreError::NotFound | FileStoreError::NotAvailable { .. } => {
                    (StatusCode::NOT_FOUND, "File not found".to_string())
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to read file".to_string(),
                ),
            })?;

        let mime = photo.mime_type().clone();
        tracing::info!(outcome = "ok", "profile photo served");

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime)
            .header(
                header::CONTENT_DISPOSITION,
                format!("inline; filename=\"{}\"", photo.file_name()),
            )
            .body(Body::from(bytes))
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to build response".to_string(),
                )
            })
    }
    .instrument(span)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_upload_meta_accepts_png_happy() {
        let (ext, mime) = validate_upload_meta("avatar.PNG", 100).unwrap();
        assert_eq!(ext, "png");
        assert_eq!(mime, "image/png");
    }

    #[test]
    fn validate_upload_meta_rejects_exe_sad() {
        let err = validate_upload_meta("x.exe", 10).unwrap_err();
        assert_eq!(err.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn validate_upload_meta_rejects_oversize_sad() {
        let err = validate_upload_meta("x.png", MAX_FILE_SIZE + 1).unwrap_err();
        assert_eq!(err.0, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn assert_profile_id_owned_mismatch_sad() {
        let err = assert_profile_id_owned(Some("other"), "mine").unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn assert_profile_id_owned_match_happy() {
        assert_profile_id_owned(Some("mine"), "mine").unwrap();
        assert_profile_id_owned(None, "mine").unwrap();
    }
}
