//! Profile photo upload / serve over Axum (`/api/files/*`).
//!
//! Authenticates the caller and checks ownership before creating System Valence
//! `ProfilePhoto` records. Bytes live in the platform `meson` crate's two
//! stores, described by a [`crate::files::BlobStoreLayout`]:
//!
//! - **Quarantine.** New uploads land here while virus scan is on (the
//!   default; `MESON_VIRUS_SCAN=off` turns it off). The photo row starts as
//!   `pending_virus_scan`, a `meson.file.updated` Photon event goes to the
//!   uploader, and meson's `meson_virus_scan` Boson task is enqueued.
//! - **Available.** A clean scan promotes the bytes here and marks the row
//!   `available`. An infected scan marks the row `quarantined` and leaves the
//!   bytes where they are. With virus scan off, uploads go straight here.
//!
//! [`crate::files::serve_handler`] only serves `available` rows, and only from the
//! available store.
//!
//! Hosts that mount [`crate::files::files_routes`] with virus scan on must also
//! run a Boson worker that links meson's `meson_virus_scan` task (`meson`
//! feature `scan-pipeline`). Without one, uploads stay pending and are never
//! served.
//!
//! # Concern → API
//!
//! | Concern | API |
//! |---------|-----|
//! | Mount routes | [`crate::files::files_routes`] |
//! | Upload | [`crate::files::upload_handler`] |
//! | Serve | [`crate::files::serve_handler`] |
//! | Stores | [`crate::files::blob_stores_from_env`], [`crate::files::BlobStoreLayout`], [`crate::files::FileByteBackend`], [`crate::files::LocalDiskBlobStore`] (re-exported from `meson`) |
//! | Scan worker hook | [`crate::files::ProfilePhotoScanAdapter`] (registered by [`crate::files::files_routes`]) |
//!
//! # Examples
//!
//! Mount upload + serve routes inside the auth / session stack:
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use lepton_host_adapter::files::{
//!     blob_stores_from_env, files_routes, BlobStoreLayout, FileByteBackend, FilesConfig,
//!     LocalDiskBlobStore,
//! };
//!
//! let layout = blob_stores_from_env().unwrap_or_else(|_| BlobStoreLayout {
//!     available: Arc::new(LocalDiskBlobStore::default_uploads()) as Arc<dyn FileByteBackend>,
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
pub use scan_adapter::{ProfilePhotoScanAdapter, PROFILE_PHOTO_TABLE};

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
    enqueue_virus_scan, get_installed_object, install_blob_store, install_quarantine_store,
    install_virus_scanner, installed_virus_scanner, put_new_object, register_file_scan_adapter,
    virus_scan_enabled, AlwaysCleanScanner, AlwaysInfectedScanner, FileUploadError,
};
use std::sync::Arc;
use tracing::{info_span, Instrument};
use valence::{Actor, DatabaseRouter, Model, RecordId, RecordPredicate, Valence};

const MAX_FILE_SIZE: usize = 5 * 1024 * 1024;
const ALLOWED_EXTENSIONS: &[&str] = &["png", "jpeg", "jpg", "gif", "webp"];

/// Env var that makes [`files_routes`] install meson's `AlwaysInfectedScanner`,
/// so end-to-end suites can drive the quarantined path.
pub const E2E_INFECTED_ENV: &str = "MESON_E2E_INFECTED";

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
/// Also does the process-wide meson setup the upload path needs:
///
/// - installs `layout.available` and `layout.quarantine` as meson's stores
///   (replacing any earlier install);
/// - registers [`ProfilePhotoScanAdapter`] for the `profile_photo` table;
/// - installs `AlwaysInfectedScanner` when [`E2E_INFECTED_ENV`] is `1`,
///   otherwise `AlwaysCleanScanner` unless the host already installed a
///   scanner (for example meson's `ClamAvScanner`).
pub fn files_routes<S>(layout: BlobStoreLayout, config: FilesConfig) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    install_file_stores(layout);
    register_file_scan_adapter(PROFILE_PHOTO_TABLE, Arc::new(ProfilePhotoScanAdapter));
    if std::env::var(E2E_INFECTED_ENV).ok().as_deref() == Some("1") {
        install_virus_scanner(Arc::new(AlwaysInfectedScanner));
    } else if installed_virus_scanner().is_none() {
        install_virus_scanner(Arc::new(AlwaysCleanScanner));
    }
    Router::<S>::new()
        .route("/api/files/upload", post(upload_handler))
        .route("/api/files/{id}", get(serve_handler))
        .layer(Extension(config))
}

fn install_file_stores(layout: BlobStoreLayout) {
    for (store, result) in [
        ("available", install_blob_store(layout.available)),
        ("quarantine", install_quarantine_store(layout.quarantine)),
    ] {
        if let Err(e) = result {
            tracing::warn!(
                target: "lepton.files",
                store,
                error = %e,
                "meson blob store install failed"
            );
        }
    }
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
    let profile = UserProfile::query(session_v, valence::use_!(r"When you **upload a profile photo**, we **load your account profile** first so we know which profile the new photo belongs to. If you have never opened your profile before, we create one next from your account email."))
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
    UserProfile::create(new_profile, session_v, valence::use_!(r"When you **upload a profile photo** and have never opened your **account profile** before, we **create a profile** from your account email so the photo has somewhere to attach. Only you use this profile record afterward."))
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create profile".to_string(),
            )
        })
}

fn map_upload_err(err: &FileUploadError) -> HttpErr {
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

struct StoredUpload {
    original_name: String,
    extension: String,
    mime: &'static str,
    size_bytes: i64,
    storage_key: String,
    file_status: FileFileStatus,
}

/// Put bytes on the store meson picks (quarantine while virus scan is on).
async fn store_upload_bytes(
    original_name: String,
    extension: String,
    mime: &'static str,
    file_bytes: &[u8],
) -> Result<StoredUpload, HttpErr> {
    let put = put_new_object(&extension, file_bytes)
        .await
        .map_err(|e| map_upload_err(&e))?;
    let file_status = if virus_scan_enabled() {
        FileFileStatus::PendingVirusScan
    } else {
        FileFileStatus::Available
    };
    Ok(StoredUpload {
        original_name,
        extension,
        mime,
        size_bytes: put.size_bytes,
        storage_key: put.storage_path,
        file_status,
    })
}

/// Tell the uploader the photo is pending and queue meson's scan task.
///
/// Both steps are best effort because the upload already succeeded. Hosts
/// that run meson's `meson_virus_scan_sweeper` Chronon job re-queue rows left
/// pending.
async fn start_virus_scan(user: &User, photo_id: &RecordId) {
    let bare = bare_id(photo_id);
    // Photon `auth = "user"` keys are the full `user:<id>` form, matching meson's scan task.
    let user_key = user.id.to_string();
    publish_file_updated(&user_key, &bare, FileFileStatus::PendingVirusScan.as_str()).await;
    if let Err(e) = enqueue_virus_scan(PROFILE_PHOTO_TABLE, &bare).await {
        tracing::warn!(
            target: "lepton.files.upload",
            outcome = "enqueue_virus_scan_failed",
            error = %e,
            "profile photo stored in quarantine but virus scan enqueue failed"
        );
    }
}

async fn create_photo_and_set_active(
    valence_router: Arc<DatabaseRouter>,
    backend_key: &str,
    user: &User,
    profile: &UserProfile,
    stored: &StoredUpload,
) -> Result<RecordId, HttpErr> {
    let profile_ref = profile.id().cloned().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Missing profile id".to_string(),
        )
    })?;

    let system_v = system_valence(Arc::clone(&valence_router), backend_key, "file_upload")?;
    let photo = ProfilePhoto::new(
        profile_ref,
        None,
        None,
        stored.original_name.clone(),
        stored.extension.clone(),
        stored.mime.to_string(),
        stored.size_bytes,
        stored.storage_key.clone(),
        stored.file_status.clone(),
        user.id.clone(),
        Utc::now(),
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to build photo".to_string(),
        )
    })?;

    let created = ProfilePhoto::create(photo, &system_v, valence::use_!(r"When you **upload a profile photo**, we **create a photo record** pointing at the file we just stored, so your profile can reference it. Only your account uses this record to show or replace your photo."))
        .await
        .map_err(|_| {
            tracing::warn!(
                target: "lepton.files.upload",
                outcome = "create_failed_after_put",
                "photo record create failed after blob put; blob may remain"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create photo".to_string(),
            )
        })?;

    let photo_id = created.id().cloned().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Missing photo id".to_string(),
        )
    })?;

    if matches!(stored.file_status, FileFileStatus::PendingVirusScan) {
        start_virus_scan(user, &photo_id).await;
    }

    let session_v = user_valence(valence_router, backend_key, user)?;
    let profile = UserProfile::query(&session_v, valence::use_!(r"Right after a **profile photo** upload finishes, we **reload your account profile** so we can point it at the photo you just uploaded."))
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
        .get_mutable(&session_v, valence::use_!(r"We then **set your profile's active photo** to the one you just uploaded, so your profile page and anywhere else your photo appears show the new picture. Only you use this change on your profile."))
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

    Ok(photo_id)
}

/// POST `/api/files/upload` — multipart `file` + optional `profile_id`.
///
/// The JSON response carries `file_status`: `pending_virus_scan` while the
/// bytes wait in quarantine, or `available` when virus scan is off.
pub async fn upload_handler(
    auth: AuthSession<Backend>,
    Extension(valence_router): Extension<Arc<DatabaseRouter>>,
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

        let stored =
            store_upload_bytes(original_name.clone(), extension.clone(), mime, &file_bytes).await?;
        let photo_id =
            create_photo_and_set_active(valence_router, backend_key, &user, &profile, &stored)
                .await?;

        let size_bytes = stored.size_bytes;
        let file_status = stored.file_status.as_str();
        tracing::info!(
            outcome = "ok",
            size_bytes,
            extension = %extension,
            file_status,
            "profile photo uploaded"
        );

        Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "id": photo_id.to_string(),
                "file_name": original_name,
                "size_bytes": size_bytes,
                "file_status": file_status,
            })),
        ))
    }
    .instrument(span)
    .await
}

/// GET `/api/files/{id}` — cookie-authenticated same-origin serve.
///
/// Answers 403 for rows that are not `available` (pending scan or
/// quarantined). Bytes are read only from the available store.
pub async fn serve_handler(
    auth: AuthSession<Backend>,
    Extension(valence_router): Extension<Arc<DatabaseRouter>>,
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
        let Ok(Some(photo)) = ProfilePhoto::get(&id, &session_v, valence::use_!(r"When your browser requests a stored **profile photo** to display it, we **look up that photo's record** under your own account privacy so you can only ever be served a photo you're allowed to see. A missing or not-allowed photo comes back the same way, as not found.")).await else {
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
