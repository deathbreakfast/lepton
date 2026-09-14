//! Byte backends for profile / File trait payloads.
//!
//! Re-exports Meson's dual-store factory, installs, and [`FileByteBackend`].
//! Valence stores metadata and an opaque `storage_path` key; the backend puts
//! and gets the bytes (quarantine first when virus scan is on).

pub use meson::{
    blob_store_from_env, blob_stores_from_env, BlobStoreConfigError, BlobStoreLayout,
    FileByteBackend, FileStoreError, LocalDiskBlobStore,
};
