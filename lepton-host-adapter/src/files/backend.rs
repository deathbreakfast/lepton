//! Byte backends for profile / File trait payloads.
//!
//! Re-exports Meson's [`FileByteBackend`], [`LocalDiskBlobStore`], and
//! [`blob_store_from_env`]. Valence stores metadata and an opaque `storage_path`
//! key; the backend puts and gets the bytes.

pub use meson::{
    blob_store_from_env, BlobStoreConfigError, FileByteBackend, FileStoreError, LocalDiskBlobStore,
};
