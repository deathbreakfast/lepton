//! Byte backend re-export.
//!
//! Storage for File trait payloads (profile photos) lives in the platform
//! `meson` crate so a host can install one shared pair of stores across every
//! `meson` `File`-trait consumer it mounts. This module re-exports meson's
//! backend types and its env-driven store factory, so hosts can build the
//! [`BlobStoreLayout`] for [`crate::files::files_routes`] without depending on
//! `meson` directly.

pub use meson::{
    blob_store_from_env, blob_stores_from_env, BlobStoreConfigError, BlobStoreLayout,
    FileByteBackend, FileStoreError, LocalDiskBlobStore,
};
