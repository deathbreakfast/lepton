//! Byte backends for profile / File trait payloads.
//!
//! Re-exports Meson's [`FileByteBackend`] and [`LocalDiskBlobStore`]. Valence
//! stores metadata and an opaque `storage_path` key; the backend puts and gets
//! the bytes.

pub use meson::{FileByteBackend, FileStoreError, LocalDiskBlobStore};
