//! Byte backend re-export.
//!
//! Storage for File trait payloads (profile photos) lives in the platform
//! `meson` crate so a host can install one shared backend across every
//! `meson` `File`-trait consumer it mounts. This module re-exports meson's
//! backend types so existing
//! `lepton_host_adapter::files::{FileByteBackend, FileStoreError, LocalDiskBlobStore}`
//! imports keep working — [`crate::files`] no longer vendors its own store.

pub use meson::{FileByteBackend, FileStoreError, LocalDiskBlobStore};
