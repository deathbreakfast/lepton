//! [`FileScanAdapter`] for lepton `profile_photo` (Mutable status commits).

use async_trait::async_trait;
use lepton_identity::generated::{FileFileStatus, ProfilePhoto};
use meson::{
    FileFileStatus as MesonFileStatus, FileScanAdapter, FileScanAdapterError, FileScanSnapshot,
};
use valence::{Model, Valence};

/// Maps lepton → meson `file_status` (same wire strings).
fn to_meson_status(status: &FileFileStatus) -> Result<MesonFileStatus, FileScanAdapterError> {
    MesonFileStatus::from_str(status.as_str()).ok_or(FileScanAdapterError::NotFound)
}

/// Boson scan worker adapter for `profile_photo` rows.
#[derive(Default)]
pub struct ProfilePhotoScanAdapter;

#[async_trait]
impl FileScanAdapter for ProfilePhotoScanAdapter {
    async fn load(
        &self,
        valence: &Valence,
        file_id: &str,
    ) -> Result<FileScanSnapshot, FileScanAdapterError> {
        let row = ProfilePhoto::get(file_id, valence)
            .await?
            .ok_or(FileScanAdapterError::NotFound)?;
        Ok(FileScanSnapshot {
            storage_path: row.storage_path().clone(),
            file_status: to_meson_status(row.file_status())?,
            uploaded_by: row.uploaded_by().clone(),
        })
    }

    async fn commit_available(
        &self,
        valence: &Valence,
        file_id: &str,
        storage_path: String,
    ) -> Result<(), FileScanAdapterError> {
        let row = ProfilePhoto::get(file_id, valence)
            .await?
            .ok_or(FileScanAdapterError::NotFound)?;
        row.get_mutable(valence)
            .set_storage_path(storage_path)
            .map_err(FileScanAdapterError::Valence)?
            .set_file_status(FileFileStatus::Available)
            .map_err(FileScanAdapterError::Valence)?
            .commit()
            .await
            .map_err(FileScanAdapterError::Valence)?;
        Ok(())
    }

    async fn commit_quarantined(
        &self,
        valence: &Valence,
        file_id: &str,
    ) -> Result<(), FileScanAdapterError> {
        let row = ProfilePhoto::get(file_id, valence)
            .await?
            .ok_or(FileScanAdapterError::NotFound)?;
        row.get_mutable(valence)
            .set_file_status(FileFileStatus::Quarantined)
            .map_err(FileScanAdapterError::Valence)?
            .commit()
            .await
            .map_err(FileScanAdapterError::Valence)?;
        Ok(())
    }
}
