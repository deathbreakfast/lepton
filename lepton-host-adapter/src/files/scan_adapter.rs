//! [`FileScanAdapter`] for lepton `profile_photo` rows.
//!
//! Meson's `meson_virus_scan` Boson task looks this adapter up by table name to
//! read a pending photo and record the scan verdict. The task runs under the
//! System actor captured when the scan was enqueued; this adapter uses the
//! Valence handle it is given and never switches actors itself.

use async_trait::async_trait;
use lepton_identity::generated::{FileFileStatus, ProfilePhoto};
use meson::{
    FileFileStatus as MesonFileStatus, FileScanAdapter, FileScanAdapterError, FileScanSnapshot,
};
use valence::{Model, Valence};

/// Table name the adapter is registered under (matches the `ProfilePhoto` schema).
pub const PROFILE_PHOTO_TABLE: &str = "profile_photo";

/// Maps lepton → meson `file_status` (same wire strings).
fn to_meson_status(status: &FileFileStatus) -> Result<MesonFileStatus, FileScanAdapterError> {
    MesonFileStatus::from_str(status.as_str()).ok_or(FileScanAdapterError::NotFound)
}

/// Virus-scan worker adapter for `profile_photo` rows.
#[derive(Debug, Default)]
pub struct ProfilePhotoScanAdapter;

#[async_trait]
impl FileScanAdapter for ProfilePhotoScanAdapter {
    async fn load(
        &self,
        valence: &Valence,
        file_id: &str,
    ) -> Result<FileScanSnapshot, FileScanAdapterError> {
        let row = ProfilePhoto::get(file_id, valence, valence::use_!(r"After you **upload a profile photo**, the **virus scan** loads that photo's record to find where the uploaded file is held and whether it still needs scanning. Only the scanner reads this; nothing is shown to you at this step."))
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
        let row = ProfilePhoto::get(file_id, valence, valence::use_!(r"When the **virus scan** finds your uploaded **profile photo** clean, we reload the photo's record so we can record that result on it."))
            .await?
            .ok_or(FileScanAdapterError::NotFound)?;
        row.get_mutable(valence, valence::use_!(r"When the **virus scan** finds your uploaded **profile photo** clean, the file moves out of quarantine and we **mark the photo available** with its new storage location, so your profile can show it."))
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
        let row = ProfilePhoto::get(file_id, valence, valence::use_!(r"When the **virus scan** flags your uploaded **profile photo**, we reload the photo's record so we can record that result on it."))
            .await?
            .ok_or(FileScanAdapterError::NotFound)?;
        row.get_mutable(valence, valence::use_!(r"When the **virus scan** flags your uploaded **profile photo** as infected, we **mark the photo quarantined**. The file stays in quarantine storage and is never served to you or anyone else."))
            .set_file_status(FileFileStatus::Quarantined)
            .map_err(FileScanAdapterError::Valence)?
            .commit()
            .await
            .map_err(FileScanAdapterError::Valence)?;
        Ok(())
    }
}
