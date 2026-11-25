//! Profile defaults, and the backfill that removes email addresses from public display names.
//!
//! `UserProfile.display_name` is readable by everyone, so a profile Lepton creates on the
//! user's behalf starts with [`DEFAULT_DISPLAY_NAME`] rather than anything taken from the
//! account. Profiles created before that rule may still show an email address;
//! [`backfill_email_display_names`] resets them.

use chrono::Utc;
use valence::{StringPredicate, Valence};

use crate::generated::UserProfile;

/// Display name for a profile Lepton creates before the user picks one.
pub const DEFAULT_DISPLAY_NAME: &str = "Member";

/// Rows read per page by [`backfill_email_display_names`].
const BACKFILL_PAGE: u32 = 100;

/// Reset every `UserProfile.display_name` that contains `@` to [`DEFAULT_DISPLAY_NAME`].
///
/// Returns the number of profiles changed. Run it once as a maintenance job on a handle that
/// starts as `Actor::System` (only System may update another user's profile). A user
/// handle gets `Error::Privacy` on the first row it doesn't own.
///
/// # Errors
///
/// Returns the Valence error from the first query or update that fails; rows already
/// rewritten stay rewritten, so the job can be run again.
pub async fn backfill_email_display_names(valence: &Valence) -> valence::Result<usize> {
    let mut changed = 0;
    loop {
        // Rewritten rows stop matching, so each pass reads the first page again.
        let page = UserProfile::query(valence, valence::use_!(r"During the one-off **display name cleanup**, we **find profiles whose public display name contains an email address** so we can replace it. Nothing is shown to anyone; the job only reads the rows it rewrites."))
            .where_display_name(StringPredicate::Contains("@".to_string()))
            .limit(BACKFILL_PAGE)
            .await?;
        if page.is_empty() {
            return Ok(changed);
        }
        for profile in page {
            profile
                .get_mutable(valence, valence::use_!(r"During the one-off **display name cleanup**, we **replace a public display name that contains an email address** with a neutral name, so the address stops showing on the profile. The person can set their own display name afterward."))
                .set_display_name(DEFAULT_DISPLAY_NAME.to_string())?
                .set_updated_at(Utc::now())?
                .commit()
                .await?;
            changed += 1;
        }
    }
}
