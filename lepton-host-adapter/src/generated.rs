#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Token / lifecycle Valence models generated here (`PasswordResetToken`,
//! `EmailVerificationToken`, `PhoneVerificationToken`, `TotpFactor`,
//! `TotpRecoveryCode`); core identity models live in `lepton-identity` and are
//! re-exported below.
#![allow(unused_imports)]
#![allow(missing_docs)]

#[cfg(feature = "ssr")]
mod ssr_only {
    #![allow(unused_imports, dead_code)]
    use valence::privacy_policies::common::{AUTHENTICATED, SYSTEM_ONLY};

    include!(concat!(env!("OUT_DIR"), "/generated_models.rs"));
}

#[cfg(feature = "ssr")]
pub use lepton_identity::generated::{
    Account, AccountEmail, AccountEmailReference, AccountMembership, AccountMembershipReference,
    AccountMembershipRole, AccountPhone, AccountPhoneReference, AccountPlan, AccountReference,
    AccountStatus, AuthDevice, AuthDeviceCeremony, AuthDeviceCeremonyPhase,
    AuthDeviceCeremonyReference, AuthDeviceKind, AuthDeviceReference, FileFileStatus,
    LinkedIdentity, LinkedIdentityProvider, LinkedIdentityReference, OauthPendingState,
    OauthPendingStateIntent, OauthPendingStateProvider, OauthPendingStateReference, ProfilePhoto,
    ProfilePhotoReference, ServiceUserAccount, ServiceUserAccountOwnerKind,
    ServiceUserAccountQuery, ServiceUserAccountReference, ServiceUserAccountStatus, User,
    UserAppearance, UserAppearanceReference, UserProfile, UserProfileReference, UserQuery,
    UserReference, UserStatus, UserUserType,
};

#[cfg(feature = "ssr")]
pub use ssr_only::{
    DeliveryAttempt, DeliveryAttemptChannel, DeliveryAttemptOutcome, DeliveryAttemptReference,
    EmailVerificationToken, EmailVerificationTokenReference, OneTimeTokenLifecycleFields,
    PasswordResetToken, PasswordResetTokenReference, PhoneVerificationToken,
    PhoneVerificationTokenReference, TotpFactor, TotpFactorReference, TotpRecoveryCode,
    TotpRecoveryCodeReference,
};
