//! Signup library API (create pending user; optional session login).
//!
//! Requires trimmed `SignupRequest::legal_name` and `display_name` (`ssr` module).
//! At create, those values are stored on `UserProfile.legal_name` and
//! `UserProfile.display_name` respectively.
//!
//! # Examples
//!
//! ```rust,ignore
//! use lepton_auth::signup_api::ssr::{create_pending_user, SignupRequest};
//!
//! let pending = create_pending_user(
//!     &valence,
//!     SignupRequest {
//!         legal_name: "Alex Rivera".into(),
//!         display_name: "Alex".into(),
//!         email: "user@example.test".into(),
//!         password: "CorrectHorseBattery1!".into(),
//!         confirm: "CorrectHorseBattery1!".into(),
//!     },
//! )
//! .await?;
//! ```

#[cfg(feature = "ssr")]
pub mod ssr {
    //! Signup execution logic shared by the Signup server function and e2e drivers.
    use axum_login::AuthSession;
    use chrono::Utc;
    use lepton_host_adapter::auth::{Backend, User as AuthUser};
    use lepton_host_adapter::generated::{
        Account, AccountEmail, AccountMembership, AccountMembershipRole, AccountPlan,
        AccountStatus, User, UserProfile, UserStatus, UserUserType,
    };
    use lepton_identity::ownership::{bare_id_from_record, ensure_signup_identity_ownership};
    use leptos::prelude::ServerFnError;
    use valence::{Model, RecordId, StringPredicate, Valence};

    use crate::security::{
        display_name_policy_error, legal_name_policy_error, log_credential_audit,
        password_policy_error_message,
    };

    /// Signup form payload submitted by the client.
    pub struct SignupRequest {
        /// Legal name (private profile field).
        pub legal_name: String,
        /// Display name (public profile field).
        pub display_name: String,
        /// Email address for the new account.
        pub email: String,
        /// Chosen password (must pass policy checks).
        pub password: String,
        /// Password confirmation (must match `password`).
        pub confirm: String,
    }

    /// Successful signup outcome returned to the client.
    pub struct SignupResult {
        /// Normalized email address of the created user.
        pub email: String,
    }

    /// Pending user created without an auth session login.
    ///
    /// When the `email` feature is on, [`Self::email_token_id`] is the verification
    /// code (also the Valence token record id). Callers send the envelope.
    pub struct PendingUser {
        /// Trimmed legal name used at create (and for email greeting).
        pub legal_name: String,
        /// Trimmed display name used at create.
        pub display_name: String,
        /// Normalized email address.
        pub email: String,
        /// Created user id.
        pub user_id: RecordId,
        /// Primary email contact id.
        pub email_id: RecordId,
        /// Email verification token id when `email` is enabled.
        #[cfg(feature = "email")]
        pub email_token_id: String,
        /// Reloaded user row (for session login).
        pub user: User,
    }

    /// Create account / user / primary email / profile, issue email verification token
    /// when `email` is enabled, and return without logging in.
    ///
    /// # Errors
    ///
    /// Validation, conflict, or persistence failures as [`ServerFnError`].
    pub async fn create_pending_user(
        valence: &Valence,
        req: SignupRequest,
    ) -> Result<PendingUser, ServerFnError> {
        let (email_trimmed, legal_name, display_name) = validate_request(&req)?;
        ensure_email_not_registered(valence, &email_trimmed).await?;
        let (created_user, primary_email) = create_user_account_and_profile(
            valence,
            &email_trimmed,
            &legal_name,
            &display_name,
            &req.password,
        )
        .await?;
        let user_id = created_user
            .id()
            .cloned()
            .ok_or_else(|| ServerFnError::new("User missing id after create"))?;
        let email_id = primary_email
            .id()
            .cloned()
            .ok_or_else(|| ServerFnError::new("User email missing id after create"))?;

        #[cfg(feature = "email")]
        let email_token_id = crate::token_helpers::issue_email_verification_token(
            valence,
            user_id.clone(),
            email_id.clone(),
        )
        .await?;

        #[cfg(feature = "spectra")]
        crate::spectra_emit::signup(true, "none");
        Ok(PendingUser {
            legal_name,
            display_name,
            email: email_trimmed,
            user_id,
            email_id,
            #[cfg(feature = "email")]
            email_token_id,
            user: created_user,
        })
    }

    /// Create the user account, issue a verification token, log in the session, and return.
    pub async fn execute(
        valence: &Valence,
        auth_session: &mut AuthSession<Backend>,
        req: SignupRequest,
    ) -> Result<SignupResult, ServerFnError> {
        let pending = create_pending_user(valence, req).await?;

        #[cfg(feature = "email")]
        {
            use crate::email_delivery::ssr::send_verification_token_email_quiet;
            use lepton_smtp::VerificationEmailFlow;

            send_verification_token_email_quiet(
                &pending.email,
                Some(pending.legal_name.as_str()),
                &pending.email_token_id,
                VerificationEmailFlow::Signup,
            )
            .await;
        }

        let auth_user = AuthUser::from_generated(
            &pending.user,
            pending.email.clone(),
            false,
            Some(pending.display_name.clone()),
            None,
            vec!["owner".to_string()],
        );
        auth_session
            .login(&auth_user)
            .await
            .map_err(|e| ServerFnError::new(format!("Login failed: {e}")))?;

        log_credential_audit(
            "signup",
            Some(pending.email.as_str()),
            "success",
            Some("user_created"),
        );

        Ok(SignupResult {
            email: pending.email,
        })
    }

    fn validate_request(req: &SignupRequest) -> Result<(String, String, String), ServerFnError> {
        if req.legal_name.trim().is_empty()
            || req.display_name.trim().is_empty()
            || req.email.trim().is_empty()
            || req.password.is_empty()
            || req.confirm.is_empty()
        {
            log_credential_audit(
                "signup",
                Some(req.email.trim()),
                "failure",
                Some("missing_fields"),
            );
            #[cfg(feature = "spectra")]
            crate::spectra_emit::signup(false, "validation");
            return Err(ServerFnError::Args("Missing fields".into()));
        }

        if let Some(policy_error) = legal_name_policy_error(&req.legal_name) {
            log_credential_audit(
                "signup",
                Some(req.email.trim()),
                "failure",
                Some("legal_name_policy"),
            );
            #[cfg(feature = "spectra")]
            crate::spectra_emit::signup(false, "validation");
            return Err(ServerFnError::Args(policy_error.into()));
        }

        if let Some(policy_error) = display_name_policy_error(&req.display_name) {
            log_credential_audit(
                "signup",
                Some(req.email.trim()),
                "failure",
                Some("display_name_policy"),
            );
            #[cfg(feature = "spectra")]
            crate::spectra_emit::signup(false, "validation");
            return Err(ServerFnError::Args(policy_error.into()));
        }

        if req.password != req.confirm {
            log_credential_audit(
                "signup",
                Some(req.email.trim()),
                "failure",
                Some("password_mismatch"),
            );
            #[cfg(feature = "spectra")]
            crate::spectra_emit::signup(false, "validation");
            return Err(ServerFnError::Args("Passwords do not match".into()));
        }

        if let Some(policy_error) = password_policy_error_message(&req.password) {
            log_credential_audit(
                "signup",
                Some(req.email.trim()),
                "failure",
                Some("password_policy"),
            );
            #[cfg(feature = "spectra")]
            crate::spectra_emit::signup(false, "validation");
            return Err(ServerFnError::Args(policy_error));
        }

        Ok((
            req.email.trim().to_string(),
            req.legal_name.trim().to_string(),
            req.display_name.trim().to_string(),
        ))
    }

    async fn ensure_email_not_registered(
        valence: &Valence,
        email: &str,
    ) -> Result<(), ServerFnError> {
        let existing = AccountEmail::query_used(valence, valence::use_!(r"In **account signup**, we **list Account Email** so the product can show or process the matching set for this workflow. Callers allowed for **account signup** use the list; it is not a public dump of every field to anonymous visitors."))
            .where_address(StringPredicate::Equals(email.to_string()))
            .first()
            .await
            .map_err(|e| ServerFnError::new(format!("Query error: {e}")))?;

        if existing.is_some() {
            log_credential_audit("signup", Some(email), "failure", Some("email_exists"));
            // Uniform client-facing error — do not reveal whether the email is registered.
            #[cfg(feature = "spectra")]
            crate::spectra_emit::signup(false, "email_exists");
            return Err(ServerFnError::Args("Unable to complete signup".into()));
        }

        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn create_user_account_and_profile(
        valence: &Valence,
        email: &str,
        legal_name: &str,
        display_name: &str,
        password: &str,
    ) -> Result<(User, AccountEmail), ServerFnError> {
        let password_hash = lepton_host_adapter::auth::hash_password(password)
            .map_err(|e| ServerFnError::new(format!("Password hashing failed: {e}")))?;

        let now = Utc::now();
        let user = User::new(
            Some(UserUserType::Person),
            Some(password_hash),
            Some(UserStatus::PendingVerification),
            None,
            None,
            None,
            None,
            None,
            now,
            now,
        )
        .map_err(|e| ServerFnError::new(format!("Failed to create user: {e}")))?;

        let user_created = User::create_used(user, valence, valence::use_!(r"When **account signup** needs to persist work, we **save User** so the next step in that feature can continue with the latest values. People and services allowed for **account signup** use this data for that workflow—not as a general export of unrelated personal fields."))
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to create user: {e}")))?;
        let user_thing = user_created
            .id()
            .cloned()
            .ok_or_else(|| ServerFnError::new("Failed to create user"))?;

        let account = Account::new(
            email.to_string(),
            user_thing.clone(),
            Some(AccountPlan::Free),
            Some(AccountStatus::Active),
            None,
            None,
            now,
            now,
        )
        .map_err(|e| ServerFnError::new(format!("Failed to create account: {e}")))?;

        let account_created = Account::create_used(account, valence, valence::use_!(r"When **account signup** needs to persist work, we **save Account** so the next step in that feature can continue with the latest values. People and services allowed for **account signup** use this data for that workflow—not as a general export of unrelated personal fields."))
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to create account: {e}")))?;

        let account_thing = account_created
            .id()
            .cloned()
            .ok_or_else(|| ServerFnError::new("Failed to create account"))?;

        let email_row = AccountEmail::new(account_thing.clone(), email.to_string(), None, now, now)
            .map_err(|e| ServerFnError::new(format!("Failed to create account email: {e}")))?;
        let email_created = AccountEmail::create_used(email_row, valence, valence::use_!(r"When **account signup** needs to persist work, we **save Account Email** so the next step in that feature can continue with the latest values. People and services allowed for **account signup** use this data for that workflow—not as a general export of unrelated personal fields."))
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to create account email: {e}")))?;
        let email_thing = email_created
            .id()
            .cloned()
            .ok_or_else(|| ServerFnError::new("Account email missing id after create"))?;

        account_created
            .get_mutable_used(valence, valence::use_!(r"In **lepton auth**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **lepton auth** use the updated data; this is not a public export of unrelated fields."))
            .set_primary_email(email_thing.clone())
            .map_err(|e| ServerFnError::new(format!("Failed to set account primary email: {e}")))?
            .set_updated_at(now)
            .map_err(|e| ServerFnError::new(format!("Failed to update account: {e}")))?
            .commit()
            .await
            .map_err(|e| {
                ServerFnError::new(format!("Failed to persist account primary email: {e}"))
            })?;

        user_created
            .get_mutable_used(valence, valence::use_!(r"In **lepton auth**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **lepton auth** use the updated data; this is not a public export of unrelated fields."))
            .set_primary_email(email_thing.clone())
            .map_err(|e| ServerFnError::new(format!("Failed to set primary email: {e}")))?
            .set_updated_at(now)
            .map_err(|e| ServerFnError::new(format!("Failed to update user: {e}")))?
            .commit()
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to persist primary email: {e}")))?;

        let user_created = User::get_used(&bare_id_from_record(&user_thing), valence, valence::use_!(r"In **account signup**, we **load User** so the application can decide what to do next in this workflow. The result is used by **account signup** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to reload user: {e}")))?
            .ok_or_else(|| ServerFnError::new("User missing after create"))?;

        let account_bare = bare_id_from_record(&account_thing);
        let user_bare = bare_id_from_record(&user_thing);
        let email_bare = bare_id_from_record(&email_thing);

        let profile = UserProfile::new(
            user_thing.clone(),
            legal_name.to_string(),
            display_name.to_string(),
            Utc::now(),
            Utc::now(),
            None,
        )
        .map_err(|e| ServerFnError::new(format!("Failed to create user profile: {e}")))?;

        let created_profile = UserProfile::create_used(profile, valence, valence::use_!(r"When **account signup** needs to persist work, we **save User Profile** so the next step in that feature can continue with the latest values. People and services allowed for **account signup** use this data for that workflow—not as a general export of unrelated personal fields."))
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to create user profile: {e}")))?;
        let profile_bare = bare_id_from_record(
            created_profile
                .id()
                .ok_or_else(|| ServerFnError::new("User profile missing id after create"))?,
        );

        let membership = AccountMembership::new(
            account_thing.clone(),
            user_thing,
            AccountMembershipRole::Owner,
            Utc::now(),
            Utc::now(),
        )
        .map_err(|e| ServerFnError::new(format!("Failed to create account membership: {e}")))?;

        let created_membership = AccountMembership::create_used(membership, valence, valence::use_!(r"When **account signup** needs to persist work, we **save Account Membership** so the next step in that feature can continue with the latest values. People and services allowed for **account signup** use this data for that workflow—not as a general export of unrelated personal fields."))
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to create account membership: {e}")))?;
        let membership_bare = bare_id_from_record(
            created_membership
                .id()
                .ok_or_else(|| ServerFnError::new("Account membership missing id after create"))?,
        );

        let extra = [
            ("user_profile", profile_bare.as_str()),
            ("account_membership", membership_bare.as_str()),
            ("account_email", email_bare.as_str()),
        ];
        ensure_signup_identity_ownership(valence, &user_bare, &account_bare, &extra)
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to assign signup ownership: {e}")))?;

        Ok((user_created, email_created))
    }
}
