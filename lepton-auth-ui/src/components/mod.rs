//! Leptos UI components for the auth flows (dialogs and embeddable form content).
//!
//! Submodules are private; only the re-exports below are part of the public API.
//! See the [crate root](crate) for mount, routes, and step-up examples.

mod auth_dialog;
mod auth_modal_shell;
mod brand_icons;
mod confirm_account_page;
mod confirm_account_prompt;
mod logout_content;
mod oauth_callback_content;
mod oauth_provider_buttons;
mod password_reset_confirm_content;
mod password_reset_dialog;
mod password_reset_request_content;
mod signin_content;
mod signup_content;
mod step_up_content;
mod step_up_controller;
mod step_up_dialog;

pub use auth_dialog::{AuthDialog, AuthDialogCallbacks, AuthDialogKind};
pub use auth_modal_shell::AuthModalShell;
pub use brand_icons::{GitHubMark, GoogleMark, MicrosoftMark};
pub use confirm_account_page::ConfirmAccountPage;
pub use confirm_account_prompt::{
    confirm_account_status_resource, ConfirmAccountPrompt, ConfirmAccountPromptVariant,
};
pub use logout_content::LogoutContent;
pub use oauth_callback_content::OAuthCallbackContent;
pub use oauth_provider_buttons::OAuthProviderButtons;
pub use password_reset_confirm_content::PasswordResetConfirmContent;
pub use password_reset_dialog::{PasswordResetDialog, PasswordResetDialogKind};
pub use password_reset_request_content::PasswordResetRequestContent;
pub use signin_content::SigninContent;
pub use signup_content::SignupContent;
pub use step_up_content::StepUpContent;
pub use step_up_controller::{
    provide_step_up_controller, use_step_up_controller, StepUpController, StepUpFactors,
    StepUpPolicy, StepUpRequest,
};
pub use step_up_dialog::StepUpDialog;
