//! [`StepUpDialog`] — host-mounted modal bound to [`super::StepUpController`].

use leptos::prelude::*;
use orbital_core_components::DialogDismissConfig;

use super::auth_modal_shell::AuthModalShell;
use super::step_up_content::StepUpContent;
use super::step_up_controller::{use_step_up_controller, StepUpController};

/// Frost step-up modal. Mount once near the shell root after
/// [`super::provide_step_up_controller`].
///
/// Backdrop and Escape do not dismiss; the user must Cancel or complete verification.
/// Pair with [`lepton_auth::factor`] on the server after [`StepUpController::request`].
///
/// # Panics
///
/// Panics when no [`StepUpController`] is in context and `controller` is not passed.
#[component]
pub fn StepUpDialog(
    /// Override context controller when the host already holds a handle.
    #[prop(optional)]
    controller: Option<StepUpController>,
) -> impl IntoView {
    #[allow(clippy::expect_used)] // documented panic when host forgot provide_step_up_controller
    let controller = controller
        .or_else(use_step_up_controller)
        .expect("StepUpDialog requires provide_step_up_controller or a controller prop");

    let open = controller.open();
    let title = Signal::derive(move || controller.request_signal().get().title);

    view! {
        <AuthModalShell
            open=open.into()
            title=title
            dismiss=DialogDismissConfig {
                mask_closeable: Signal::from(false),
                close_on_esc: false,
            }
        >
            <StepUpContent controller=controller />
        </AuthModalShell>
    }
}
