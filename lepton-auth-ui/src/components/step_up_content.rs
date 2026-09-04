//! Step-up form body: password and/or TOTP fields inside [`super::StepUpDialog`].

use leptos::prelude::*;
use orbital_core_components::{
    Body1, Button, ButtonAppearance, ButtonType, Field, Flex, FlexGap, Input, InputAppearance,
    InputBind, InputType, Link, MessageBar, MessageBarIntent,
};

use super::step_up_controller::{StepUpController, StepUpFactors, StepUpPolicy};

/// Collects step-up factors and hands them to [`StepUpController::submit_factors`].
#[component]
#[allow(clippy::too_many_lines)] // password + TOTP fields and enrollment branch in one form
pub fn StepUpContent(controller: StepUpController) -> impl IntoView {
    let totp_code = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let client_error = RwSignal::new(Option::<String>::None);

    let enrollment = Resource::new(
        move || controller.open().get(),
        |is_open| async move {
            if !is_open {
                return None;
            }
            Some(
                lepton_auth::actions::totp::get_totp_settings_status()
                    .await
                    .is_ok_and(|status| status.totp_enabled),
            )
        },
    );

    // Clear fields when a new challenge opens.
    Effect::new(move |_| {
        if controller.open().get() {
            totp_code.set(String::new());
            password.set(String::new());
            client_error.set(None);
        }
    });

    let on_cancel = Callback::new(move |_| {
        controller.cancel();
    });

    let on_continue = Callback::new(move |_| {
        client_error.set(None);
        let req = controller.request_signal().get_untracked();
        let code = totp_code.get_untracked().trim().to_string();
        if code.is_empty() {
            client_error.set(Some("Enter the code from your authenticator app.".into()));
            return;
        }
        let password_opt = match req.policy {
            StepUpPolicy::Totp => None,
            StepUpPolicy::PasswordAndTotp => {
                let pw = password.get_untracked();
                if pw.is_empty() {
                    client_error.set(Some("Enter your current password.".into()));
                    return;
                }
                Some(pw)
            }
        };
        controller.submit_factors(StepUpFactors {
            totp_code: code,
            password: password_opt,
        });
    });

    view! {
        <div data-testid="step-up-dialog">
            <Flex vertical=true gap=FlexGap::Medium>
                {move || {
                    controller
                        .request_signal()
                        .get()
                        .description
                        .map_or_else(
                            || ().into_any(),
                            |d| {
                                view! {
                                    <div data-testid="step-up-description">
                                        <Body1>{d}</Body1>
                                    </div>
                                }
                                .into_any()
                            },
                        )
                }}

                <Show when=move || {
                    client_error.get().is_some() || controller.error().get().is_some()
                }>
                    <div data-testid="step-up-error">
                        <MessageBar intent=MessageBarIntent::Error>
                            {move || {
                                client_error
                                    .get()
                                    .or_else(|| controller.error().get())
                                    .unwrap_or_default()
                            }}
                        </MessageBar>
                    </div>
                </Show>

                {move || match enrollment.get() {
                    None | Some(None) => view! {
                        <Body1>"Checking authenticator…"</Body1>
                    }.into_any(),
                    Some(Some(false)) => view! {
                        <div data-testid="step-up-not-enrolled">
                            <MessageBar intent=MessageBarIntent::Warning>
                                "Set up an authenticator in Account Settings before this action."
                            </MessageBar>
                            <Flex gap=FlexGap::Small>
                                <div data-testid="step-up-cancel">
                                    <Button
                                        appearance=ButtonAppearance::Secondary
                                        button_type=ButtonType::Button
                                        on_click=on_cancel
                                    >
                                        "Cancel"
                                    </Button>
                                </div>
                                <div data-testid="step-up-open-settings">
                                    <Link href=lepton_auth::paths::USER_ACCOUNT_SETTINGS>
                                        "Open settings"
                                    </Link>
                                </div>
                            </Flex>
                        </div>
                    }.into_any(),
                    Some(Some(true)) => {
                        let policy = controller.request_signal().get().policy;
                        view! {
                            <Flex vertical=true gap=FlexGap::Medium>
                                <Show when=move || policy == StepUpPolicy::PasswordAndTotp>
                                    <div data-testid="step-up-password">
                                        <Field label="Current password" required=true>
                                            <Input
                                                bind=InputBind::new(password)
                                                appearance=InputAppearance {
                                                    input_type: Signal::from(InputType::Password),
                                                    ..Default::default()
                                                }
                                            />
                                        </Field>
                                    </div>
                                </Show>
                                <div data-testid="step-up-totp">
                                    <Field label="Authentication code" required=true>
                                        <Input
                                            bind=InputBind::new(totp_code)
                                            appearance=InputAppearance {
                                                input_type: Signal::from(InputType::Text),
                                                placeholder: MaybeProp::<String>::from(
                                                    "6-digit code".to_string(),
                                                ),
                                                ..Default::default()
                                            }
                                        />
                                    </Field>
                                </div>
                                <Flex gap=FlexGap::Small>
                                    <div data-testid="step-up-cancel">
                                        <Button
                                            appearance=ButtonAppearance::Secondary
                                            button_type=ButtonType::Button
                                            on_click=on_cancel
                                            disabled=Signal::derive(move || {
                                                controller.submitting().get()
                                            })
                                        >
                                            "Cancel"
                                        </Button>
                                    </div>
                                    <div data-testid="step-up-submit">
                                        <Button
                                            button_type=ButtonType::Button
                                            on_click=on_continue
                                            disabled=Signal::derive(move || {
                                                controller.submitting().get()
                                            })
                                        >
                                            {move || {
                                                if controller.submitting().get() {
                                                    "Continuing…"
                                                } else {
                                                    "Continue"
                                                }
                                            }}
                                        </Button>
                                    </div>
                                </Flex>
                            </Flex>
                        }
                        .into_any()
                    }
                }}
            </Flex>
        </div>
    }
}
