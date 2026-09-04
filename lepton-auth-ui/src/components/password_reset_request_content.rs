//! [`PasswordResetRequestContent`] — the "enter your email" reset request form.

use leptos::prelude::*;
use orbital_core_components::Text;
use orbital_core_components::{
    Button, ButtonType, Field, Flex, FlexGap, Input, InputAppearance, InputBind, InputType,
    MessageBar, MessageBarIntent,
};

/// Form that submits [`lepton_auth::actions::password_reset::RequestPasswordReset`] for the
/// entered email.
#[component]
pub fn PasswordResetRequestContent() -> impl IntoView {
    let action = ServerAction::<lepton_auth::actions::password_reset::RequestPasswordReset>::new();

    view! {
        <Flex vertical=true gap=FlexGap::Medium>
            <Text>"Enter your email. If an account exists, reset instructions will be sent."</Text>
            <Show when=move || matches!(action.value().get(), Some(Ok(())))>
                <div data-testid="password-reset-request-success">
                    <MessageBar intent=MessageBarIntent::Success>
                        "If the account exists, reset instructions were issued."
                    </MessageBar>
                </div>
            </Show>
            <Show when=move || matches!(action.value().get(), Some(Err(_)))>
                <div data-testid="password-reset-request-error">
                    <MessageBar intent=MessageBarIntent::Error>
                        {move || {
                            action
                                .value()
                                .get()
                                .and_then(Result::err)
                                .map(|e| e.to_string())
                                .unwrap_or_default()
                        }}
                    </MessageBar>
                </div>
            </Show>
            <ActionForm action=action>
                <Flex vertical=true gap=FlexGap::Medium>
                    <div data-testid="password-reset-request-email">
                        <Field label="Email" required=true>
                            <Input bind=InputBind { name: "email".into(), ..InputBind::default() } appearance=InputAppearance { input_type: Signal::from(InputType::Email), ..Default::default() } />
                        </Field>
                    </div>
                    <div data-testid="password-reset-request-submit">
                        <Button button_type=ButtonType::Submit>"Request reset"</Button>
                    </div>
                </Flex>
            </ActionForm>
        </Flex>
    }
}
