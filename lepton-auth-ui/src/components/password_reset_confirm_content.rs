//! [`PasswordResetConfirmContent`] — the "set new password" form for a reset token.

use leptos::prelude::*;
use orbital_core_components::{
    Button, ButtonType, Field, Flex, FlexGap, InfoLabel, InfoLabelInfo, Input, InputAppearance,
    InputBind, InputType, Link, MessageBar, MessageBarIntent,
};

use lepton_auth::security::password_requirement_results;

/// Form that takes a reset token and new password and submits
/// [`lepton_auth::actions::password_reset::ResetPassword`].
#[component]
pub fn PasswordResetConfirmContent(
    #[prop(into)] token_from_query: Signal<String>,
) -> impl IntoView {
    let action = ServerAction::<lepton_auth::actions::password_reset::ResetPassword>::new();
    let token_input = RwSignal::new(String::new());
    Effect::new(move |_| {
        let from_url = token_from_query.get();
        if !from_url.is_empty() {
            token_input.set(from_url);
        }
    });
    let password_preview = RwSignal::new(String::new());
    let requirements = Memo::new(move |_| password_requirement_results(&password_preview.get()));

    view! {
        <Flex vertical=true gap=FlexGap::Medium>
            {move || match action.value().get() {
                Some(Ok(())) => view! {
                    <MessageBar intent=MessageBarIntent::Success>
                        "Password reset complete. You can sign in now."
                    </MessageBar>
                }.into_any(),
                Some(Err(_)) => view! {
                    <div data-testid="password-reset-confirm-error">
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
                }.into_any(),
                None => view! {
                    <span
                        data-testid="password-reset-confirm-idle"
                        style="display:none"
                        aria-hidden="true"
                    />
                }.into_any(),
            }}
            <ActionForm action=action>
                <Flex vertical=true gap=FlexGap::Medium>
                    <Field label="Reset token" required=true>
                        <Input
                            bind={
                                let mut bind = InputBind::new(token_input);
                                bind.name = "token".into();
                                bind
                            }
                        />
                    </Field>
                    <Field label="New password" required=true>
                        <Input
                            bind={
                                let mut bind = InputBind::new(password_preview);
                                bind.name = "new_password".into();
                                bind
                            }
                            appearance=InputAppearance {
                                input_type: Signal::from(InputType::Password),
                                ..Default::default()
                            }
                        />
                    </Field>
                    <MessageBar intent=MessageBarIntent::Info>
                        <InfoLabel>
                            "Password requirements (hover for details)"
                            <InfoLabelInfo slot>
                                <ul data-testid="reset-password-requirements">
                                    <For
                                        each=move || requirements.get()
                                        key=|item| item.label
                                        children=move |item| view! { <li>{item.label}</li> }
                                    />
                                </ul>
                            </InfoLabelInfo>
                        </InfoLabel>
                    </MessageBar>
                    <Field label="Confirm new password" required=true>
                        <Input bind=InputBind { name: "confirm_password".into(), ..InputBind::default() } appearance=InputAppearance { input_type: Signal::from(InputType::Password), ..Default::default() } />
                    </Field>
                    <Button button_type=ButtonType::Submit>"Reset password"</Button>
                </Flex>
            </ActionForm>
            <Link href=lepton_auth::paths::SIGNIN inline=true>"Back to sign in"</Link>
        </Flex>
    }
}
