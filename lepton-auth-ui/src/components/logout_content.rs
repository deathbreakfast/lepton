//! [`LogoutContent`] — the log-out confirmation form, embeddable in [`super::AuthDialog`]
//! or standalone.

use leptos::prelude::*;
use orbital_core_components::{
    Button, ButtonAppearance, ButtonType, Flex, FlexGap, Link, MessageBar, MessageBarIntent, Text,
};

/// Log-out confirmation form: submits the [`lepton_auth::actions::logout::Logout`] server
/// action and offers a link/callback back to sign-in.
#[component]
pub fn LogoutContent(
    referer: Signal<String>,
    #[prop(default = None)] on_success: Option<Callback<()>>,
    #[prop(default = None)] on_close: Option<Callback<()>>,
    #[prop(default = None)] on_switch_signin: Option<Callback<()>>,
) -> impl IntoView {
    let action = ServerAction::<lepton_auth::actions::logout::Logout>::new();

    Effect::new(move |_| {
        if action.value().get() == Some(Ok(())) {
            if let Some(cb) = on_success.as_ref() {
                cb.run(());
            }
        }
    });

    view! {
        <Flex vertical=true gap=FlexGap::Medium>
            <Show when=move || matches!(action.value().get(), Some(Err(_)))>
                <div data-testid="logout-error">
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
            <Show when=move || matches!(action.value().get(), Some(Ok(())))>
                <div data-testid="logout-info">
                    <MessageBar intent=MessageBarIntent::Info>"You have been signed out."</MessageBar>
                </div>
            </Show>
            <ActionForm action=action>
                <input type="hidden" name="referer" prop:value=move || referer.get() />
                <Flex gap=FlexGap::Small>
                    <div data-testid="logout-button">
                        <Button button_type=ButtonType::Submit>"Log out"</Button>
                    </div>
                    {move || {
                        on_close.map_or_else(
                            move || ().into_any(),
                            |cb| {
                                view! {
                                    <Button
                                        appearance=ButtonAppearance::Secondary
                                        button_type=ButtonType::Button
                                        on_click=Callback::new(move |_| cb.run(()))
                                    >
                                        "Cancel"
                                    </Button>
                                }
                                .into_any()
                            },
                        )
                    }}
                </Flex>
            </ActionForm>
            <div>
                <Text>"Need to sign back in? "</Text>
                {move || {
                    on_switch_signin.map_or_else(
                        move || {
                            view! {
                                <Link href=lepton_auth::paths::SIGNIN inline=true>"Sign in"</Link>
                            }
                            .into_any()
                        },
                        |cb| {
                            view! {
                                <Button appearance=ButtonAppearance::Transparent on_click=Callback::new(move |_| cb.run(()))>
                                    "Sign in"
                                </Button>
                            }
                            .into_any()
                        },
                    )
                }}
            </div>
        </Flex>
    }
}
