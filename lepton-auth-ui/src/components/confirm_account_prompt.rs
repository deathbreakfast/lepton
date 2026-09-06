//! Drop-in re-entry for the account confirm funnel.

use lepton_auth::account_api::ConfirmAccountStatus;
use lepton_auth::actions::confirm_account::get_confirm_account_status;
use lepton_auth::routes::confirm_account_path_with_referer;
use leptos::prelude::*;
use leptos_router::hooks::{use_location, use_navigate};
use leptos_router::NavigateOptions;
use orbital_core_components::{
    Badge, BadgeAppearance, Body1, Button, ButtonAppearance, Card, CardContent, CardHeader, Flex,
    FlexAlign, FlexGap, FlexWrap, MessageBar, MessageBarActions, MessageBarBody, MessageBarIntent,
    MessageBarLayout, Text, Title3,
};

/// Visual density for [`ConfirmAccountPrompt`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConfirmAccountPromptVariant {
    /// Card layout for account settings and similar pages.
    #[default]
    Card,
    /// Compact message bar for shell chrome.
    Compact,
}

/// Resource helper wrapping [`get_confirm_account_status`].
#[must_use]
pub fn confirm_account_status_resource() -> Resource<Result<ConfirmAccountStatus, ServerFnError>> {
    Resource::new(|| (), |()| get_confirm_account_status())
}

/// Shows incomplete confirm status with a Continue CTA to `/user/confirm-account`.
///
/// Continue includes `?referer=` for the current path so finishing confirm returns here.
/// When the account is already confirmed, renders a short success state and no CTA.
#[allow(clippy::too_many_lines)]
#[component]
pub fn ConfirmAccountPrompt(
    /// Layout variant (settings card vs shell banner).
    #[prop(optional, default = ConfirmAccountPromptVariant::Card)]
    variant: ConfirmAccountPromptVariant,
) -> impl IntoView {
    let status = confirm_account_status_resource();
    let navigate = use_navigate();
    let location = use_location();

    view! {
        <Suspense fallback=|| ()>
            {move || {
                match status.get() {
                    Some(Ok(s)) if s.confirmed => {
                        match variant {
                            ConfirmAccountPromptVariant::Compact => {
                                let _: () = view! { <></> };
                                ().into_any()
                            },
                            ConfirmAccountPromptVariant::Card => view! {
                                <div data-testid="confirm-account-prompt-confirmed">
                                    <MessageBar intent=MessageBarIntent::Success>
                                        "Account confirmed."
                                    </MessageBar>
                                </div>
                            }
                            .into_any(),
                        }
                    }
                    Some(Ok(s)) => {
                        let email_ok = s.email_verified;
                        let phone_ok = s.phone_verified;
                        let go = {
                            let navigate = navigate.clone();
                            let location = location.clone();
                            move |_| {
                                let href =
                                    confirm_account_path_with_referer(&location.pathname.get());
                                navigate(&href, NavigateOptions::default());
                            }
                        };
                        match variant {
                            ConfirmAccountPromptVariant::Compact => view! {
                                <div data-testid="confirm-incomplete-banner">
                                    <MessageBar
                                        intent=MessageBarIntent::Warning
                                        layout=MessageBarLayout::Multiline
                                    >
                                        <MessageBarBody>
                                            <Text>"Finish confirming your account"</Text>
                                        </MessageBarBody>
                                        <MessageBarActions>
                                            <div data-testid="confirm-incomplete-continue">
                                                <Button
                                                    appearance=ButtonAppearance::Secondary
                                                    on_click=Callback::new(go)
                                                >
                                                    "Continue"
                                                </Button>
                                            </div>
                                        </MessageBarActions>
                                    </MessageBar>
                                </div>
                            }
                            .into_any(),
                            ConfirmAccountPromptVariant::Card => view! {
                                <div data-testid="confirm-account-prompt">
                                    <Card>
                                        <CardHeader>
                                            <Title3>"Account confirmation"</Title3>
                                        </CardHeader>
                                        <CardContent>
                                            <Flex vertical=true gap=FlexGap::Medium>
                                                <Body1>"Status: Not confirmed"</Body1>
                                                <Flex
                                                    align=FlexAlign::Center
                                                    gap=FlexGap::Small
                                                    wrap=FlexWrap::Wrap
                                                >
                                                    <Badge appearance=BadgeAppearance::Filled>
                                                        {if email_ok { "Email ✓" } else { "Email ○" }}
                                                    </Badge>
                                                    <Badge appearance=BadgeAppearance::Filled>
                                                        {if phone_ok { "Phone ✓" } else { "Phone ○" }}
                                                    </Badge>
                                                    <Badge appearance=BadgeAppearance::Filled>
                                                        "Confirm ○"
                                                    </Badge>
                                                </Flex>
                                                <div data-testid="confirm-account-prompt-continue">
                                                    <Button on_click=Callback::new(go)>
                                                        "Continue setup"
                                                    </Button>
                                                </div>
                                            </Flex>
                                        </CardContent>
                                    </Card>
                                </div>
                            }
                            .into_any(),
                        }
                    }
                    Some(Err(_)) | None => {
                        let _: () = view! { <></> };
                        ().into_any()
                    },
                }
            }}
        </Suspense>
    }
}
