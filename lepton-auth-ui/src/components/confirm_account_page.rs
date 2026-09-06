//! Guided account confirm funnel (email → phone → confirm).

use lepton_auth::account_api::ConfirmAccountStatus;
use lepton_auth::actions::account::{RequestEmailVerification, VerifyEmailToken};
use lepton_auth::actions::confirm_account::{
    confirm_account, get_confirm_account_status, issue_phone_otp, verify_phone_otp,
};
#[cfg(not(feature = "hydrate"))]
use lepton_auth::routes::parse_token_from_url_parts;
use lepton_auth::routes::{parse_referer_from_search, sanitize_referer_path};
#[cfg(feature = "hydrate")]
use lepton_auth::token_url::{
    read_token_from_window_location, strip_legacy_token_query_from_address_bar,
};
use leptos::prelude::*;
use leptos_router::hooks::use_location;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;
use orbital_core_components::{
    Badge, BadgeAppearance, Body1, Button, ButtonAppearance, ButtonType, Card, CardContent,
    CardHeader, Field, Flex, FlexAlign, FlexGap, FlexWrap, Input, InputAppearance, InputBind,
    InputType, MessageBar, MessageBarIntent, Text, Title3,
};

/// Active step in the confirm funnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfirmStep {
    Email,
    Phone,
    Confirm,
}

const fn active_step(status: &ConfirmAccountStatus) -> ConfirmStep {
    if !status.email_verified {
        ConfirmStep::Email
    } else if !status.phone_verified {
        ConfirmStep::Phone
    } else {
        ConfirmStep::Confirm
    }
}

/// `/user/confirm-account` guided stepper (Orbital composition only).
#[component]
#[allow(clippy::too_many_lines)] // email / phone / confirm steps in one page component
pub fn ConfirmAccountPage() -> impl IntoView {
    let location = use_location();
    let navigate = use_navigate();
    let status = Resource::new(|| (), |()| get_confirm_account_status());
    let refresh = move || status.refetch();

    let return_path = Memo::new(move |_| {
        sanitize_referer_path(parse_referer_from_search(&location.search.get()))
    });

    let verify_action = ServerAction::<VerifyEmailToken>::new();
    let resend_action = ServerAction::<RequestEmailVerification>::new();
    let phone_challenge_id = RwSignal::new(String::new());
    let phone_e164 = RwSignal::new(String::new());
    let phone_otp = RwSignal::new(String::new());
    let phone_error = RwSignal::new(Option::<String>::None);
    let phone_success = RwSignal::new(false);
    let phone_busy = RwSignal::new(false);
    let confirm_error = RwSignal::new(Option::<String>::None);
    let confirm_success = RwSignal::new(false);
    let confirm_busy = RwSignal::new(false);

    let token_from_query = Memo::new(move |_| {
        #[cfg(feature = "hydrate")]
        {
            read_token_from_window_location()
        }
        #[cfg(not(feature = "hydrate"))]
        {
            parse_token_from_url_parts(&location.search.get(), "").unwrap_or_default()
        }
    });
    let verify_token_input = RwSignal::new(String::new());
    Effect::new(move |_| {
        let from_url = token_from_query.get();
        if !from_url.is_empty() {
            verify_token_input.set(from_url);
        }
    });
    #[cfg(feature = "hydrate")]
    Effect::new(move |_| {
        if !token_from_query.get().is_empty() {
            strip_legacy_token_query_from_address_bar();
        }
    });

    Effect::new(move |_| {
        if matches!(verify_action.value().get(), Some(Ok(()))) {
            refresh();
        }
    });

    let on_send_phone = move |_| {
        phone_error.set(None);
        phone_success.set(false);
        phone_busy.set(true);
        let e164 = phone_e164.get();
        leptos::task::spawn_local_scoped(async move {
            match issue_phone_otp(e164).await {
                Ok(id) => {
                    phone_challenge_id.set(id);
                    phone_busy.set(false);
                }
                Err(e) => {
                    phone_error.set(Some(e.to_string()));
                    phone_busy.set(false);
                }
            }
        });
    };

    let on_verify_phone = move |_| {
        phone_error.set(None);
        phone_busy.set(true);
        let challenge = phone_challenge_id.get();
        let code = phone_otp.get();
        leptos::task::spawn_local_scoped(async move {
            match verify_phone_otp(challenge, code).await {
                Ok(()) => {
                    phone_success.set(true);
                    phone_busy.set(false);
                    refresh();
                }
                Err(e) => {
                    phone_error.set(Some(e.to_string()));
                    phone_busy.set(false);
                }
            }
        });
    };

    let on_confirm = move |_| {
        confirm_error.set(None);
        confirm_busy.set(true);
        leptos::task::spawn_local_scoped(async move {
            match confirm_account().await {
                Ok(()) => {
                    confirm_success.set(true);
                    confirm_busy.set(false);
                    refresh();
                }
                Err(e) => {
                    confirm_error.set(Some(e.to_string()));
                    confirm_busy.set(false);
                }
            }
        });
    };

    let on_skip = Callback::new(move |_| {
        let path = return_path.get();
        if path == "/" {
            navigate("/welcome", NavigateOptions::default());
        } else {
            navigate(&path, NavigateOptions::default());
        }
    });

    view! {
        <div data-testid="confirm-account-container">
            <Flex vertical=true gap=FlexGap::Large>
                <Title3>"Confirm your account"</Title3>

                <Suspense fallback=move || {
                    view! { <Body1>"Loading…"</Body1> }
                }>
                    {move || {
                        match status.get() {
                            Some(Ok(s)) if s.confirmed || confirm_success.get() => {
                                view! {
                                    <div data-testid="confirm-account-success">
                                        <MessageBar intent=MessageBarIntent::Success>
                                            "Account confirmed."
                                        </MessageBar>
                                    </div>
                                }
                                .into_any()
                            }
                            Some(Ok(s)) => {
                                let step = active_step(&s);
                                let email_done = s.email_verified;
                                let phone_done = s.phone_verified;
                                let email_sent_to =
                                    format!("Code sent to {}", s.masked_email);
                                let email_summary =
                                    format!("Email ✓  {}", s.masked_email);
                                let phone_summary = format!(
                                    "Phone ✓  {}",
                                    s.masked_phone

                                        .unwrap_or_else(|| "••••".into())
                                );
                                let indicator = view! {
                                    <div data-testid="confirm-step-indicator">
                                        <Flex
                                            align=FlexAlign::Center
                                            gap=FlexGap::Small
                                            wrap=FlexWrap::Wrap
                                        >
                                            <Badge appearance=BadgeAppearance::Filled>
                                                {if email_done {
                                                    "Email ✓"
                                                } else if step == ConfirmStep::Email {
                                                    "Email ●"
                                                } else {
                                                    "Email ○"
                                                }}
                                            </Badge>
                                            <Badge appearance=BadgeAppearance::Filled>
                                                {if phone_done {
                                                    "Phone ✓"
                                                } else if step == ConfirmStep::Phone {
                                                    "Phone ●"
                                                } else {
                                                    "Phone ○"
                                                }}
                                            </Badge>
                                            <Badge appearance=BadgeAppearance::Filled>
                                                {if step == ConfirmStep::Confirm {
                                                    "Confirm ●"
                                                } else {
                                                    "Confirm ○"
                                                }}
                                            </Badge>
                                        </Flex>
                                    </div>
                                };
                                let step_panel = match step {
                                    ConfirmStep::Email => view! {
                                        <div data-testid="confirm-step-email">
                                            <Card>
                                                <CardHeader>
                                                    <Text>"Verify email"</Text>
                                                </CardHeader>
                                                <CardContent>
                                                    <Flex vertical=true gap=FlexGap::Medium>
                                                        <Body1>{email_sent_to}</Body1>
                                                        <Show when=move || {
                                                            matches!(
                                                                verify_action.value().get(),
                                                                Some(Err(_))
                                                            )
                                                        }>
                                                            <div data-testid="confirm-email-error">
                                                                <MessageBar intent=MessageBarIntent::Error>
                                                                    {move || {
                                                                        verify_action
                                                                            .value()
                                                                            .get()
                                                                            .and_then(Result::err)
                                                                            .map_or_else(
                                                                                || "Unable to verify email.".to_string(),
                                                                                |e| e.to_string(),
                                                                            )
                                                                    }}
                                                                </MessageBar>
                                                            </div>
                                                        </Show>
                                                        <ActionForm action=verify_action>
                                                            <Flex vertical=true gap=FlexGap::Medium>
                                                                <Field label="Verification code" required=true>
                                                                    <div data-testid="confirm-email-token">
                                                                        <Input
                                                                            bind={
                                                                                let mut bind = InputBind::new(verify_token_input);
                                                                                bind.name = "token".into();
                                                                                bind
                                                                            }
                                                                            appearance=InputAppearance::with_placeholder("Paste code")
                                                                        />
                                                                    </div>
                                                                </Field>
                                                                <div data-testid="confirm-email-verify">
                                                                    <Button
                                                                        button_type=ButtonType::Submit
                                                                        disabled=verify_action.pending()
                                                                    >
                                                                        "Verify email"
                                                                    </Button>
                                                                </div>
                                                            </Flex>
                                                        </ActionForm>
                                                        <ActionForm action=resend_action>
                                                            <div data-testid="confirm-email-resend">
                                                                <Button
                                                                    appearance=ButtonAppearance::Secondary
                                                                    button_type=ButtonType::Submit
                                                                    disabled=resend_action.pending()
                                                                >
                                                                    "Resend code"
                                                                </Button>
                                                            </div>
                                                        </ActionForm>
                                                        <Show when=move || {
                                                            matches!(
                                                                resend_action.value().get(),
                                                                Some(Ok(()))
                                                            )
                                                        }>
                                                            <div data-testid="confirm-email-success">
                                                                <MessageBar intent=MessageBarIntent::Success>
                                                                    "Verification email sent."
                                                                </MessageBar>
                                                            </div>
                                                        </Show>
                                                        <div data-testid="confirm-skip">
                                                            <Button
                                                                appearance=ButtonAppearance::Transparent
                                                                on_click=on_skip
                                                            >
                                                                "Skip for now"
                                                            </Button>
                                                        </div>
                                                    </Flex>
                                                </CardContent>
                                            </Card>
                                        </div>
                                    }
                                    .into_any(),
                                    ConfirmStep::Phone => view! {
                                        <div data-testid="confirm-step-phone">
                                            <Card>
                                                <CardHeader>
                                                    <Text>"Add and verify phone"</Text>
                                                </CardHeader>
                                                <CardContent>
                                                    <Flex vertical=true gap=FlexGap::Medium>
                                                        <Show when=move || phone_error.get().is_some()>
                                                            <div data-testid="confirm-phone-error">
                                                                <MessageBar intent=MessageBarIntent::Error>
                                                                    {move || {
                                                                        phone_error
                                                                            .get()
                                                                            .unwrap_or_default()
                                                                    }}
                                                                </MessageBar>
                                                            </div>
                                                        </Show>
                                                        <Show when=move || phone_success.get()>
                                                            <div data-testid="confirm-phone-success">
                                                                <MessageBar intent=MessageBarIntent::Success>
                                                                    "Phone verified."
                                                                </MessageBar>
                                                            </div>
                                                        </Show>
                                                        <Field label="Phone number" required=true>
                                                            <div data-testid="confirm-phone-e164">
                                                                <Input
                                                                    bind=InputBind::new(phone_e164)
                                                                    appearance=InputAppearance {
                                                                        input_type: Signal::from(InputType::Tel),
                                                                        placeholder: MaybeProp::<String>::from(
                                                                            "(555) 123-4567".to_string(),
                                                                        ),
                                                                        ..Default::default()
                                                                    }
                                                                />
                                                            </div>
                                                        </Field>
                                                        <div data-testid="confirm-phone-send">
                                                            <Button
                                                                button_type=ButtonType::Button
                                                                disabled=phone_busy
                                                                on_click=Callback::new(on_send_phone)
                                                            >
                                                                "Send code"
                                                            </Button>
                                                        </div>
                                                        <Field label="SMS code" required=true>
                                                            <div data-testid="confirm-phone-otp">
                                                                <Input
                                                                    bind=InputBind::new(phone_otp)
                                                                    appearance=InputAppearance::with_placeholder("123456")
                                                                />
                                                            </div>
                                                        </Field>
                                                        <div data-testid="confirm-phone-verify">
                                                            <Button
                                                                button_type=ButtonType::Button
                                                                disabled=Signal::derive(move || {
                                                                    phone_busy.get()
                                                                        || phone_challenge_id.get().is_empty()
                                                                })
                                                                on_click=Callback::new(on_verify_phone)
                                                            >
                                                                "Verify phone"
                                                            </Button>
                                                        </div>
                                                        <div data-testid="confirm-skip">
                                                            <Button
                                                                appearance=ButtonAppearance::Transparent
                                                                on_click=on_skip
                                                            >
                                                                "Skip for now"
                                                            </Button>
                                                        </div>
                                                    </Flex>
                                                </CardContent>
                                            </Card>
                                        </div>
                                    }
                                    .into_any(),
                                    ConfirmStep::Confirm => view! {
                                        <div data-testid="confirm-step-confirm">
                                            <Card>
                                                <CardHeader>
                                                    <Text>"Confirm account"</Text>
                                                </CardHeader>
                                                <CardContent>
                                                    <Flex vertical=true gap=FlexGap::Medium>
                                                        <Flex
                                                            align=FlexAlign::Center
                                                            gap=FlexGap::Small
                                                            wrap=FlexWrap::Wrap
                                                        >
                                                            <Body1>{email_summary}</Body1>
                                                            <Body1>{phone_summary}</Body1>
                                                        </Flex>
                                                        <Show when=move || {
                                                            confirm_error.get().is_some()
                                                        }>
                                                            <div data-testid="confirm-account-error">
                                                                <MessageBar intent=MessageBarIntent::Error>
                                                                    {move || {
                                                                        confirm_error
                                                                            .get()
                                                                            .unwrap_or_default()
                                                                    }}
                                                                </MessageBar>
                                                            </div>
                                                        </Show>
                                                        <div data-testid="confirm-account-submit">
                                                            <Button
                                                                button_type=ButtonType::Button
                                                                disabled=confirm_busy
                                                                on_click=Callback::new(on_confirm)
                                                            >
                                                                "Confirm account"
                                                            </Button>
                                                        </div>
                                                    </Flex>
                                                </CardContent>
                                            </Card>
                                        </div>
                                    }
                                    .into_any(),
                                };
                                view! {
                                    <Flex vertical=true gap=FlexGap::Large>
                                        {indicator}
                                        {step_panel}
                                    </Flex>
                                }
                                .into_any()
                            }
                            Some(Err(e)) => view! {
                                <MessageBar intent=MessageBarIntent::Error>
                                    {e.to_string()}
                                </MessageBar>
                            }
                            .into_any(),
                            None => view! { <Body1>"Loading…"</Body1> }.into_any(),
                        }
                    }}
                </Suspense>
            </Flex>
        </div>
    }
}
