//! Paged sign-up wizard inside [`super::AuthDialog`].

use leptos::prelude::*;
use leptos::task::spawn_local_scoped;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;
use orbital_base_components::Handler;
use orbital_core_components::Text;
use orbital_core_components::{
    Body1, Button, ButtonAppearance, ButtonType, Field, Flex, FlexGap, InfoLabel, InfoLabelInfo,
    Input, InputAppearance, InputBind, InputEvents, InputType, Link, MessageBar, MessageBarIntent,
};
use orbital_motion::{MotionCurve, OrbitalPresence, PresenceMotion, SlideFrom};

use lepton_auth::actions::account::{RequestEmailVerification, VerifyEmailToken};
use lepton_auth::actions::confirm_account::{issue_phone_otp, verify_phone_otp};
use lepton_auth::actions::totp::{
    begin_totp_enroll_ui, confirm_totp_enroll_ui, PendingTotpEnrollView,
};
use lepton_auth::routes::sanitize_referer_path;
use lepton_auth::security::password_requirement_results;

use super::oauth_provider_buttons::OAuthProviderButtons;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignupPage {
    Email,
    Details,
    EmailVerify,
    PhoneVerify,
    Totp,
}

/// Sign-up wizard: email → account details → email verify → phone → authenticator.
#[allow(clippy::too_many_lines)]
#[component]
pub fn SignupContent(
    referer: Signal<String>,
    #[prop(default = None)] on_success: Option<Callback<()>>,
    #[prop(default = None)] on_switch_signin: Option<Callback<()>>,
) -> impl IntoView {
    let navigate = use_navigate();
    let page = RwSignal::new(SignupPage::Email);
    let going_forward = RwSignal::new(true);

    let email_preview = RwSignal::new(String::new());
    let legal_name_preview = RwSignal::new(String::new());
    let display_name_preview = RwSignal::new(String::new());
    let password_preview = RwSignal::new(String::new());
    let confirm_preview = RwSignal::new(String::new());
    let password_blurred = RwSignal::new(false);
    let confirm_focused = RwSignal::new(false);
    let page_error = RwSignal::new(Option::<String>::None);

    let signup_action = ServerAction::<lepton_auth::actions::signup::Signup>::new();
    let verify_action = ServerAction::<VerifyEmailToken>::new();
    let resend_action = ServerAction::<RequestEmailVerification>::new();

    let verify_token_input = RwSignal::new(String::new());
    let phone_e164 = RwSignal::new(String::new());
    let phone_otp = RwSignal::new(String::new());
    let phone_challenge_id = RwSignal::new(String::new());
    let phone_busy = RwSignal::new(false);

    let totp_pending = RwSignal::new(Option::<PendingTotpEnrollView>::None);
    let totp_code = RwSignal::new(String::new());
    let totp_busy = RwSignal::new(false);

    let password_requirements =
        Memo::new(move |_| password_requirement_results(&password_preview.get()));
    let has_unmet_password_requirements = Memo::new(move |_| {
        password_requirements
            .get()
            .into_iter()
            .any(|requirement| !requirement.satisfied)
    });

    let finish_wizard = Callback::new(move |()| {
        let target = sanitize_referer_path(Some(referer.get()));
        navigate(&target, NavigateOptions::default());
        if let Some(cb) = on_success.as_ref() {
            cb.run(());
        }
    });

    Effect::new(move |_| {
        if signup_action.value().get() == Some(Ok(())) {
            going_forward.set(true);
            page.set(SignupPage::EmailVerify);
            page_error.set(None);
        }
    });

    Effect::new(move |_| {
        if matches!(verify_action.value().get(), Some(Ok(()))) {
            going_forward.set(true);
            page.set(SignupPage::PhoneVerify);
            page_error.set(None);
        }
    });

    let go_next = move |next: SignupPage| {
        going_forward.set(true);
        page_error.set(None);
        page.set(next);
    };

    let page_motion = Signal::derive(move || {
        let from = if going_forward.get() {
            SlideFrom::Right
        } else {
            SlideFrom::Left
        };
        PresenceMotion::slide(from).with_curve(MotionCurve::DecelerateMid)
    });

    let (style_sheet, class_names) = turf::inline_style_sheet_values! {
        .RequirementList {
            margin: 0;
            padding-left: 18px;
            display: grid;
            gap: 4px;
        }

        .RequirementPending {
            color: var(--colorNeutralForeground2, #605e5c);
        }

        .RequirementMet {
            color: var(--colorPaletteGreenForeground1, #107c10);
            font-weight: 600;
        }

        .RequirementUnmet {
            color: var(--colorPaletteRedForeground1, #d13438);
        }

        .WizardFrame {
            min-height: 12rem;
            width: 100%;
        }
    };

    let switch_signin = move || {
        on_switch_signin.map_or_else(
            || {
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
    };

    view! {
        <style>{style_sheet}</style>
        <div data-testid="signup-wizard" class=class_names.wizard_frame>
            <Show when=move || page_error.get().is_some()>
                <div data-testid="signup-error">
                    <MessageBar intent=MessageBarIntent::Error>
                        {move || page_error.get().unwrap_or_default()}
                    </MessageBar>
                </div>
            </Show>
            <Show when=move || matches!(signup_action.value().get(), Some(Err(_)))>
                <div data-testid="signup-error">
                    <MessageBar intent=MessageBarIntent::Error>
                        {move || {
                            signup_action
                                .value()
                                .get()
                                .and_then(Result::err)
                                .map(|e| e.to_string())
                                .unwrap_or_default()
                        }}
                    </MessageBar>
                </div>
            </Show>

            <OrbitalPresence
                appear=true
                show=Signal::derive(move || page.get() == SignupPage::Email)
                motion=page_motion
                respect_reduced_motion=true
            >
                <div data-testid="signup-page-email">
                    <Flex vertical=true gap=FlexGap::Medium>
                        <Body1>"Enter your email to create an account."</Body1>
                        <div data-testid="signup-email">
                            <Field label="Email" required=true>
                                <Input
                                    bind={
                                        let mut bind = InputBind::new(email_preview);
                                        bind.name = "email".into();
                                        bind
                                    }
                                    appearance=InputAppearance::email("Email")
                                />
                            </Field>
                        </div>
                        <div data-testid="signup-email-continue">
                            <Button on_click=Callback::new(move |_| {
                                let email = email_preview.get().trim().to_string();
                                if email.is_empty() || !email.contains('@') {
                                    page_error.set(Some("Enter a valid email address.".into()));
                                    return;
                                }
                                go_next(SignupPage::Details);
                            })>
                                "Continue"
                            </Button>
                        </div>
                        <div>
                            <Text>"Already have an account? "</Text>
                            {switch_signin()}
                        </div>
                        <OAuthProviderButtons referer=referer />
                    </Flex>
                </div>
            </OrbitalPresence>

            <OrbitalPresence
                appear=false
                show=Signal::derive(move || page.get() == SignupPage::Details)
                motion=page_motion
                respect_reduced_motion=true
            >
                <div data-testid="signup-page-details">
                    <ActionForm action=signup_action>
                        <Flex vertical=true gap=FlexGap::Medium>
                            <input type="hidden" name="referer" prop:value=move || referer.get() />
                            <input type="hidden" name="email" prop:value=move || email_preview.get() />
                            <div data-testid="signup-legal-name">
                                <Field label="Legal name" required=true>
                                    <Input
                                        bind={
                                            let mut bind = InputBind::new(legal_name_preview);
                                            bind.name = "legal_name".into();
                                            bind
                                        }
                                        appearance=InputAppearance::with_placeholder("Legal name")
                                    />
                                </Field>
                            </div>
                            <div data-testid="signup-display-name">
                                <Field label="Display name" required=true>
                                    <Input
                                        bind={
                                            let mut bind = InputBind::new(display_name_preview);
                                            bind.name = "display_name".into();
                                            bind
                                        }
                                        appearance=InputAppearance::with_placeholder("Display name")
                                    />
                                </Field>
                            </div>
                            <div data-testid="signup-password">
                                <Field label="Password" required=true>
                                    <Input
                                        bind={
                                            let mut bind = InputBind::new(password_preview);
                                            bind.name = "password".into();
                                            bind
                                        }
                                        appearance=InputAppearance {
                                            input_type: Signal::from(InputType::Password),
                                            placeholder: MaybeProp::<String>::from("Password".to_string()),
                                            ..Default::default()
                                        }
                                        events=InputEvents {
                                            on_blur: Some(Handler::on(move |_: leptos::ev::FocusEvent| password_blurred.set(true))),
                                            ..InputEvents::default()
                                        }
                                    />
                                </Field>
                            </div>
                            <div data-testid="signup-confirm">
                                <Field label="Confirm password" required=true>
                                    <Input
                                        bind={
                                            let mut bind = InputBind::new(confirm_preview);
                                            bind.name = "confirm".into();
                                            bind
                                        }
                                        appearance=InputAppearance {
                                            input_type: Signal::from(InputType::Password),
                                            placeholder: MaybeProp::<String>::from("Confirm password".to_string()),
                                            ..Default::default()
                                        }
                                        events=InputEvents {
                                            on_focus: Some(Handler::on(move |_: leptos::ev::FocusEvent| confirm_focused.set(true))),
                                            on_blur: Some(Handler::on(move |_: leptos::ev::FocusEvent| confirm_focused.set(false))),
                                            ..InputEvents::default()
                                        }
                                    />
                                </Field>
                            </div>
                            <div data-testid="signup-password-help">
                                <MessageBar intent=Signal::derive(move || {
                                    if confirm_focused.get()
                                        && password_blurred.get()
                                        && has_unmet_password_requirements.get()
                                    {
                                        MessageBarIntent::Error
                                    } else {
                                        MessageBarIntent::Info
                                    }
                                })>
                                    <InfoLabel>
                                        "Password requirements (hover for details)"
                                        <InfoLabelInfo slot>
                                            <div>
                                                <Text>"Password requirements"</Text>
                                                <ul class=class_names.requirement_list>
                                                    {move || {
                                                        let show_unmet_error = confirm_focused.get()
                                                            && password_blurred.get();
                                                        password_requirements
                                                            .get()
                                                            .into_iter()
                                                            .map(|item| {
                                                                let class_name = if item.satisfied {
                                                                    class_names.requirement_met
                                                                } else if show_unmet_error {
                                                                    class_names.requirement_unmet
                                                                } else {
                                                                    class_names.requirement_pending
                                                                };
                                                                view! {
                                                                    <li class=class_name>{item.label}</li>
                                                                }
                                                            })
                                                            .collect_view()
                                                    }}
                                                </ul>
                                            </div>
                                        </InfoLabelInfo>
                                    </InfoLabel>
                                </MessageBar>
                            </div>
                            <div data-testid="signup-submit">
                                <Button
                                    button_type=ButtonType::Submit
                                    disabled=Signal::derive(move || signup_action.pending().get())
                                >
                                    "Create account"
                                </Button>
                            </div>
                        </Flex>
                    </ActionForm>
                </div>
            </OrbitalPresence>

            <OrbitalPresence
                appear=false
                show=Signal::derive(move || page.get() == SignupPage::EmailVerify)
                motion=page_motion
                respect_reduced_motion=true
            >
                <div data-testid="signup-page-email-verify">
                    <Flex vertical=true gap=FlexGap::Medium>
                        <Body1>"Confirm your email. We sent a code if mail is configured."</Body1>
                        <Show when=move || matches!(verify_action.value().get(), Some(Err(_)))>
                            <MessageBar intent=MessageBarIntent::Error>
                                {move || {
                                    verify_action
                                        .value()
                                        .get()
                                        .and_then(Result::err)
                                        .map(|e| e.to_string())
                                        .unwrap_or_default()
                                }}
                            </MessageBar>
                        </Show>
                        <ActionForm action=verify_action>
                            <Flex vertical=true gap=FlexGap::Medium>
                                <Field label="Email verification code" required=true>
                                    <Input
                                        bind={
                                            let mut bind = InputBind::new(verify_token_input);
                                            bind.name = "token".into();
                                            bind
                                        }
                                        appearance=InputAppearance::with_placeholder("Paste code")
                                    />
                                </Field>
                                <div data-testid="signup-email-verify-submit">
                                    <Button
                                        button_type=ButtonType::Submit
                                        disabled=Signal::derive(move || verify_action.pending().get())
                                    >
                                        "Verify email"
                                    </Button>
                                </div>
                            </Flex>
                        </ActionForm>
                        <div data-testid="signup-email-resend">
                            <ActionForm action=resend_action>
                                <Button
                                    appearance=ButtonAppearance::Secondary
                                    button_type=ButtonType::Submit
                                    disabled=Signal::derive(move || resend_action.pending().get())
                                >
                                    "Resend email"
                                </Button>
                            </ActionForm>
                        </div>
                        <div data-testid="signup-email-skip">
                            <Button
                                appearance=ButtonAppearance::Transparent
                                on_click=Callback::new(move |_| go_next(SignupPage::PhoneVerify))
                            >
                                "Skip for now"
                            </Button>
                        </div>
                    </Flex>
                </div>
            </OrbitalPresence>

            <OrbitalPresence
                appear=false
                show=Signal::derive(move || page.get() == SignupPage::PhoneVerify)
                motion=page_motion
                respect_reduced_motion=true
            >
                <div data-testid="signup-page-phone">
                    <Flex vertical=true gap=FlexGap::Medium>
                        <Body1>"Add a phone number for SMS codes."</Body1>
                        <Field label="Phone number" required=true>
                            <div data-testid="signup-phone-e164">
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
                        <div data-testid="signup-phone-send">
                            <Button
                                disabled=Signal::derive(move || phone_busy.get())
                                on_click=Callback::new(move |_| {
                                    phone_busy.set(true);
                                    page_error.set(None);
                                    let e164 = phone_e164.get();
                                    spawn_local_scoped(async move {
                                        match issue_phone_otp(e164).await {
                                            Ok(id) => {
                                                phone_challenge_id.set(id);
                                                phone_busy.set(false);
                                            }
                                            Err(e) => {
                                                page_error.set(Some(e.to_string()));
                                                phone_busy.set(false);
                                            }
                                        }
                                    });
                                })
                            >
                                "Send code"
                            </Button>
                        </div>
                        <Field label="SMS code" required=true>
                            <div data-testid="signup-phone-otp">
                                <Input
                                    bind=InputBind::new(phone_otp)
                                    appearance=InputAppearance::with_placeholder("123456")
                                />
                            </div>
                        </Field>
                        <div data-testid="signup-phone-verify">
                            <Button
                                disabled=Signal::derive(move || {
                                    phone_busy.get() || phone_challenge_id.get().is_empty()
                                })
                                on_click=Callback::new(move |_| {
                                    phone_busy.set(true);
                                    page_error.set(None);
                                    let challenge = phone_challenge_id.get();
                                    let code = phone_otp.get();
                                    spawn_local_scoped(async move {
                                        match verify_phone_otp(challenge, code).await {
                                            Ok(()) => {
                                                phone_busy.set(false);
                                                go_next(SignupPage::Totp);
                                            }
                                            Err(e) => {
                                                page_error.set(Some(e.to_string()));
                                                phone_busy.set(false);
                                            }
                                        }
                                    });
                                })
                            >
                                "Verify phone"
                            </Button>
                        </div>
                        <div data-testid="signup-phone-skip">
                            <Button
                                appearance=ButtonAppearance::Transparent
                                on_click=Callback::new(move |_| go_next(SignupPage::Totp))
                            >
                                "Skip for now"
                            </Button>
                        </div>
                    </Flex>
                </div>
            </OrbitalPresence>

            <OrbitalPresence
                appear=false
                show=Signal::derive(move || page.get() == SignupPage::Totp)
                motion=page_motion
                respect_reduced_motion=true
            >
                <div data-testid="signup-page-totp">
                    <Flex vertical=true gap=FlexGap::Medium>
                        <Body1>"Set up an authenticator app for two-factor sign-in."</Body1>
                        <Show when=move || totp_pending.get().is_none()>
                            <div data-testid="signup-totp-start">
                                <Button
                                    disabled=Signal::derive(move || totp_busy.get())
                                    on_click=Callback::new(move |_| {
                                        totp_busy.set(true);
                                        page_error.set(None);
                                        spawn_local_scoped(async move {
                                            match begin_totp_enroll_ui().await {
                                                Ok(pending) => {
                                                    totp_pending.set(Some(pending));
                                                    totp_busy.set(false);
                                                }
                                                Err(e) => {
                                                    page_error.set(Some(e.to_string()));
                                                    totp_busy.set(false);
                                                }
                                            }
                                        });
                                    })
                                >
                                    "Show QR code"
                                </Button>
                            </div>
                        </Show>
                        <Show when=move || totp_pending.get().is_some()>
                            {move || totp_pending.get().map(|p| {
                                let svg = p.qr_svg.clone();
                                let secret = p.manual_secret.clone();
                                let factor_id = p.factor_id;
                                view! {
                                    <div data-testid="signup-totp-qr" inner_html=svg></div>
                                    <Body1>"Or enter this key manually:"</Body1>
                                    <Body1>{secret}</Body1>
                                    <Field label="Authenticator code" required=true>
                                        <Input
                                            bind=InputBind::new(totp_code)
                                            appearance=InputAppearance::with_placeholder("000000")
                                        />
                                    </Field>
                                    <div data-testid="signup-totp-confirm">
                                        <Button
                                            disabled=Signal::derive(move || totp_busy.get())
                                            on_click=Callback::new(move |_| {
                                                totp_busy.set(true);
                                                page_error.set(None);
                                                let code = totp_code.get();
                                                let factor_id = factor_id.clone();
                                                spawn_local_scoped(async move {
                                                    match confirm_totp_enroll_ui(factor_id, code)
                                                        .await
                                                    {
                                                        Ok(_) => {
                                                            totp_busy.set(false);
                                                            finish_wizard.run(());
                                                        }
                                                        Err(e) => {
                                                            page_error.set(Some(e.to_string()));
                                                            totp_busy.set(false);
                                                        }
                                                    }
                                                });
                                            })
                                        >
                                            "Confirm authenticator"
                                        </Button>
                                    </div>
                                }
                            })}
                        </Show>
                        <div data-testid="signup-totp-skip">
                            <Button
                                appearance=ButtonAppearance::Transparent
                                on_click=Callback::new(move |_| finish_wizard.run(()))
                            >
                                "Skip for now"
                            </Button>
                        </div>
                    </Flex>
                </div>
            </OrbitalPresence>
        </div>
    }
}
