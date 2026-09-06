//! [`SigninContent`] — the sign-in form, embeddable in [`super::AuthDialog`] or standalone.

use lepton_auth::actions::signin::SigninClientOutcome;
use leptos::prelude::*;
use leptos_router::hooks::{use_location, use_navigate};
use leptos_router::NavigateOptions;
use orbital_core_components::FormHint;
use orbital_core_components::{
    Body1, Button, ButtonAppearance, ButtonType, Field, Flex, FlexGap, Input, InputAppearance,
    InputBind, InputType, Link, MessageBar, MessageBarIntent, Text,
};

use super::oauth_provider_buttons::OAuthProviderButtons;

fn location_path_with_search(pathname: &str, search: &str) -> String {
    let mut path = pathname.to_owned();
    if !search.is_empty() {
        path.push_str(search);
    }
    path
}

/// Run success callback, then navigate only when the target differs from the current URL.
fn finish_signed_in_navigate(
    on_success: Option<Callback<()>>,
    navigate: impl Fn(&str, NavigateOptions),
    current_path: &str,
    redirect_to: &str,
) {
    if let Some(cb) = on_success {
        cb.run(());
    }
    // Stay put when already on the post-auth target (in-place gate modal).
    if current_path != redirect_to {
        navigate(redirect_to, NavigateOptions::default());
    }
}

/// Sign-in form: submits [`lepton_auth::actions::signin::Signin`], optional MFA step,
/// and offers a link/callback to switch to sign-up or request a password reset.
#[component]
#[allow(clippy::too_many_lines)] // password + MFA + passkey + OAuth layout in one component
pub fn SigninContent(
    referer: Signal<String>,
    #[prop(default = None)] on_success: Option<Callback<()>>,
    #[prop(default = None)] on_switch_signup: Option<Callback<()>>,
) -> impl IntoView {
    let navigate = use_navigate();
    let location = use_location();
    let signin_action = ServerAction::<lepton_auth::actions::signin::Signin>::new();
    let mfa_action = ServerAction::<lepton_auth::actions::signin::CompleteMfaTotp>::new();
    let mfa_step = RwSignal::new(false);
    let has_webauthn = RwSignal::new(false);
    let mfa_error = RwSignal::new(Option::<String>::None);
    let passkey_redirect = RwSignal::new(Option::<String>::None);

    Effect::new({
        let navigate = navigate.clone();
        move |_| match signin_action.value().get() {
            Some(Ok(SigninClientOutcome::Completed { redirect_to })) => {
                let current = location_path_with_search(
                    &location.pathname.get_untracked(),
                    &location.search.get_untracked(),
                );
                finish_signed_in_navigate(on_success, navigate.clone(), &current, &redirect_to);
            }
            Some(Ok(SigninClientOutcome::NeedsMfa { has_webauthn: wa })) => {
                has_webauthn.set(wa);
                mfa_step.set(true);
                mfa_error.set(None);
            }
            Some(Err(_)) => {
                mfa_step.set(false);
            }
            None => {}
        }
    });

    Effect::new({
        let navigate = navigate.clone();
        move |_| match mfa_action.value().get() {
            Some(Ok(SigninClientOutcome::Completed { redirect_to })) => {
                let current = location_path_with_search(
                    &location.pathname.get_untracked(),
                    &location.search.get_untracked(),
                );
                finish_signed_in_navigate(on_success, navigate.clone(), &current, &redirect_to);
            }
            Some(Ok(SigninClientOutcome::NeedsMfa { .. })) | None => {}
            Some(Err(e)) => {
                mfa_error.set(Some(e.to_string()));
            }
        }
    });

    Effect::new({
        let navigate = navigate.clone();
        move |_| {
            if let Some(path) = passkey_redirect.get() {
                let current = location_path_with_search(
                    &location.pathname.get_untracked(),
                    &location.search.get_untracked(),
                );
                finish_signed_in_navigate(on_success, navigate.clone(), &current, &path);
            }
        }
    });

    let on_passkey = move |_| {
        #[cfg(feature = "hydrate")]
        {
            use leptos::task::spawn_local_scoped;
            mfa_error.set(None);
            spawn_local_scoped(async move {
                match run_mfa_webauthn().await {
                    Ok(redirect_to) => passkey_redirect.set(Some(redirect_to)),
                    Err(e) => mfa_error.set(Some(e)),
                }
            });
        }
        #[cfg(not(feature = "hydrate"))]
        {
            mfa_error.set(Some("Passkey sign-in requires a browser.".into()));
        }
    };

    view! {
        <Flex vertical=true gap=FlexGap::Medium>
            <Show when=move || !mfa_step.get()>
                <Show when=move || matches!(signin_action.value().get(), Some(Err(_)))>
                    <div data-testid="signin-error">
                        <MessageBar intent=MessageBarIntent::Error>
                            {move || {
                                signin_action
                                    .value()
                                    .get()
                                    .and_then(Result::err)
                                    .map(|e| e.to_string())
                                    .unwrap_or_default()
                            }}
                        </MessageBar>
                    </div>
                </Show>
                <ActionForm action=signin_action>
                    <Flex vertical=true gap=FlexGap::Medium>
                        <input type="hidden" name="referer" prop:value=move || referer.get() />
                        <div data-testid="signin-email">
                            <Field label="Email" required=true>
                                <Input
                                    bind=InputBind { name: "email".into(), ..InputBind::default() }
                                    appearance=InputAppearance::email("Email")
                                />
                            </Field>
                        </div>
                        <div data-testid="signin-password">
                            <Field label="Password" required=true>
                                <Input
                                    bind=InputBind { name: "password".into(), ..InputBind::default() }
                                    appearance=InputAppearance {
                                        input_type: Signal::from(InputType::Password),
                                        placeholder: MaybeProp::<String>::from("Password".to_string()),
                                        ..Default::default()
                                    }
                                />
                            </Field>
                        </div>
                        <div data-testid="signin-submit">
                            <Button button_type=ButtonType::Submit>"Sign In"</Button>
                        </div>
                    </Flex>
                </ActionForm>
                <div>
                    <Text>"New here? "</Text>
                    {move || {
                        on_switch_signup.map_or_else(
                            move || {
                                view! {
                                    <Link href=lepton_auth::paths::SIGNUP inline=true>"Create an account"</Link>
                                }
                                .into_any()
                            },
                            |cb| {
                                view! {
                                    <Button appearance=ButtonAppearance::Transparent on_click=Callback::new(move |_| cb.run(()))>
                                        "Create an account"
                                    </Button>
                                }
                                .into_any()
                            },
                        )
                    }}
                </div>
                <div>
                    <Link href=lepton_auth::paths::RESET_PASSWORD_REQUEST inline=true>
                        "Forgot your password?"
                    </Link>
                </div>
                <OAuthProviderButtons referer=referer />
            </Show>

            <Show when=move || mfa_step.get()>
                <div data-testid="signin-mfa-step">
                    <Flex vertical=true gap=FlexGap::Medium>
                        <Show when=move || mfa_error.get().is_some()>
                            <div data-testid="signin-mfa-error">
                                <MessageBar intent=MessageBarIntent::Error>
                                    {move || mfa_error.get().unwrap_or_default()}
                                </MessageBar>
                            </div>
                        </Show>
                        <Body1>"Enter the code from your authenticator app."</Body1>
                        <ActionForm action=mfa_action>
                            <Flex vertical=true gap=FlexGap::Medium>
                                <div data-testid="signin-mfa-totp">
                                    <Field label="Authentication code" required=true>
                                        <Input
                                            bind=InputBind { name: "code".into(), ..InputBind::default() }
                                            appearance=InputAppearance {
                                                input_type: Signal::from(InputType::Text),
                                                placeholder: MaybeProp::<String>::from("000000".to_string()),
                                                ..Default::default()
                                            }
                                        />
                                        <FormHint test_id="signin-mfa-recovery-hint">
                                            "You can also enter a one-time recovery code."
                                        </FormHint>
                                    </Field>
                                </div>
                                <div data-testid="signin-mfa-remember">
                                    <Field label="Remember this browser">
                                        <label>
                                            <input type="checkbox" name="remember" value="true" />
                                            " Remember this browser for 30 days"
                                        </label>
                                    </Field>
                                </div>
                                <div data-testid="signin-mfa-submit">
                                    <Button button_type=ButtonType::Submit>"Verify"</Button>
                                </div>
                            </Flex>
                        </ActionForm>
                        <Show when=move || has_webauthn.get()>
                            <div data-testid="signin-mfa-passkey">
                                <Button
                                    appearance=ButtonAppearance::Secondary
                                    on_click=Callback::new(on_passkey)
                                >
                                    "Use passkey"
                                </Button>
                            </div>
                        </Show>
                    </Flex>
                </div>
            </Show>
        </Flex>
    }
}

#[cfg(feature = "hydrate")]
async fn run_mfa_webauthn() -> Result<String, String> {
    use lepton_auth::webauthn_browser::credentials_get_json;

    let pending = lepton_auth::actions::signin::begin_mfa_webauthn()
        .await
        .map_err(|e| e.to_string())?;
    let assertion = credentials_get_json(&pending.request_options)
        .await
        .map_err(|e| e.to_string())?;
    let outcome = lepton_auth::actions::signin::finish_mfa_webauthn(pending.ceremony_id, assertion)
        .await
        .map_err(|e| e.to_string())?;
    match outcome {
        SigninClientOutcome::Completed { redirect_to } => Ok(redirect_to),
        SigninClientOutcome::NeedsMfa { .. } => Err("Unexpected MFA state after passkey".into()),
    }
}
