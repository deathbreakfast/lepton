//! E2e harness: sensitive actions gated by [`lepton_auth_ui::StepUpDialog`].

use lepton_auth_ui::{StepUpController, StepUpDialog, StepUpFactors, StepUpPolicy, StepUpRequest};
use leptos::prelude::*;
use orbital_core_components::{Body1, Caption1, Subtitle1};
use orbital_primitives::{
    Button, ButtonAppearance, Card, CardContent, CardHeader, Flex, FlexGap, MessageBar,
    MessageBarIntent, Title3,
};

use crate::page_shell::E2ePageShell;

/// Demo page that opens step-up before calling harness server fns.
#[component]
pub fn E2eStepUpDemo(controller: StepUpController) -> impl IntoView {
    let result = RwSignal::new(String::from("idle"));

    let run_totp = Callback::new(move |(): ()| {
        result.set("idle".into());
        controller.request(
            StepUpRequest {
                title: "Confirm it's you".into(),
                description: Some("Enter your authenticator code to complete this action.".into()),
                policy: StepUpPolicy::Totp,
            },
            Callback::new(move |factors: StepUpFactors| {
                leptos::task::spawn_local_scoped(async move {
                    match step_up_demo_sensitive_op(factors.totp_code).await {
                        Ok(()) => {
                            result.set("success".into());
                            controller.complete_success();
                        }
                        Err(e) => {
                            result.set("unchanged".into());
                            controller.report_error(map_step_up_err(&e));
                        }
                    }
                });
            }),
        );
    });

    let run_password_totp = Callback::new(move |(): ()| {
        result.set("idle".into());
        controller.request(
            StepUpRequest {
                title: "Confirm it's you".into(),
                description: Some(
                    "Re-enter your password and an authenticator code to continue.".into(),
                ),
                policy: StepUpPolicy::PasswordAndTotp,
            },
            Callback::new(move |factors: StepUpFactors| {
                leptos::task::spawn_local_scoped(async move {
                    let password = factors.password.unwrap_or_default();
                    match step_up_demo_password_and_totp(password, factors.totp_code).await {
                        Ok(()) => {
                            result.set("success".into());
                            controller.complete_success();
                        }
                        Err(e) => {
                            result.set("unchanged".into());
                            controller.report_error(map_step_up_err(&e));
                        }
                    }
                });
            }),
        );
    });

    view! {
        <E2ePageShell data_testid="step-up-demo-container">
            <Title3>"Step-up demo"</Title3>
            <Card>
                <CardHeader>
                    <Subtitle1>"Sensitive actions"</Subtitle1>
                </CardHeader>
                <CardContent>
                    <Flex vertical=true gap=FlexGap::Medium>
                        <Caption1>
                            "These buttons open the step-up dialog before calling harness server functions."
                        </Caption1>
                        <div data-testid="step-up-demo-result">
                            <Body1>{move || result.get()}</Body1>
                        </div>
                        <Show when=move || result.get() == "success">
                            <div data-testid="step-up-demo-success">
                                <MessageBar intent=MessageBarIntent::Success>
                                    "Sensitive action completed."
                                </MessageBar>
                            </div>
                        </Show>
                        <Flex gap=FlexGap::Small wrap=orbital_primitives::FlexWrap::Wrap>
                            <div data-testid="step-up-demo-totp-trigger">
                                <Button
                                    appearance=ButtonAppearance::Primary
                                    on_click=Callback::new(move |_| run_totp.run(()))
                                >
                                    "Sensitive action (TOTP)"
                                </Button>
                            </div>
                            <div data-testid="step-up-demo-password-totp-trigger">
                                <Button
                                    appearance=ButtonAppearance::Secondary
                                    on_click=Callback::new(move |_| run_password_totp.run(()))
                                >
                                    "Sensitive action (password + TOTP)"
                                </Button>
                            </div>
                        </Flex>
                    </Flex>
                </CardContent>
            </Card>
            <StepUpDialog controller=controller />
        </E2ePageShell>
    }
}

fn map_step_up_err(e: &ServerFnError) -> String {
    let text = e.to_string();
    if (text.contains("password") || text.contains("Password"))
        && (text.contains("incorrect") || text.contains("Incorrect"))
    {
        return "Current password is incorrect".into();
    }
    if text.contains("incorrect")
        || text.contains("Incorrect")
        || text.contains("mismatch")
        || text.contains("invalid totp")
    {
        return "Authenticator code is incorrect".into();
    }
    if text.contains("authenticator") || text.contains("totp_unavailable") {
        return "Set up an authenticator in Account Settings before this action.".into();
    }
    text
}

/// Strict TOTP step-up then mark the demo mutation complete.
#[server(StepUpDemoSensitiveOp)]
pub async fn step_up_demo_sensitive_op(totp_code: String) -> Result<(), ServerFnError> {
    use lepton_auth::{require_auth_user, FactorChallengeService};

    let (ctx, auth_user) = require_auth_user().await?;
    // TotpFactor secrets are system-readable (same as MFA complete / settings verify).
    let valence = ctx
        .unsafe_system_valence()
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let services = lepton_auth::auth_services()?;
    let factors = FactorChallengeService::new(services);
    factors
        .verify_totp_code(&valence, &auth_user.id, &totp_code)
        .await
        .map_err(|e| match e {
            lepton_auth::FactorChallengeError::TotpInvalid => {
                ServerFnError::Args("Authenticator code is incorrect".into())
            }
            lepton_auth::FactorChallengeError::TotpUnavailable => ServerFnError::Args(
                "Set up an authenticator in Account Settings before this action.".into(),
            ),
            other => ServerFnError::new(other.to_string()),
        })?;
    Ok(())
}

/// Password re-check + strict TOTP before the demo mutation.
#[server(StepUpDemoPasswordAndTotp)]
pub async fn step_up_demo_password_and_totp(
    current_password: String,
    totp_code: String,
) -> Result<(), ServerFnError> {
    use lepton_auth::token_helpers::verify_token_secret;
    use lepton_auth::{require_auth_user, FactorChallengeService};
    use lepton_host_adapter::generated::User;
    use valence::Model;

    let (ctx, auth_user) = require_auth_user().await?;
    let valence = ctx
        .unsafe_system_valence()
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let record_id = auth_user.id.to_string();
    let bare = record_id
        .split_once(':')
        .map(|(_, rest)| rest.to_string())
        .unwrap_or(record_id);
    let user = User::get(&bare, &valence, valence::use_!(r"**Test:** Fixture **User** load for `step_up_demo` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .map_err(|e| ServerFnError::new(format!("Failed to load user: {e}")))?
        .ok_or_else(|| ServerFnError::new("User not found"))?;
    let Some(phc) = user.password_hash() else {
        return Err(ServerFnError::Args("Current password is incorrect".into()));
    };
    if verify_token_secret(&current_password, phc).is_err() {
        return Err(ServerFnError::Args("Current password is incorrect".into()));
    }

    let services = lepton_auth::auth_services()?;
    let factors = FactorChallengeService::new(services);
    factors
        .verify_totp_code(&valence, &auth_user.id, &totp_code)
        .await
        .map_err(|e| match e {
            lepton_auth::FactorChallengeError::TotpInvalid => {
                ServerFnError::Args("Authenticator code is incorrect".into())
            }
            lepton_auth::FactorChallengeError::TotpUnavailable => ServerFnError::Args(
                "Set up an authenticator in Account Settings before this action.".into(),
            ),
            other => ServerFnError::new(other.to_string()),
        })?;
    Ok(())
}
