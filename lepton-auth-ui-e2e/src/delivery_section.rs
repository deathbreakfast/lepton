//! Lab "Sign-in and delivery" page.
//!
//! Email and text-message settings take effect on the next send, with no restart.
//! The server functions sit on [`crate::delivery_lab::LabDelivery`].

use leptos::prelude::*;
use leptos::task::spawn_local_scoped;
use orbital_core_components::{Body1, Caption1, Subtitle1};
use orbital_primitives::{
    Button, Card, CardContent, CardHeader, Field, Flex, FlexGap, Input, InputAppearance, InputBind,
    InputType, MessageBar, MessageBarIntent,
};

#[cfg(feature = "ssr")]
async fn lab_valence() -> Result<valence::Valence, ServerFnError> {
    let (ctx, _user) = lepton_auth::require_auth_user().await?;
    lepton_auth::user_valence(&ctx)
}

/// Current drivers and settings revision, or the denial for a user without access.
#[server(LabDeliverySummary)]
pub async fn lab_delivery_summary() -> Result<String, ServerFnError> {
    let v = lab_valence().await?;
    crate::delivery_lab::lab()
        .and_then(|lab| lab.summary_for(&v))
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Save email settings. `password` and `sendgrid_key` are write-only; blank keeps the
/// stored value.
#[server(LabDeliverySaveEmail)]
pub async fn lab_delivery_save_email(
    driver: String,
    host: String,
    port: String,
    from_email: String,
    password: String,
    sendgrid_key: String,
) -> Result<String, ServerFnError> {
    use lepton_auth::delivery_settings::{
        DeliverySettingsBackend, EmailCandidate, WriteOnlySecret,
    };
    let v = lab_valence().await?;
    let secret = |s: String| (!s.trim().is_empty()).then(|| WriteOnlySecret::new(s));
    let fail = |e: lepton_auth::delivery_settings::DeliveryError| ServerFnError::new(e.to_string());
    let lab = crate::delivery_lab::lab().map_err(fail)?;
    let smtp_port = port.trim().parse::<u16>().map_err(|_| {
        fail(lepton_auth::delivery_settings::DeliveryError::Invalid {
            field: "smtp_port",
            reason: "must be between 1 and 65535",
        })
    })?;
    let candidate = EmailCandidate {
        driver: crate::delivery_lab::parse_driver(&driver).map_err(fail)?,
        smtp_host: host,
        smtp_port,
        smtp_tls: false,
        from_email,
        test_recipient: "lab@example.test".into(),
        smtp_password: secret(password),
        sendgrid_api_key: secret(sendgrid_key),
        ..EmailCandidate::default()
    };
    lab.save_email(&v, candidate).await.map_err(fail)?;
    lab.summary_for(&v).map_err(fail)
}

/// Save text-message settings. `api_secret` is write-only; blank keeps the stored value.
#[server(LabDeliverySaveSms)]
pub async fn lab_delivery_save_sms(
    mode: String,
    account_sid: String,
    api_key_sid: String,
    verify_sid: String,
    api_secret: String,
) -> Result<String, ServerFnError> {
    use lepton_auth::delivery_settings::{DeliverySettingsBackend, SmsCandidate, WriteOnlySecret};
    let v = lab_valence().await?;
    let fail = |e: lepton_auth::delivery_settings::DeliveryError| ServerFnError::new(e.to_string());
    let lab = crate::delivery_lab::lab().map_err(fail)?;
    let candidate = SmsCandidate {
        mode: crate::delivery_lab::parse_mode(&mode).map_err(fail)?,
        twilio_account_sid: account_sid,
        twilio_api_key_sid: api_key_sid,
        twilio_verify_service_sid: verify_sid,
        test_recipient: "+15550100".into(),
        twilio_api_secret: (!api_secret.trim().is_empty())
            .then(|| WriteOnlySecret::new(api_secret)),
        ..SmsCandidate::default()
    };
    lab.save_sms(&v, candidate).await.map_err(fail)?;
    lab.summary_for(&v).map_err(fail)
}

#[component]
fn LabField(
    label: &'static str,
    testid: &'static str,
    value: RwSignal<String>,
    #[prop(optional)] secret: bool,
) -> impl IntoView {
    let input_type = if secret {
        InputType::Password
    } else {
        InputType::Text
    };
    view! {
        <Field label=label>
            <div data-testid=testid>
                <Input
                    bind=InputBind::new(value)
                    appearance=InputAppearance { input_type: Signal::from(input_type), ..Default::default() }
                />
            </div>
        </Field>
    }
}

/// Email and text-message cards plus a status line.
#[component]
#[allow(clippy::too_many_lines)] // two forms and a status line
pub fn E2eDeliverySection() -> impl IntoView {
    let saved_ok = RwSignal::new(Option::<String>::None);
    let save_err = RwSignal::new(Option::<String>::None);
    let driver = RwSignal::new("smtp".to_string());
    let host = RwSignal::new("127.0.0.1".to_string());
    let port = RwSignal::new("1025".to_string());
    let from = RwSignal::new("noreply@example.test".to_string());
    let password = RwSignal::new(String::new());
    let sendgrid = RwSignal::new(String::new());
    let mode = RwSignal::new("verify".to_string());
    let account = RwSignal::new("ACtest".to_string());
    let key_sid = RwSignal::new("SKtest".to_string());
    let verify = RwSignal::new("VAtest".to_string());
    let secret = RwSignal::new(String::new());

    let summary = Resource::new(|| (), |()| async { lab_delivery_summary().await });
    // A save's outcome wins over the first load; a failed save keeps the last good summary.
    let result = move || {
        saved_ok.get().or_else(|| match summary.get() {
            Some(Ok(s)) => Some(s),
            _ => None,
        })
    };
    let error = move || {
        save_err.get().or_else(|| match summary.get() {
            Some(Err(e)) => Some(e.to_string()),
            _ => None,
        })
    };
    let outcome = move |r: Result<String, ServerFnError>| match r {
        Ok(s) => {
            save_err.set(None);
            saved_ok.set(Some(s));
        }
        Err(e) => save_err.set(Some(e.to_string())),
    };

    view! {
        <Flex vertical=true gap=FlexGap::Medium>
            <Show when=move || error().is_some()>
                <div data-testid="delivery-error">
                    <MessageBar intent=MessageBarIntent::Error>
                        {move || error().unwrap_or_default()}
                    </MessageBar>
                </div>
            </Show>
            <div data-testid="delivery-summary"><Body1>{move || result().unwrap_or_default()}</Body1></div>
            <Card>
                <CardHeader><Subtitle1>"Email"</Subtitle1></CardHeader>
                <CardContent>
                    <Caption1>"driver: off, smtp, sendgrid"</Caption1>
                    <LabField label="Driver" testid="delivery-email-driver" value=driver/>
                    <LabField label="SMTP host" testid="delivery-email-host" value=host/>
                    <LabField label="SMTP port" testid="delivery-email-port" value=port/>
                    <LabField label="From" testid="delivery-email-from" value=from/>
                    <LabField label="SMTP password" testid="delivery-email-password" value=password secret=true/>
                    <LabField label="SendGrid key" testid="delivery-email-sendgrid" value=sendgrid secret=true/>
                    <div data-testid="delivery-email-save">
                        <Button on_click=Callback::new(move |_| {
                            let args = (
                                driver.get_untracked(),
                                host.get_untracked(),
                                port.get_untracked(),
                                from.get_untracked(),
                                password.get_untracked(),
                                sendgrid.get_untracked(),
                            );
                            spawn_local_scoped(async move {
                                outcome(
                                    lab_delivery_save_email(args.0, args.1, args.2, args.3, args.4, args.5)
                                        .await,
                                );
                                password.set(String::new());
                                sendgrid.set(String::new());
                            });
                        })>"Save email"</Button>
                    </div>
                </CardContent>
            </Card>
            <Card>
                <CardHeader><Subtitle1>"Text messages"</Subtitle1></CardHeader>
                <CardContent>
                    <Caption1>"mode: off, verify, messages"</Caption1>
                    <LabField label="Mode" testid="delivery-sms-mode" value=mode/>
                    <LabField label="Account SID" testid="delivery-sms-account" value=account/>
                    <LabField label="API key SID" testid="delivery-sms-key-sid" value=key_sid/>
                    <LabField label="Verify service SID" testid="delivery-sms-verify" value=verify/>
                    <LabField label="API secret" testid="delivery-sms-secret" value=secret secret=true/>
                    <div data-testid="delivery-sms-save">
                        <Button on_click=Callback::new(move |_| {
                            let args = (
                                mode.get_untracked(),
                                account.get_untracked(),
                                key_sid.get_untracked(),
                                verify.get_untracked(),
                                secret.get_untracked(),
                            );
                            spawn_local_scoped(async move {
                                outcome(
                                    lab_delivery_save_sms(args.0, args.1, args.2, args.3, args.4).await,
                                );
                                secret.set(String::new());
                            });
                        })>"Save text messages"</Button>
                    </div>
                </CardContent>
            </Card>
        </Flex>
    }
}
