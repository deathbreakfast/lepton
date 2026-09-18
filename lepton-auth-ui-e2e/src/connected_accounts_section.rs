//! E2e harness for Connected accounts (same server fns / testids as product UI).
//!
//! Link CTAs compile in only when this crate enables `oauth-google` / `oauth-github`.

#[cfg(any(feature = "oauth-google", feature = "oauth-github"))]
mod enabled {
    use lepton_auth::actions::oauth_settings::{
        list_linked_identities_ui, unlink_oauth_identity_ui, LinkedIdentityView,
    };
    use lepton_auth::paths::USER_ACCOUNT_SETTINGS;
    #[cfg(feature = "oauth-github")]
    use lepton_auth_ui::GitHubMark;
    #[cfg(feature = "oauth-google")]
    use lepton_auth_ui::GoogleMark;
    use leptos::prelude::*;
    use leptos::task::spawn_local_scoped;
    use orbital_base_components::SkeletonItemSize;
    use orbital_core_components::{Body1, Caption1, Subtitle1};
    use orbital_primitives::{
        Button, ButtonAppearance, ButtonType, Card, CardContent, CardHeader, Flex, FlexAlign,
        FlexGap, FlexWrap, MessageBar, MessageBarIntent, Skeleton, SkeletonItem, Text,
    };

    fn provider_label(provider: &str) -> &'static str {
        match provider {
            "google" => "Google",
            "github" => "GitHub",
            _ => "Unknown",
        }
    }

    /// Connected-accounts section for the auth-ui e2e host (Orbital card layout).
    #[component]
    #[allow(clippy::too_many_lines)] // mirrors product ConnectedAccountsSection layout for e2e
    pub fn E2eConnectedAccountsSection() -> impl IntoView {
        let refresh = RwSignal::new(0u32);
        let links = Resource::new(
            move || refresh.get(),
            |_| async move { list_linked_identities_ui().await },
        );
        let error = RwSignal::new(Option::<String>::None);
        let success = RwSignal::new(Option::<String>::None);
        let unlink_confirm = RwSignal::new(Option::<LinkedIdentityView>::None);
        let busy = RwSignal::new(false);
        let bump_refresh = move || refresh.update(|n| *n = n.wrapping_add(1));

        #[cfg(feature = "oauth-google")]
        let google_link =
            ServerAction::<lepton_auth::actions::oauth_settings::BeginOAuthLink>::new();
        #[cfg(feature = "oauth-github")]
        let github_link =
            ServerAction::<lepton_auth::actions::oauth_settings::BeginOAuthLink>::new();

        view! {
            <Card>
                <CardHeader>
                    <Subtitle1>"Connected accounts"</Subtitle1>
                </CardHeader>
                <CardContent>
                    <div data-testid="connected-accounts-section">
                        <Flex vertical=true gap=FlexGap::Medium>
                            <Caption1>
                                "Link Google or GitHub to sign in with those accounts."
                            </Caption1>

                            <Show when=move || error.get().is_some()>
                                <MessageBar intent=MessageBarIntent::Error>
                                    <div data-testid="connected-accounts-error">
                                        {move || error.get().unwrap_or_default()}
                                    </div>
                                </MessageBar>
                            </Show>
                            <Show when=move || success.get().is_some()>
                                <MessageBar intent=MessageBarIntent::Success>
                                    <div data-testid="connected-accounts-success">
                                        {move || success.get().unwrap_or_default()}
                                    </div>
                                </MessageBar>
                            </Show>
                            <Show when=move || {
                                #[cfg(feature = "oauth-google")]
                                {
                                    if matches!(google_link.value().get(), Some(Err(_))) {
                                        return true;
                                    }
                                }
                                #[cfg(feature = "oauth-github")]
                                {
                                    if matches!(github_link.value().get(), Some(Err(_))) {
                                        return true;
                                    }
                                }
                                false
                            }>
                                <MessageBar intent=MessageBarIntent::Error>
                                    <div data-testid="connected-accounts-error">
                                        {move || {
                                            #[cfg(feature = "oauth-google")]
                                            {
                                                if let Some(e) =
                                                    google_link.value().get().and_then(Result::err)
                                                {
                                                    return e.to_string();
                                                }
                                            }
                                            #[cfg(feature = "oauth-github")]
                                            {
                                                if let Some(e) =
                                                    github_link.value().get().and_then(Result::err)
                                                {
                                                    return e.to_string();
                                                }
                                            }
                                            String::new()
                                        }}
                                    </div>
                                </MessageBar>
                            </Show>

                            <Show when=move || unlink_confirm.get().is_some()>
                                {move || {
                                    let Some(pending) = unlink_confirm.get() else {
                                        return ().into_any();
                                    };
                                    let label = provider_label(&pending.provider);
                                    let id = pending.id.clone();
                                    view! {
                                        <div data-testid="connected-accounts-unlink-confirm">
                                            <Flex vertical=true gap=FlexGap::Small>
                                                <Body1>
                                                    {format!("Unlink {label} from this account?")}
                                                </Body1>
                                                <Caption1>"You can link it again later."</Caption1>
                                                <Flex gap=FlexGap::Small>
                                                    <Button
                                                        appearance=ButtonAppearance::Secondary
                                                        disabled=Signal::derive(move || busy.get())
                                                        on_click=Callback::new(move |_| {
                                                            unlink_confirm.set(None);
                                                        })
                                                    >
                                                        "Keep linked"
                                                    </Button>
                                                    <div data-testid="connected-accounts-unlink">
                                                        <Button
                                                            disabled=Signal::derive(move || busy.get())
                                                            on_click=Callback::new({
                                                                let bump_refresh = bump_refresh;
                                                                move |_| {
                                                                    let linked_id = id.clone();
                                                                    let label = label.to_string();
                                                                    busy.set(true);
                                                                    error.set(None);
                                                                    success.set(None);
                                                                    spawn_local_scoped(async move {
                                                                        match unlink_oauth_identity_ui(linked_id)
                                                                            .await
                                                                        {
                                                                            Ok(()) => {
                                                                                unlink_confirm.set(None);
                                                                                success.set(Some(format!(
                                                                                    "{label} unlinked."
                                                                                )));
                                                                                bump_refresh();
                                                                            }
                                                                            Err(e) => {
                                                                                error.set(Some(e.to_string()));
                                                                                unlink_confirm.set(None);
                                                                            }
                                                                        }
                                                                        busy.set(false);
                                                                    });
                                                                }
                                                            })
                                                        >
                                                            "Unlink"
                                                        </Button>
                                                    </div>
                                                </Flex>
                                            </Flex>
                                        </div>
                                    }
                                    .into_any()
                                }}
                            </Show>

                            <Suspense fallback=move || view! {
                                <Skeleton>
                                    <SkeletonItem size=Signal::from(SkeletonItemSize::S48) />
                                </Skeleton>
                            }>
                                {move || match links.get() {
                                    Some(Ok(list)) => {
                                        #[cfg(feature = "oauth-google")]
                                        let has_google = list.iter().any(|l| l.provider == "google");
                                        #[cfg(feature = "oauth-github")]
                                        let has_github = list.iter().any(|l| l.provider == "github");
                                        view! {
                                            <Flex vertical=true gap=FlexGap::Small>
                                                <Show when=move || unlink_confirm.get().is_none()>
                                                    {if list.is_empty() {
                                                        view! {
                                                            <div data-testid="connected-accounts-empty">
                                                                <Body1>"No connected accounts yet."</Body1>
                                                            </div>
                                                        }
                                                        .into_any()
                                                    } else {
                                                        let rows = list.clone();
                                                        view! {
                                                            <div data-testid="connected-accounts-list">
                                                                <Flex vertical=true gap=FlexGap::Small>
                                                                    {rows
                                                                        .into_iter()
                                                                        .map(|row| {
                                                                            let label =
                                                                                provider_label(&row.provider);
                                                                            let hint = row.email_hint.clone();
                                                                            let row_for_confirm = row.clone();
                                                                            view! {
                                                                                <div data-testid="connected-accounts-row">
                                                                                    <Flex
                                                                                        align=FlexAlign::Center
                                                                                        gap=FlexGap::Small
                                                                                        wrap=FlexWrap::Wrap
                                                                                    >
                                                                                        <Body1>
                                                                                            {label}
                                                                                            {hint
                                                                                                .map_or_else(String::new, |h| format!(" · {h}"))}
                                                                                        </Body1>
                                                                                        <Button
                                                                                            appearance=ButtonAppearance::Secondary
                                                                                            disabled=Signal::derive(move || {
                                                                                                busy.get()
                                                                                            })
                                                                                            on_click=Callback::new(move |_| {
                                                                                                error.set(None);
                                                                                                success.set(None);
                                                                                                unlink_confirm.set(Some(
                                                                                                    row_for_confirm.clone(),
                                                                                                ));
                                                                                            })
                                                                                        >
                                                                                            "Unlink"
                                                                                        </Button>
                                                                                    </Flex>
                                                                                </div>
                                                                            }
                                                                        })
                                                                        .collect_view()}
                                                                </Flex>
                                                            </div>
                                                        }
                                                        .into_any()
                                                    }}
                                                </Show>
                                                <Show when=move || unlink_confirm.get().is_none()>
                                                    <Flex vertical=true gap=FlexGap::Small>
                                                        {
                                                            #[cfg(feature = "oauth-google")]
                                                            {
                                                                view! {
                                                                    <Show when=move || !has_google>
                                                                        <ActionForm action=google_link>
                                                                            <input type="hidden" name="provider" value="google" />
                                                                            <input
                                                                                type="hidden"
                                                                                name="referer"
                                                                                value=USER_ACCOUNT_SETTINGS
                                                                            />
                                                                            <div data-testid="connected-accounts-link-google">
                                                                                <Button
                                                                                    button_type=ButtonType::Submit
                                                                                    appearance=ButtonAppearance::Secondary
                                                                                    disabled=Signal::derive(move || {
                                                                                        busy.get()
                                                                                            || google_link.pending().get()
                                                                                            || {
                                                                                                #[cfg(feature = "oauth-github")]
                                                                                                {
                                                                                                    github_link.pending().get()
                                                                                                }
                                                                                                #[cfg(not(feature = "oauth-github"))]
                                                                                                {
                                                                                                    false
                                                                                                }
                                                                                            }
                                                                                    })
                                                                                >
                                                                                    <Flex gap=FlexGap::Small>
                                                                                        <GoogleMark />
                                                                                        <Text>"Link Google"</Text>
                                                                                    </Flex>
                                                                                </Button>
                                                                            </div>
                                                                        </ActionForm>
                                                                    </Show>
                                                                }
                                                                .into_any()
                                                            }
                                                            #[cfg(not(feature = "oauth-google"))]
                                                            {
                                                                ().into_any()
                                                            }
                                                        }
                                                        {
                                                            #[cfg(feature = "oauth-github")]
                                                            {
                                                                view! {
                                                                    <Show when=move || !has_github>
                                                                        <ActionForm action=github_link>
                                                                            <input type="hidden" name="provider" value="github" />
                                                                            <input
                                                                                type="hidden"
                                                                                name="referer"
                                                                                value=USER_ACCOUNT_SETTINGS
                                                                            />
                                                                            <div data-testid="connected-accounts-link-github">
                                                                                <Button
                                                                                    button_type=ButtonType::Submit
                                                                                    appearance=ButtonAppearance::Secondary
                                                                                    disabled=Signal::derive(move || {
                                                                                        busy.get()
                                                                                            || github_link.pending().get()
                                                                                            || {
                                                                                                #[cfg(feature = "oauth-google")]
                                                                                                {
                                                                                                    google_link.pending().get()
                                                                                                }
                                                                                                #[cfg(not(feature = "oauth-google"))]
                                                                                                {
                                                                                                    false
                                                                                                }
                                                                                            }
                                                                                    })
                                                                                >
                                                                                    <Flex gap=FlexGap::Small>
                                                                                        <GitHubMark />
                                                                                        <Text>"Link GitHub"</Text>
                                                                                    </Flex>
                                                                                </Button>
                                                                            </div>
                                                                        </ActionForm>
                                                                    </Show>
                                                                }
                                                                .into_any()
                                                            }
                                                            #[cfg(not(feature = "oauth-github"))]
                                                            {
                                                                ().into_any()
                                                            }
                                                        }
                                                    </Flex>
                                                </Show>
                                            </Flex>
                                        }
                                        .into_any()
                                    }
                                    Some(Err(err)) => view! {
                                        <MessageBar intent=MessageBarIntent::Error>
                                            <div data-testid="connected-accounts-error">
                                                {err.to_string()}
                                            </div>
                                        </MessageBar>
                                    }
                                    .into_any(),
                                    None => ().into_any(),
                                }}
                            </Suspense>
                        </Flex>
                    </div>
                </CardContent>
            </Card>
        }
    }
}

#[cfg(any(feature = "oauth-google", feature = "oauth-github"))]
pub use enabled::E2eConnectedAccountsSection;

#[cfg(not(any(feature = "oauth-google", feature = "oauth-github")))]
use leptos::prelude::*;

/// Connected-accounts section stub when OAuth UI features are off.
#[cfg(not(any(feature = "oauth-google", feature = "oauth-github")))]
#[component]
#[allow(clippy::unused_unit)] // empty stub when OAuth UI features are off
pub fn E2eConnectedAccountsSection() -> impl IntoView {}
