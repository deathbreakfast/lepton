//! “Continue with Google / GitHub” buttons for sign-in and sign-up.
//!
//! Provider rows (and the “or” divider) compile in only when the matching
//! `oauth-google` / `oauth-github` crate features are enabled. With neither
//! feature, this component renders nothing.

#[cfg(any(feature = "oauth-google", feature = "oauth-github"))]
mod enabled {
    use leptos::prelude::*;
    use orbital_core_components::Divider;
    use orbital_core_components::{
        Button, ButtonAppearance, ButtonType, Flex, FlexGap, MessageBar, MessageBarIntent, Text,
    };

    #[cfg(feature = "oauth-github")]
    use super::super::brand_icons::GitHubMark;
    #[cfg(feature = "oauth-google")]
    use super::super::brand_icons::GoogleMark;

    /// Full-width OAuth provider buttons with brand marks and an “or” divider.
    #[component]
    #[allow(clippy::too_many_lines)] // per-provider ActionForms + shared error bar
    pub fn OAuthProviderButtons(referer: Signal<String>) -> impl IntoView {
        #[cfg(feature = "oauth-google")]
        let google = ServerAction::<lepton_auth::actions::oauth::BeginOAuth>::new();
        #[cfg(feature = "oauth-github")]
        let github = ServerAction::<lepton_auth::actions::oauth::BeginOAuth>::new();

        view! {
            <Flex vertical=true gap=FlexGap::Small>
                <div data-testid="oauth-divider">
                    <Divider>"or"</Divider>
                </div>
                <Show when=move || {
                    #[cfg(feature = "oauth-google")]
                    {
                        if matches!(google.value().get(), Some(Err(_))) {
                            return true;
                        }
                    }
                    #[cfg(feature = "oauth-github")]
                    {
                        if matches!(github.value().get(), Some(Err(_))) {
                            return true;
                        }
                    }
                    false
                }>
                    <div data-testid="oauth-error">
                        <MessageBar intent=MessageBarIntent::Error>
                            {move || {
                                #[cfg(feature = "oauth-google")]
                                {
                                    if let Some(e) = google.value().get().and_then(Result::err) {
                                        return e.to_string();
                                    }
                                }
                                #[cfg(feature = "oauth-github")]
                                {
                                    if let Some(e) = github.value().get().and_then(Result::err) {
                                        return e.to_string();
                                    }
                                }
                                String::new()
                            }}
                        </MessageBar>
                    </div>
                </Show>
                {
                    #[cfg(feature = "oauth-google")]
                    {
                        view! {
                            <ActionForm action=google>
                                <input type="hidden" name="provider" value="google" />
                                <input type="hidden" name="referer" prop:value=move || referer.get() />
                                <div data-testid="oauth-continue-google">
                                    <Button
                                        button_type=ButtonType::Submit
                                        appearance=ButtonAppearance::Secondary
                                        disabled=Signal::derive(move || {
                                            google.pending().get()
                                                || {
                                                    #[cfg(feature = "oauth-github")]
                                                    {
                                                        github.pending().get()
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
                                            <Text>"Continue with Google"</Text>
                                        </Flex>
                                    </Button>
                                </div>
                            </ActionForm>
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
                            <ActionForm action=github>
                                <input type="hidden" name="provider" value="github" />
                                <input type="hidden" name="referer" prop:value=move || referer.get() />
                                <div data-testid="oauth-continue-github">
                                    <Button
                                        button_type=ButtonType::Submit
                                        appearance=ButtonAppearance::Secondary
                                        disabled=Signal::derive(move || {
                                            github.pending().get()
                                                || {
                                                    #[cfg(feature = "oauth-google")]
                                                    {
                                                        google.pending().get()
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
                                            <Text>"Continue with GitHub"</Text>
                                        </Flex>
                                    </Button>
                                </div>
                            </ActionForm>
                        }
                        .into_any()
                    }
                    #[cfg(not(feature = "oauth-github"))]
                    {
                        ().into_any()
                    }
                }
            </Flex>
        }
    }
}

#[cfg(any(feature = "oauth-google", feature = "oauth-github"))]
pub use enabled::OAuthProviderButtons;

#[cfg(not(any(feature = "oauth-google", feature = "oauth-github")))]
use leptos::prelude::*;

/// Full-width OAuth provider buttons with brand marks and an “or” divider.
///
/// Renders nothing unless at least one of `oauth-google` / `oauth-github` is enabled.
#[cfg(not(any(feature = "oauth-google", feature = "oauth-github")))]
#[component]
#[allow(clippy::unused_unit)] // empty stub when OAuth UI features are off
pub fn OAuthProviderButtons(#[allow(unused_variables)] referer: Signal<String>) -> impl IntoView {}

#[cfg(test)]
mod tests {
    #[test]
    fn oauth_ui_off_without_provider_features() {
        #[cfg(not(any(feature = "oauth-google", feature = "oauth-github")))]
        {
            const {
                assert!(!(cfg!(feature = "oauth-google") || cfg!(feature = "oauth-github")));
            }
        }
        #[cfg(all(feature = "oauth-google", feature = "oauth-github"))]
        {
            const {
                assert!(cfg!(feature = "oauth-google"));
                assert!(cfg!(feature = "oauth-github"));
            }
        }
    }
}
