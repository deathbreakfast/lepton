//! OAuth callback content: completes the provider handoff and establishes a session.

use leptos::prelude::*;
use orbital_core_components::{Flex, FlexGap, MessageBar, MessageBarIntent, Text};

/// Runs [`CompleteOAuthCallback`] once when `code` / `state` / `provider` are present.
#[component]
pub fn OAuthCallbackContent(
    provider: Signal<String>,
    code: Signal<String>,
    state: Signal<String>,
    referer: Signal<String>,
) -> impl IntoView {
    let action = ServerAction::<lepton_auth::actions::oauth::CompleteOAuthCallback>::new();
    // Last `code`+`state` key dispatched (SPA may reuse this route without remount).
    let dispatched_key = RwSignal::new(String::new());

    Effect::new(move |_| {
        let provider = provider.get();
        let code = code.get();
        let state = state.get();
        // Provider may be empty: real IdP callbacks and the mock IdP only return
        // `code` + `state`; `CompleteOAuthCallback` peeks the provider from CSRF state.
        if code.is_empty() || state.is_empty() {
            return;
        }
        let key = format!("{code}\0{state}");
        if dispatched_key.get_untracked() == key {
            return;
        }
        dispatched_key.set(key);
        action.dispatch(lepton_auth::actions::oauth::CompleteOAuthCallback {
            provider,
            code,
            state,
            referer: {
                let r = referer.get();
                if r.is_empty() {
                    None
                } else {
                    Some(r)
                }
            },
        });
    });

    view! {
        <Flex vertical=true gap=FlexGap::Medium>
            <div data-testid="oauth-callback-pending">
                <Text>"Finishing sign-in…"</Text>
            </div>
            <Show when=move || matches!(action.value().get(), Some(Err(_)))>
                <div data-testid="oauth-callback-error">
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
        </Flex>
    }
}
