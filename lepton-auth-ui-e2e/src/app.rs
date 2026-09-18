//! Routes that mount `lepton-auth-ui` components for Playwright.

use lepton_auth::paths::{LOGOUT, SIGNIN, SIGNUP};
use lepton_auth::routes::parse_token_from_url_parts;
use lepton_auth_ui::{
    provide_step_up_controller, use_step_up_controller, AuthDialog, AuthDialogCallbacks,
    AuthDialogKind, AuthModalShell, ConfirmAccountPage, ConfirmAccountPrompt,
    ConfirmAccountPromptVariant, OAuthCallbackContent, PasswordResetDialog,
    PasswordResetDialogKind,
};
use leptos::prelude::*;
use leptos_meta::{provide_meta_context, MetaTags, Stylesheet, Title};
use leptos_router::components::{Route, Router, Routes};
use leptos_router::hooks::{use_location, use_navigate};
use leptos_router::path;
use leptos_router::NavigateOptions;
use orbital_core_components::{Body1, Caption1};
use orbital_primitives::{Flex, FlexAlign, FlexGap, FlexWrap, Link, Title3};
use orbital_theme::OrbitalThemeProvider;

use crate::connected_accounts_section::E2eConnectedAccountsSection;
use crate::devices_section::E2eDevicesSection;
use crate::page_shell::E2ePageShell;
use crate::step_up_demo::E2eStepUpDemo;
use crate::totp_section::E2eTotpSection;
use crate::wipe_section::E2eWipeSection;

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    let _step_up = provide_step_up_controller();
    view! {
        <OrbitalThemeProvider>
            <Stylesheet id="leptos" href="/pkg/lepton-auth-ui-e2e.css"/>
            <Title text="lepton-auth-ui e2e"/>
            <Router>
                <Routes fallback=|| view! {
                    <E2ePageShell>
                        <Title3>"Not found"</Title3>
                        <Body1>"That route is not part of this Playwright host."</Body1>
                        <Link href="/">"Back home"</Link>
                    </E2ePageShell>
                }>
                    <Route path=path!("/") view=HomePage/>
                    <Route path=path!("/welcome") view=WelcomePage/>
                    <Route path=path!("/auth/signin") view=SigninPage/>
                    <Route path=path!("/auth/signup") view=SignupPage/>
                    <Route path=path!("/auth/logout") view=LogoutPage/>
                    <Route path=path!("/auth/oauth/callback") view=OAuthCallbackPage/>
                    <Route path=path!("/auth/reset/request") view=ResetRequestPage/>
                    <Route path=path!("/auth/reset/confirm") view=ResetConfirmPage/>
                    <Route path=path!("/user/account-settings") view=AccountSettingsPage/>
                    <Route path=path!("/user/confirm-account") view=ConfirmAccountRoute/>
                    <Route path=path!("/user/step-up-demo") view=StepUpDemoPage/>
                </Routes>
            </Router>
        </OrbitalThemeProvider>
    }
}

#[component]
fn StepUpDemoPage() -> impl IntoView {
    #[allow(clippy::expect_used)] // e2e App always calls provide_step_up_controller
    let controller = use_step_up_controller().expect("provide_step_up_controller in App");
    view! { <E2eStepUpDemo controller=controller /> }
}

/// HTML shell for SSR.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <AutoReload options=options.clone()/>
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    view! {
        <E2ePageShell data_testid="home-root">
            <Title3>"lepton-auth-ui e2e"</Title3>
            <Caption1>
                "Playwright host for auth dialogs and account-settings fixtures."
            </Caption1>
            <Flex gap=FlexGap::Medium align=FlexAlign::Center wrap=FlexWrap::Wrap>
                <Link href=SIGNIN>"Sign in"</Link>
                <Link href=SIGNUP>"Sign up"</Link>
            </Flex>
        </E2ePageShell>
    }
}

#[component]
fn WelcomePage() -> impl IntoView {
    view! {
        <E2ePageShell data_testid="welcome-root">
            <Title3>"Welcome"</Title3>
            <ConfirmAccountPrompt variant=ConfirmAccountPromptVariant::Compact />
            <div data-testid="welcome-authenticated">
                <Body1>"Signed in"</Body1>
            </div>
            <Link href=LOGOUT>"Log out"</Link>
        </E2ePageShell>
    }
}

#[component]
fn ConfirmAccountRoute() -> impl IntoView {
    view! {
        <E2ePageShell>
            <ConfirmAccountPage/>
        </E2ePageShell>
    }
}

#[component]
fn AccountSettingsPage() -> impl IntoView {
    view! {
        <E2ePageShell data_testid="account-settings-container">
            <Title3>"Account settings"</Title3>
            <ConfirmAccountPrompt variant=ConfirmAccountPromptVariant::Compact />
            <ConfirmAccountPrompt />
            <div data-testid="account-settings-note">
                <Caption1>"Post-signup / unverified landing"</Caption1>
            </div>
            <E2eTotpSection/>
            <E2eConnectedAccountsSection/>
            <E2eDevicesSection/>
            <E2eWipeSection/>
            <div data-testid="user-menu-logout">
                <Link href=LOGOUT>"Log out"</Link>
            </div>
        </E2ePageShell>
    }
}

#[component]
fn SigninPage() -> impl IntoView {
    view! { <AuthRouteHost initial_kind=AuthDialogKind::Signin test_id="signin-container"/> }
}

#[component]
fn SignupPage() -> impl IntoView {
    view! { <AuthRouteHost initial_kind=AuthDialogKind::Signup test_id="signup-container"/> }
}

#[component]
fn LogoutPage() -> impl IntoView {
    view! { <AuthRouteHost initial_kind=AuthDialogKind::Logout test_id="logout-container"/> }
}

#[component]
fn AuthRouteHost(initial_kind: AuthDialogKind, test_id: &'static str) -> impl IntoView {
    let navigate = use_navigate();
    let location = use_location();
    let referer = Memo::new(move |_| {
        let search = location.search.get();
        lepton_auth::routes::sanitize_referer_path(lepton_auth::routes::parse_referer_from_search(
            &search,
        ))
    });
    let open = RwSignal::new(true);
    let kind = RwSignal::new(initial_kind);
    // Sign-in content navigates to `redirect_to` (may be confirm-account); do not
    // overwrite that with the query referer when the dialog closes after success.
    let auth_finished = RwSignal::new(false);

    Effect::new(move |was_open: Option<bool>| {
        let is_open = open.get();
        if was_open == Some(true) && !is_open && !auth_finished.get() {
            navigate(&referer.get(), NavigateOptions::default());
        }
        is_open
    });

    view! {
        <E2ePageShell data_testid=test_id>
            <div data-testid="auth-page-shell-root">
                <Title3>{move || match kind.get() {
                    AuthDialogKind::Signin => "Sign in",
                    AuthDialogKind::Signup => "Sign up",
                    AuthDialogKind::Logout => "Sign out",
                }}</Title3>
                <AuthDialog
                    open=open.into()
                    kind=kind.into()
                    referer=referer.into()
                    callbacks=AuthDialogCallbacks {
                        on_close: Some(Callback::new(move |()| open.set(false))),
                        on_success: Some(Callback::new(move |()| {
                            auth_finished.set(true);
                            open.set(false);
                        })),
                        // Leave switch callbacks unset so content uses `<Link href=…>`
                        // for signin↔signup URL navigation (Playwright nav scenario).
                        ..Default::default()
                    }
                />
            </div>
        </E2ePageShell>
    }
}

#[component]
fn ResetRequestPage() -> impl IntoView {
    let open = RwSignal::new(true);
    let empty = Signal::derive(String::new);
    view! {
        <E2ePageShell data_testid="password-reset-request-container">
            <Title3>"Reset password"</Title3>
            <PasswordResetDialog
                open=open.into()
                kind=Signal::derive(|| PasswordResetDialogKind::Request)
                token_from_query=empty
            />
        </E2ePageShell>
    }
}

#[component]
fn ResetConfirmPage() -> impl IntoView {
    let open = RwSignal::new(true);
    let location = use_location();
    let token = Memo::new(move |_| {
        let search = location.search.get();
        let hash = location.hash.get();
        parse_token_from_url_parts(&search, &hash).unwrap_or_default()
    });

    view! {
        <E2ePageShell data_testid="password-reset-confirm-container">
            <Title3>"Choose a new password"</Title3>
            <PasswordResetDialog
                open=open.into()
                kind=Signal::derive(|| PasswordResetDialogKind::Confirm)
                token_from_query=Signal::derive(move || token.get())
            />
        </E2ePageShell>
    }
}

fn query_param(search: &str, key: &str) -> String {
    let trimmed = search.trim_start_matches('?');
    url::form_urlencoded::parse(trimmed.as_bytes())
        .find(|(k, _)| k == key)
        .map_or_else(String::new, |(_, v)| v.into_owned())
}

#[component]
fn OAuthCallbackPage() -> impl IntoView {
    let location = use_location();
    let open = RwSignal::new(true);
    let title = Signal::derive(|| "Sign in".to_string());
    let provider = Memo::new(move |_| query_param(&location.search.get(), "provider"));
    let code = Memo::new(move |_| query_param(&location.search.get(), "code"));
    let state = Memo::new(move |_| query_param(&location.search.get(), "state"));
    let referer = Memo::new(move |_| {
        lepton_auth::routes::sanitize_referer_path(lepton_auth::routes::parse_referer_from_search(
            &location.search.get(),
        ))
    });

    view! {
        <E2ePageShell data_testid="oauth-callback-container">
            <AuthModalShell open=open.into() title=title>
                <OAuthCallbackContent
                    provider=provider.into()
                    code=code.into()
                    state=state.into()
                    referer=referer.into()
                />
            </AuthModalShell>
        </E2ePageShell>
    }
}
