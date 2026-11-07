//! Admin list of every service user with its owner and a handle filter.

use lepton_auth::actions::service_users::{
    filter_by_handle, list_all_service_users_admin, ServiceUserAdminView,
};
use leptos::prelude::*;
use orbital_core_components::{
    Body1, Caption1, Card, CardContent, CardHeader, Field, Flex, FlexAlign, FlexGap, FlexWrap,
    Input, InputAppearance, InputBind, MessageBar, MessageBarIntent, Subtitle1,
};

/// Lists every service user, whoever owns it, for callers the host's service user gate
/// grants manage-any. Everyone else sees the server's refusal in an error bar.
///
/// The handle filter narrows the loaded list in the browser, ignoring case and dashes.
/// Mount it at `/user/bots/all`.
#[component]
pub fn AllServiceUsersPage() -> impl IntoView {
    let rows = Resource::new(|| (), |()| list_all_service_users_admin());
    let filter = RwSignal::new(String::new());

    view! {
        <Card>
            <CardHeader>
                <Subtitle1>"All service users"</Subtitle1>
            </CardHeader>
            <CardContent>
                <div data-testid="all-service-users-page">
                    <Flex vertical=true gap=FlexGap::Medium>
                        <Field label="Filter by handle">
                            <div data-testid="all-service-users-filter">
                                <Input
                                    bind=InputBind::new(filter)
                                    appearance=InputAppearance::with_placeholder("spectra-agent")
                                />
                            </div>
                        </Field>
                        <Suspense fallback=|| view! {
                            <div data-testid="all-service-users-loading">
                                <Body1>"Loading service users…"</Body1>
                            </div>
                        }>
                            {move || match rows.get() {
                                None => ().into_any(),
                                Some(Err(e)) => view! {
                                    <MessageBar intent=MessageBarIntent::Error>
                                        <div data-testid="all-service-users-error">
                                            {e.to_string()}
                                        </div>
                                    </MessageBar>
                                }
                                .into_any(),
                                Some(Ok(all)) => {
                                    let shown = filter_by_handle(&all, &filter.get());
                                    render_rows(shown)
                                }
                            }}
                        </Suspense>
                    </Flex>
                </div>
            </CardContent>
        </Card>
    }
}

fn render_rows(rows: Vec<ServiceUserAdminView>) -> AnyView {
    if rows.is_empty() {
        return view! {
            <div data-testid="all-service-users-empty">
                <Body1>"No service users match."</Body1>
            </div>
        }
        .into_any();
    }
    view! {
        <div data-testid="all-service-users-list">
            <Flex vertical=true gap=FlexGap::Small>
                {rows
                    .into_iter()
                    .map(|row| {
                        let ServiceUserAdminView { handle, display_name, status, owner_id, .. } = row;
                        let owner = if owner_id.is_empty() {
                            "no owner".to_string()
                        } else {
                            owner_id
                        };
                        view! {
                            <div data-testid="all-service-users-row">
                                <Flex align=FlexAlign::Center gap=FlexGap::Small wrap=FlexWrap::Wrap>
                                    <span data-testid="all-service-users-handle">
                                        <Body1>{handle}</Body1>
                                    </span>
                                    <Caption1>{display_name}</Caption1>
                                    <Caption1>{status}</Caption1>
                                    <span data-testid="all-service-users-owner">
                                        <Caption1>"Owner: " {owner}</Caption1>
                                    </span>
                                </Flex>
                            </div>
                        }
                    })
                    .collect_view()}
            </Flex>
        </div>
    }
    .into_any()
}
