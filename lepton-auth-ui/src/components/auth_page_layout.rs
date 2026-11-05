use leptos::prelude::*;
use orbital_core_components::{Flex, FlexGap, Title3};

/// Shared body for dedicated `/auth/*` pages: a page title above a vertical stack.
///
/// The host supplies the surrounding app shell. Pass `test_id` to put a
/// `data-testid` on the wrapper.
#[component]
pub fn AuthPageLayout(
    #[prop(into)] title: Signal<String>,
    #[prop(optional)] test_id: Option<&'static str>,
    children: Children,
) -> impl IntoView {
    view! {
        <div data-testid=test_id>
            <Flex vertical=true gap=FlexGap::Large>
                <Title3>{move || title.get()}</Title3>
                {children()}
            </Flex>
        </div>
    }
}
