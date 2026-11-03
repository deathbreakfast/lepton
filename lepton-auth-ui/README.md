# lepton-auth-ui

Leptos auth dialogs and embeddable forms composed with Orbital. Depends on
[`lepton-auth`](../lepton-auth/) for `#[server]` actions, paths, and password-policy helpers.

**Source of truth for teaching:** `cargo doc -p lepton-auth-ui --features ssr --open`.

## Features

- **Auth dialog shell** — `AuthDialog` for sign-in / sign-up / log-out
- **Embeddable forms** — `SigninContent`, `SignupContent`, `LogoutContent`
- **Step-up** — `provide_step_up_controller` + `StepUpDialog`
- **OAuth UI** — `OAuthProviderButtons` / callback content (feature-gated)
- **Confirm account** — `ConfirmAccountPrompt`, `ConfirmAccountPage`

## Getting started

Mount `AuthDialog` with `open` / `kind` / `referer` signals, call
`provide_step_up_controller` once, and toggle `open.set(true)`. Full examples live in
crate rustdoc (**Getting started** / Mount `AuthDialog`).

## Feature flags

| Feature | Role |
|---------|------|
| `ssr` | SSR of auth UI (includes `SignupContent`) |
| `hydrate` | Client hydration |
| `oauth-google` | Continue with Google and the “or” divider |
| `oauth-github` | Continue with GitHub and the “or” divider |
| `oauth-microsoft` | Continue with Microsoft and the “or” divider |

Hosts must enable matching `oauth-*` features on both SSR and hydrate graphs.

## Public components

`AuthDialog`, `AuthModalShell`, `SigninContent`, `SignupContent`, `LogoutContent`,
`OAuthProviderButtons`, `OAuthCallbackContent`, `PasswordResetDialog`,
`PasswordResetRequestContent`, `PasswordResetConfirmContent`,
`provide_step_up_controller`, `StepUpDialog`, `StepUpController`, `StepUpPolicy`,
`ConfirmAccountPrompt`, `ConfirmAccountPage`.

Library browser e2e and leptos-lints (`cargo dylint` on hydrate): see workspace
`lepton-auth-ui-e2e` / [`docs/VERIFICATION.md`](../docs/VERIFICATION.md).
