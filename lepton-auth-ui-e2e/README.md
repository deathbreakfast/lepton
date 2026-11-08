# lepton-auth-ui-e2e

Library-owned Leptos host + Playwright for [`lepton-auth-ui`](../lepton-auth-ui/).

Uses tolerant **in-memory** Valence (SQLite cannot run Surreal-shaped unique probes).
Higgs SSR factory allows internal System minting for signup / password-reset
(same pattern as embedded `ProcessValenceFactory::as_higgs_factory`).

Playwright hits `http://localhost:3120` (WebAuthn RP id `localhost`) while the
process binds `127.0.0.1:3120` (avoids clashing with product hosts on `:3000`).
On boot the host starts lab sidecars (or reuses them if already listening):

| Sidecar | Bind | Role |
|---------|------|------|
| Mock OIDC | `127.0.0.1:5556` | OAuth IdP |
| SMS HTTP sink | `127.0.0.1:8099` | Capture SMS OTP (`HttpCaptureSmsAdapter`) |

Confirm-funnel specs also need **Mailpit** (SMTP `1025`, API `8025`):

```bash
docker compose -f infra/mailpit/docker-compose.yml up -d
```

Specs: `auth.spec.ts`, `confirm_account.spec.ts`, `oauth.spec.ts`,
`oauth_link_settings.spec.ts` (Account Settings Connected accounts link / unlink),
`devices.spec.ts` (Account Settings Security devices + Chromium virtual authenticator),
`totp_enroll.spec.ts` (Authenticator enroll via DOM secret + `otplib`, no TOTP sidecar),
`signin_mfa.spec.ts`, `account_wipe.spec.ts`,
`step_up_modal.spec.ts` (per-op re-auth modal on `/user/step-up-demo`),
`delivery_settings.spec.ts` (`/lab/delivery`: email and text-message settings saved on a
page take effect on the next send with no restart; a user without access is denied).
The lab keeps settings in memory and sends texts to the SMS sink instead of Twilio.

## Run

Headless (CI / default):

```bash
# From lepton workspace root (builds SSR + hydrate, then Playwright):
# Mailpit must be up for confirm email steps.
cargo leptos end-to-end --project lepton-auth-ui-e2e
```

Watch the browser (headed) — serve first, then run Playwright in another terminal:

```bash
cargo leptos watch --project lepton-auth-ui-e2e
# other terminal (WSLg / display required on WSL):
cd lepton-auth-ui-e2e/end2end
npm ci && npx playwright install chromium
npm run test:headed   # Chromium window + slowMo
# or: npm run test:ui  # Playwright UI mode
```

Seed HTTP (harness only): `POST /api/test/seed-data`. Scenarios and builders live
in [`lepton-test-support`](../lepton-test-support/) (`auth_basic_user`,
`auth_unverified_user`, `auth_confirm_*`, `auth_reset_token`, `auth_user_with_totp`, …).

Shared Playwright helpers: [`end2end/shared/`](end2end/shared/) (`seedTestData`,
`signInAs`, Mailpit/SMS). Specs import from `end2end/tests/fixtures.ts`, which
re-exports that folder.

Confirm mid-funnel seeds resume the UI; primary happy paths still read codes from
Mailpit / SMS sink. TOTP enroll reads the base32 secret from
`totp-settings-manual-secret` and generates codes with `otplib` (same idea as
Mailpit/SMS capture, but the page is the capture surface).
