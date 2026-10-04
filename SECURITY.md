# Security Policy

## Supported versions

Security fixes are accepted against the latest `main` branch and tagged releases (`0.1.x`) of this repository's crates (`lepton-auth`, `lepton-identity`, and related crates).

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security-sensitive reports.

Prefer one of the following:

1. **GitHub Security Advisories** — use [Report a vulnerability](https://github.com/unified-field-dev/lepton/security/advisories/new) on this repository when available.
2. Contact the maintainers privately via the repository owner listed at https://github.com/unified-field-dev/lepton.

Include:

- a description of the issue and its impact
- steps to reproduce or a proof of concept when possible
- affected crate names and versions

We will acknowledge receipt as soon as practical and coordinate a fix and disclosure timeline with you.

## Scope

In scope: vulnerabilities in this repository's published crates and documentation that could cause unsafe production defaults, plus CI/supply-chain issues in this repository.

Out of scope: vulnerabilities solely in third-party dependencies unless this project mishandles them in a security-relevant way.

## Host requirements: session cookies

This kit does **not** configure HTTP session cookie flags. Consuming hosts that wire
`tower-sessions` / `axum-login` (see
`lepton-host-adapter/examples/axum_session_snapshot.rs`) **must** set:

| Flag | Requirement |
|------|-------------|
| `HttpOnly` | Required — blocks document access to the session cookie |
| `Secure` | Required in production (HTTPS) — omit only for local HTTP dev |
| `SameSite` | Required — prefer `Lax` or `Strict` |

Also prefer a persistent session store (not process-local memory alone) and rotate
the session id on login. Inspect production `Set-Cookie` responses to confirm
`Secure; HttpOnly; SameSite=…` before go-live.

## TrustedBrowser MFA-skip cookie (`lepton_device`)

When a user completes login MFA with “Remember this browser,” the server sets an
HttpOnly cookie named `lepton_device` (`device_id.secret`). The secret is stored
only as an Argon2 hash on `AuthDevice.binding_secret_hash` (SYSTEM_ONLY). Hosts
should mirror session cookie flags (`Secure` in production, `SameSite=Lax` or
stricter). Revoking the device clears the hash so the cookie no longer skips MFA.
TrustedBrowser skip is intentionally weaker than WebAuthn assertion skip.

## One-time tokens in email links

Verification and password-reset emails embed tokens in the URL **fragment**
(`#token=…`), not the query string, so tokens are not sent to the server on
navigation and are not included in the `Referer` header on same-origin links.

Legacy `?token=` links are still accepted client-side; the UI strips that query
param from the address bar after reading the token. Token verification itself
uses a **POST body** (`VerifyEmailToken` / `ResetPassword` server functions),
not the URL.

**Residual:** Email clients and browser history may retain full link URLs
(including fragments). Hosts that need shorter exposure can add an HttpOnly
cookie handoff route; this kit does not ship one.

## `User.password_hash` field policy

`password_hash` read allow is `[OWNER_BY_ID, SYSTEM_ONLY]`
(`lepton-identity/schemas/user_valence_schema.rs`). The owning User actor can
load their own PHC for change-password and email re-auth on session
`user_valence`. System still reads any PHC for pre-session
`Backend::authenticate` / `get_user`, signup, and password reset.

Entity `User` read stays `AUTHENTICATED`, so another signed-in user can load the
row; Valence field filtering omits `password_hash` (returns `None`). Covered by
`lepton-auth` tests `password_hash_owner_read_happy_path`,
`password_hash_cross_user_redacted_sad`, and
`password_hash_system_read_happy_path`.

**Accepted residual:** any System-scoped Valence can still read every user's
PHC. That is required for control-plane credential paths; keep System use
intentional and narrow.

## Account wipe (GDPR erase)

Account wipe on Account Settings (`WipeAccount` / `execute_wipe_account`) is for the
account's own user. Sign-up gives that user the `member` role; `owner` is reserved for
platform owners, who may also wipe their own account. `admin` is refused.

1. Session via `require_auth_user`
2. Session role `member` or `owner` **and** `AccountMembership` role Member or Owner on the resolved account
3. Current-password Argon2 re-check (same path as change-password)
4. Confirm phrase `DELETE`
5. When an enabled `TotpFactor` exists, a valid TOTP code
6. Then `Higgs::unsafe_system_valence()` for Account / contact CUD (`SYSTEM_ONLY`)
7. `identity_delete::erase_account`, then session logout

The server fn does not take a foreign account id (no IDOR surface). Errors and
tracing use `reason_class` / generic Args strings (no email, password, or TOTP).
Persona deletes stay on library `delete_user` with `SoleMember` / `AccountPrimary`
guards; they are not exposed as host Account Settings UI.

**Accepted residual:** System Valence after gates mirrors devices CUD. Schema-level
`account_owner` delete policy is still open; keep elevation behind the gates above.

## Signup policy

Under `ssr`, the `Signup` server function is available by default (open registration).
Hosts that need private or invite-only deploys must set:

```bash
UF_LEPTON_SIGNUP_DISABLED=1
```

When set to `1` or `true`, `Signup` fails closed with a generic error. Hide or
remove sign-up CTAs in the host UI when you disable signup (shell menu and
`/auth/signup`). Rate limits and invite tokens are host/edge concerns; this kit
does not ship them.

## Multi-instance and session stores

This kit does **not** ship a shared session store. Consuming hosts that run more
than one process must use a persistent `tower-sessions` store. Single-process
embedded/lab hosts may keep process-local memory for sessions.

OAuth CSRF + PKCE pending state is stored in Valence (`OauthPendingState`, TTL
about 10 minutes) so multi-replica OAuth begin/complete works when hosts share
the same Valence backend. Session cookies remain a separate host concern.

## Auth delivery and verification

Hosts resolve secrets into plain strings and pass them to builders. Lepton crates
have no secrets-manager dependency.

- `verification_status` uses pre-auth Photon `auth = "none"`: `challenge_id` is a
  high-entropy capability. Responses never include secrets.
- OAuth CSRF + PKCE pending state lives in Valence (see **Multi-instance and
  session stores**); device confirm codes and TOTP recovery codes are returned
  once; `Display` uses `reason_class` only (no OTP / tokens / passwords).
- Quiet password-reset and signup delivery failures stay opaque (anti-enumeration).
- Live OAuth: authorization codes and access tokens never appear in `Display` or
  tracing; the live CLI binds loopback only.
- SMS / email adapters must not log E.164, recipient, body, OTP, or auth tokens.