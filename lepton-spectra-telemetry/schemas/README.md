# Lepton Spectra schemas

Human-edited `spectra_metric!` / `spectra_schema!` DSL sources. Linked from
`src/schemas.rs` so inventory registration and typed `*Recorder` / `*Logger`
helpers expand when this crate is linked.

| File | Name | Kind |
|------|------|------|
| `lepton_email_send_spectra_metric.rs` | `lepton_email_send` | counter |
| `lepton_sms_send_spectra_metric.rs` | `lepton_sms_send` | counter |
| `lepton_signup_spectra_metric.rs` | `lepton_signup` | counter |
| `lepton_signin_spectra_metric.rs` | `lepton_signin` | counter |
| `lepton_oauth_spectra_metric.rs` | `lepton_oauth` | counter |
| `lepton_verify_spectra_metric.rs` | `lepton_verify` | counter |
| `lepton_password_reset_spectra_metric.rs` | `lepton_password_reset` | counter |
| `lepton_totp_spectra_metric.rs` | `lepton_totp` | counter |
| `lepton_device_spectra_metric.rs` | `lepton_device` | counter |
| `lepton_service_user_spectra_metric.rs` | `lepton_service_user` | counter |
| `lepton_contact_spectra_metric.rs` | `lepton_contact` | counter |
| `lepton_account_spectra_metric.rs` | `lepton_account` | counter |
| `lepton_identity_delete_spectra_metric.rs` | `lepton_identity_delete` | counter |
| `lepton_step_up_spectra_metric.rs` | `lepton_step_up` | counter |
| `lepton_auth_failure_spectra_schema.rs` | `lepton_auth_failure` | event |

Labels and event fields are ops-id only (no recipient, body, PII, passwords, tokens).
