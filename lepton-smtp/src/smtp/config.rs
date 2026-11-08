//! SMTP relay configuration and builder.
//!
//! Build a validated [`SmtpConfig`] for [`crate::SmtpAdapter`] / [`crate::EmailServiceBuilder::smtp`].
//! For Mailpit locally: `host = "127.0.0.1"`, `port = 1025`, `use_tls = false`.

use crate::error::EmailDeliveryError;

/// Relay settings for [`crate::SmtpAdapter`].
///
/// Prefer [`SmtpConfig::builder`] so required fields and credential pairing are checked before
/// send. Use when delivering through Mailpit or a production SMTP host.
///
/// Required for a usable config: `host`, `port`, `from_email`. Optional: `use_tls`, `username`,
/// `password`, `from_name` (default `Orbital`). Username and password must both be set or both
/// omitted. TLS defaults to `true` when credentials are set, else `false`; an explicit
/// [`SmtpConfigBuilder::use_tls`] wins.
///
/// [`SmtpConfig::from_env`] remains a host helper that loads `UF_SMTP_*` / `UF_EMAIL_*` once at
/// boot—do not call it on every send.
///
/// # Examples
///
/// Mailpit-style local relay (no TLS, no auth):
///
/// ```
/// use lepton_smtp::SmtpConfig;
///
/// # fn main() -> Result<(), lepton_smtp::EmailDeliveryError> {
/// let config = SmtpConfig::builder()
///     .host("127.0.0.1")
///     .port(1025)
///     .use_tls(false)
///     .from_email("noreply@example.test")
///     .build()?;
/// assert_eq!(config.host, "127.0.0.1");
/// assert!(!config.use_tls);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct SmtpConfig {
    /// SMTP relay hostname.
    pub host: String,
    /// SMTP relay port.
    pub port: u16,
    /// Whether to connect over TLS.
    pub use_tls: bool,
    /// Optional SMTP auth username.
    pub username: Option<String>,
    /// Optional SMTP auth password.
    pub password: Option<String>,
    /// `From:` address.
    pub from_email: String,
    /// `From:` display name (default `Orbital` via builder / env).
    pub from_name: String,
}

impl SmtpConfig {
    /// Start a validated builder.
    #[must_use]
    pub fn builder() -> SmtpConfigBuilder {
        SmtpConfigBuilder::default()
    }

    /// Load from `UF_SMTP_*` / `UF_EMAIL_*` env vars (host helper).
    ///
    /// # Errors
    ///
    /// Returns [`EmailDeliveryError::ConfigError`] when required env vars are missing or
    /// invalid (`reason_class=missing_field` or `invalid_port`), or when builder validation
    /// fails (`incomplete_credentials`).
    pub fn from_env() -> Result<Self, EmailDeliveryError> {
        let host = std::env::var("UF_SMTP_HOST")
            .map_err(|_| EmailDeliveryError::config("missing_field", "Missing UF_SMTP_HOST"))?;
        if host.trim().is_empty() {
            return Err(EmailDeliveryError::config(
                "missing_field",
                "UF_SMTP_HOST cannot be empty",
            ));
        }
        let port_raw = std::env::var("UF_SMTP_PORT")
            .map_err(|_| EmailDeliveryError::config("missing_field", "Missing UF_SMTP_PORT"))?;
        let port = port_raw.parse::<u16>().map_err(|_| {
            EmailDeliveryError::config("invalid_port", "Invalid UF_SMTP_PORT: expected integer")
        })?;
        let username = std::env::var("UF_SMTP_USERNAME")
            .ok()
            .filter(|v| !v.is_empty());
        let password = std::env::var("UF_SMTP_PASSWORD")
            .ok()
            .filter(|v| !v.is_empty());
        let from_email = std::env::var("UF_EMAIL_FROM")
            .map_err(|_| EmailDeliveryError::config("missing_field", "Missing UF_EMAIL_FROM"))?;
        let from_name =
            std::env::var("UF_EMAIL_FROM_NAME").unwrap_or_else(|_| "Orbital".to_string());

        let mut builder = Self::builder()
            .host(host)
            .port(port)
            .from_email(from_email)
            .from_name(from_name);

        if let Some(user) = username {
            builder = builder.username(user);
        }
        if let Some(pass) = password {
            builder = builder.password(pass);
        }

        if let Ok(value) = std::env::var("UF_SMTP_USE_TLS") {
            let normalized = value.trim().to_ascii_lowercase();
            let use_tls = normalized == "1" || normalized == "true" || normalized == "yes";
            builder = builder.use_tls(use_tls);
        }

        builder.build()
    }
}

/// Fluent builder for [`SmtpConfig`].
///
/// Required: `host`, `port`, `from_email`. Optional: `use_tls`, `username`, `password`,
/// `from_name` (default `Orbital`). Username and password must both be set or both omitted.
/// TLS defaults to `true` when credentials are set, else `false`; an explicit [`use_tls`](Self::use_tls)
/// wins.
///
/// # Examples
///
/// ```
/// use lepton_smtp::SmtpConfig;
///
/// # fn main() -> Result<(), lepton_smtp::EmailDeliveryError> {
/// let config = SmtpConfig::builder()
///     .host("127.0.0.1")
///     .port(1025)
///     .use_tls(false)
///     .from_email("noreply@example.test")
///     .build()?;
/// assert_eq!(config.port, 1025);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Default)]
pub struct SmtpConfigBuilder {
    host: Option<String>,
    port: Option<u16>,
    use_tls: Option<bool>,
    username: Option<String>,
    password: Option<String>,
    from_email: Option<String>,
    from_name: Option<String>,
}

impl SmtpConfigBuilder {
    /// SMTP relay hostname (required).
    #[must_use]
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// SMTP relay port (required).
    #[must_use]
    pub const fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Explicit TLS flag (overrides credential-based default).
    #[must_use]
    pub const fn use_tls(mut self, use_tls: bool) -> Self {
        self.use_tls = Some(use_tls);
        self
    }

    /// SMTP auth username (requires matching password).
    #[must_use]
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// SMTP auth password (requires matching username).
    #[must_use]
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// `From:` address (required).
    #[must_use]
    pub fn from_email(mut self, from_email: impl Into<String>) -> Self {
        self.from_email = Some(from_email.into());
        self
    }

    /// `From:` display name (default `Orbital`).
    #[must_use]
    pub fn from_name(mut self, from_name: impl Into<String>) -> Self {
        self.from_name = Some(from_name.into());
        self
    }

    /// Validate and build [`SmtpConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`EmailDeliveryError::ConfigError`] when:
    ///
    /// * `host`, `port`, or `from_email` is missing (`reason_class=missing_field`);
    /// * username is set without password, or password without username
    ///   (`reason_class=incomplete_credentials`).
    pub fn build(self) -> Result<SmtpConfig, EmailDeliveryError> {
        let host = self
            .host
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .ok_or_else(|| EmailDeliveryError::config("missing_field", "host is required"))?;
        let port = self
            .port
            .ok_or_else(|| EmailDeliveryError::config("missing_field", "port is required"))?;
        let from_email = self
            .from_email
            .map(|e| e.trim().to_string())
            .filter(|e| !e.is_empty())
            .ok_or_else(|| EmailDeliveryError::config("missing_field", "from_email is required"))?;

        let username = self.username.filter(|u| !u.is_empty());
        let password = self.password.filter(|p| !p.is_empty());
        if username.is_some() ^ password.is_some() {
            return Err(EmailDeliveryError::config(
                "incomplete_credentials",
                "username and password must both be set or both omitted",
            ));
        }

        let credentials_set = username.is_some() && password.is_some();
        let use_tls = self.use_tls.unwrap_or(credentials_set);
        let from_name = self
            .from_name
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "Orbital".to_string());

        Ok(SmtpConfig {
            host,
            port,
            use_tls,
            username,
            password,
            from_email,
            from_name,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::driver::EMAIL_ENV_LOCK;

    #[test]
    fn smtp_config_builder_happy_path() {
        let cfg = SmtpConfig::builder()
            .host("127.0.0.1")
            .port(1025)
            .use_tls(false)
            .from_email("noreply@example.test")
            .build()
            .expect("valid smtp config");
        assert_eq!(cfg.host, "127.0.0.1");
        assert_eq!(cfg.port, 1025);
        assert!(!cfg.use_tls);
        assert_eq!(cfg.from_email, "noreply@example.test");
        assert_eq!(cfg.from_name, "Orbital");
        assert!(cfg.username.is_none());
        assert!(cfg.password.is_none());
    }

    #[test]
    fn smtp_config_builder_missing_host_sad() {
        let err = SmtpConfig::builder()
            .port(587)
            .from_email("noreply@example.test")
            .build()
            .expect_err("host required");
        assert!(matches!(err, EmailDeliveryError::ConfigError(_)));
        assert!(err.to_string().contains("reason_class=missing_field"));
        assert!(err.to_string().contains("host"));
    }

    #[test]
    fn smtp_config_builder_username_without_password_sad() {
        let err = SmtpConfig::builder()
            .host("smtp.example.test")
            .port(587)
            .from_email("noreply@example.test")
            .username("user")
            .build()
            .expect_err("password required with username");
        assert!(matches!(err, EmailDeliveryError::ConfigError(_)));
        assert!(err
            .to_string()
            .contains("reason_class=incomplete_credentials"));
    }

    #[test]
    fn smtp_tls_defaults_on_when_credentials_set() {
        let _g = EMAIL_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let keys = [
            "UF_SMTP_HOST",
            "UF_SMTP_PORT",
            "UF_SMTP_USE_TLS",
            "UF_SMTP_USERNAME",
            "UF_SMTP_PASSWORD",
            "UF_EMAIL_FROM",
            "UF_EMAIL_FROM_NAME",
        ];
        let prev: Vec<_> = keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        for k in keys {
            std::env::remove_var(k);
        }
        std::env::set_var("UF_SMTP_HOST", "smtp.example.test");
        std::env::set_var("UF_SMTP_PORT", "587");
        std::env::set_var("UF_EMAIL_FROM", "noreply@example.test");
        std::env::set_var("UF_SMTP_USERNAME", "user");
        std::env::set_var("UF_SMTP_PASSWORD", "secret");

        let cfg = SmtpConfig::from_env().expect("smtp config");
        assert!(
            cfg.use_tls,
            "TLS should default on when credentials are set"
        );

        std::env::set_var("UF_SMTP_USE_TLS", "false");
        let cfg_off = SmtpConfig::from_env().expect("smtp config");
        assert!(!cfg_off.use_tls, "explicit UF_SMTP_USE_TLS=false must win");

        for (k, v) in prev {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }

    #[test]
    fn smtp_tls_defaults_off_without_credentials() {
        let _g = EMAIL_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let keys = [
            "UF_SMTP_HOST",
            "UF_SMTP_PORT",
            "UF_SMTP_USE_TLS",
            "UF_SMTP_USERNAME",
            "UF_SMTP_PASSWORD",
            "UF_EMAIL_FROM",
            "UF_EMAIL_FROM_NAME",
        ];
        let prev: Vec<_> = keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        for k in keys {
            std::env::remove_var(k);
        }
        std::env::set_var("UF_SMTP_HOST", "smtp.example.test");
        std::env::set_var("UF_SMTP_PORT", "25");
        std::env::set_var("UF_EMAIL_FROM", "noreply@example.test");

        let cfg = SmtpConfig::from_env().expect("smtp config");
        assert!(
            !cfg.use_tls,
            "TLS should stay off when no credentials and env unset"
        );

        for (k, v) in prev {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}
