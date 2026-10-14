//! Redirect/referer path parsing and sanitization for post-auth navigation.

use url::form_urlencoded;

/// Extract the `referer` query parameter from the provided search string.
pub fn parse_referer_from_search(search: &str) -> Option<String> {
    let trimmed = search.trim_start_matches('?');
    if trimmed.is_empty() {
        return None;
    }

    for (key, value) in form_urlencoded::parse(trimmed.as_bytes()) {
        if key == "referer" {
            return Some(value.into_owned());
        }
    }
    None
}

/// Build a public one-time-token URL using a URL fragment (not query) so tokens are not
/// sent to the server or leaked via the Referer header on in-app navigation.
pub fn build_public_token_url(base_url: &str, path: &str, token_id: &str) -> String {
    format!(
        "{}{}#token={}",
        base_url.trim_end_matches('/'),
        path,
        urlencoding::encode(token_id)
    )
}

/// Parse a one-time token from the URL fragment (preferred) or query string (legacy links).
pub fn parse_token_from_url_parts(search: &str, fragment: &str) -> Option<String> {
    parse_token_param(fragment.trim_start_matches('#'))
        .or_else(|| parse_token_param(search.trim_start_matches('?')))
}

fn parse_token_param(param_string: &str) -> Option<String> {
    if param_string.is_empty() {
        return None;
    }
    for (key, value) in form_urlencoded::parse(param_string.as_bytes()) {
        if key == "token" && !value.is_empty() {
            return Some(value.into_owned());
        }
    }
    None
}

/// Normalize redirect path after auth actions (re-sanitized for defense in depth).
pub fn auth_redirect_path(path: String) -> String {
    sanitize_referer_path(Some(path))
}

fn decode_referer_once(path: &str) -> Option<String> {
    urlencoding::decode(path)
        .ok()
        .map(std::borrow::Cow::into_owned)
}

/// `/api` itself or anything under it; app pages such as `/api-tokens` are not.
fn is_api_path(path: &str) -> bool {
    path.strip_prefix("/api")
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '?', '#']))
}

fn is_safe_in_app_path(path: &str) -> bool {
    if !path.starts_with('/') || path.starts_with("//") {
        return false;
    }
    if path.contains('\\') || path.contains('@') || path.contains('\0') || path.contains("..") {
        return false;
    }
    if path.starts_with("/auth") || is_api_path(path) {
        return false;
    }
    if path == "/home" || path == "/home/" {
        return false;
    }
    true
}

/// Sanitize and normalize a referer path for redirects.
pub fn sanitize_referer_path(referer: Option<String>) -> String {
    referer
        .and_then(|path| {
            let trimmed = path.trim();
            if trimmed.is_empty() {
                return None;
            }
            let decoded = decode_referer_once(trimmed).unwrap_or_else(|| trimmed.to_string());
            if is_safe_in_app_path(&decoded) {
                Some(decoded)
            } else {
                None
            }
        })
        .unwrap_or_else(|| "/".to_string())
}

/// Build `/user/confirm-account?referer=…` with a sanitized return path.
#[must_use]
pub fn confirm_account_path_with_referer(current_path: &str) -> String {
    let safe = sanitize_referer_path(Some(current_path.to_string()));
    if safe == "/" {
        crate::paths::USER_CONFIRM_ACCOUNT.to_string()
    } else {
        format!(
            "{}?referer={}",
            crate::paths::USER_CONFIRM_ACCOUNT,
            urlencoding::encode(&safe)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        auth_redirect_path, build_public_token_url, confirm_account_path_with_referer,
        parse_referer_from_search, parse_token_from_url_parts, sanitize_referer_path,
    };

    #[test]
    fn parse_referer_from_search_reads_referer_param() {
        assert_eq!(
            parse_referer_from_search("?referer=%2Fcounter"),
            Some("/counter".to_string())
        );
    }

    #[test]
    fn parse_referer_from_search_returns_none_when_missing() {
        assert_eq!(parse_referer_from_search("?foo=bar"), None);
        assert_eq!(parse_referer_from_search(""), None);
    }

    #[test]
    fn build_public_token_url_uses_fragment_not_query() {
        let url = build_public_token_url("https://app.test", "/user/account-settings", "abc123");
        assert!(url.contains("#token=abc123"));
        assert!(!url.contains("?token="));
    }

    #[test]
    fn parse_token_from_url_parts_prefers_fragment_over_query() {
        assert_eq!(
            parse_token_from_url_parts("?token=query", "#token=fragment"),
            Some("fragment".to_string())
        );
        assert_eq!(
            parse_token_from_url_parts("?token=legacy", ""),
            Some("legacy".to_string())
        );
    }

    #[test]
    fn sanitize_referer_path_accepts_in_app_paths() {
        assert_eq!(
            sanitize_referer_path(Some("/counter/high-scores".to_string())),
            "/counter/high-scores"
        );
    }

    #[test]
    fn sanitize_referer_path_accepts_pages_that_start_with_api() {
        assert_eq!(
            sanitize_referer_path(Some("/api-tokens".to_string())),
            "/api-tokens"
        );
        assert_eq!(sanitize_referer_path(Some("/apis".to_string())), "/apis");
    }

    #[test]
    fn sanitize_referer_path_rejects_unsafe_or_auth_paths() {
        assert_eq!(
            sanitize_referer_path(Some("//example.com".to_string())),
            "/"
        );
        assert_eq!(sanitize_referer_path(Some("/auth/signin".to_string())), "/");
        assert_eq!(sanitize_referer_path(Some("/auth".to_string())), "/");
        assert_eq!(sanitize_referer_path(Some("/api/upload".to_string())), "/");
        assert_eq!(sanitize_referer_path(Some("/api".to_string())), "/");
        assert_eq!(sanitize_referer_path(Some("/api?x=1".to_string())), "/");
        assert_eq!(sanitize_referer_path(Some("/home".to_string())), "/");
        assert_eq!(sanitize_referer_path(None), "/");
    }

    #[test]
    fn sanitize_referer_path_rejects_encoded_and_traversal_bypasses() {
        assert_eq!(
            sanitize_referer_path(Some("%2F%2Fevil.example".to_string())),
            "/"
        );
        assert_eq!(
            sanitize_referer_path(Some("/welcome/../auth/signin".to_string())),
            "/"
        );
        assert_eq!(sanitize_referer_path(Some("/path\\evil".to_string())), "/");
    }

    #[test]
    fn auth_redirect_path_re_sanitizes_unsafe_paths() {
        assert_eq!(auth_redirect_path("//evil".to_string()), "/");
        assert_eq!(auth_redirect_path("/dashboard".to_string()), "/dashboard");
    }

    #[test]
    fn confirm_account_path_with_referer_encodes_safe_path() {
        assert_eq!(
            confirm_account_path_with_referer("/counter/high-scores"),
            "/user/confirm-account?referer=%2Fcounter%2Fhigh-scores"
        );
        assert_eq!(
            confirm_account_path_with_referer("/auth/signin"),
            "/user/confirm-account"
        );
    }
}
