//! API Key authentication middleware

use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use http::header::{HeaderMap, AUTHORIZATION};

/// Authentication middleware layer
#[derive(Clone, Debug)]
pub struct AuthMiddleware {
    #[allow(
        dead_code,
        reason = "State field reserved for future middleware functionality"
    )]
    state: crate::server::ApiState,
}

impl AuthMiddleware {
    #[must_use]
    pub fn new(state: crate::server::ApiState) -> Self {
        Self { state }
    }

    /// Extract API key from request headers
    fn extract_api_key(headers: &HeaderMap) -> Option<&str> {
        let auth_header = headers.get(AUTHORIZATION)?.to_str().ok()?;

        // Support "Bearer <key>" format
        auth_header.strip_prefix("Bearer ").or(Some(auth_header))
    }
}

/// Middleware handler for API key authentication
///
/// # Errors
///
/// Returns `StatusCode::UNAUTHORIZED` if the API key is missing or invalid.
pub async fn auth_middleware(
    State(state): State<crate::server::ApiState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract API key from headers
    let api_key = {
        let headers = request.headers();
        match AuthMiddleware::extract_api_key(headers) {
            Some(key) => key.to_string(),
            None => {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    };

    // Validate API key
    if !state.config.is_valid_key(&api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let (mut parts, body) = request.into_parts();
    parts.extensions.insert(api_key);

    Ok(next.run(Request::from_parts(parts, body)).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_api_key_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer test-key-123".parse().unwrap());

        let key = AuthMiddleware::extract_api_key(&headers);
        assert_eq!(key, Some("test-key-123"));
    }

    #[test]
    fn test_extract_api_key_direct() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "direct-key-456".parse().unwrap());

        let key = AuthMiddleware::extract_api_key(&headers);
        assert_eq!(key, Some("direct-key-456"));
    }

    #[test]
    fn test_extract_api_key_missing() {
        let headers = HeaderMap::new();
        let key = AuthMiddleware::extract_api_key(&headers);
        assert_eq!(key, None);
    }
}
