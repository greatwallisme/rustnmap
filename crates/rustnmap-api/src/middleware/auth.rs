// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  greatwallisme
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
/// Skips authentication for health check endpoint.
///
/// # Errors
///
/// Returns `StatusCode::UNAUTHORIZED` if the API key is missing or invalid.
pub async fn auth_middleware(
    State(state): State<crate::server::ApiState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip authentication for health check endpoint
    if request.uri().path() == "/api/v1/health" {
        return Ok(next.run(request).await);
    }

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
