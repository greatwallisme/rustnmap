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

//! API Server implementation

use std::net::SocketAddr;
use std::sync::Arc;

use tower_http::trace::TraceLayer;

use crate::config::ApiConfig;
use crate::error::ApiResult;
use crate::manager::ScanManager;
use crate::runner::ScanRunner;

/// Shared API state
#[derive(Clone, Debug)]
pub struct ApiState {
    pub config: Arc<ApiConfig>,
    pub scan_manager: Arc<ScanManager>,
}

impl ApiState {
    #[must_use]
    pub fn new(config: ApiConfig, scan_manager: Arc<ScanManager>) -> Self {
        Self {
            config: Arc::new(config),
            scan_manager,
        }
    }
}

/// REST API Server
#[derive(Debug)]
pub struct ApiServer {
    config: ApiConfig,
    scan_manager: Arc<ScanManager>,
}

impl ApiServer {
    /// Create a new API server
    ///
    /// # Errors
    ///
    /// Returns `ApiError` if initialization fails.
    pub fn new(config: &ApiConfig) -> ApiResult<Self> {
        Ok(Self {
            config: config.clone(),
            scan_manager: Arc::new(ScanManager::new(config.clone())),
        })
    }

    /// Create with existing scan manager
    #[must_use]
    pub fn with_scan_manager(config: ApiConfig, scan_manager: Arc<ScanManager>) -> Self {
        Self {
            config,
            scan_manager,
        }
    }

    /// Get the API state
    fn state(&self) -> ApiState {
        ApiState::new(self.config.clone(), Arc::clone(&self.scan_manager))
    }

    /// Run the API server
    ///
    /// # Errors
    ///
    /// Returns `ApiError` if the server fails to start or encounters an error during operation.
    pub async fn run(self, addr: SocketAddr) -> ApiResult<()> {
        let state = self.state();

        // Start background scan runner
        let runner = Arc::new(ScanRunner::new(Arc::clone(&state.scan_manager)));
        runner.start();

        // Create router
        let app = crate::routes::create_router(state);

        // Add tracing layer
        let app = app.layer(TraceLayer::new_for_http());

        tracing::info!("Starting API server on {}", addr);

        // Run server
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }

    /// Run the API server and return the actual bound address
    ///
    /// # Errors
    ///
    /// Returns `ApiError` if the server fails to start or encounters an error during operation.
    pub async fn run_with_addr(self, addr: SocketAddr) -> ApiResult<SocketAddr> {
        let state = self.state();

        // Start background scan runner
        let runner = Arc::new(ScanRunner::new(Arc::clone(&state.scan_manager)));
        runner.start();

        // Create router
        let app = crate::routes::create_router(state);

        // Add tracing layer
        let app = app.layer(TraceLayer::new_for_http());

        // Run server
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let actual_addr = listener.local_addr()?;

        tracing::info!("Starting API server on {}", actual_addr);

        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Ok(actual_addr)
    }

    /// Get the scan manager
    #[must_use]
    pub fn scan_manager(&self) -> Arc<ScanManager> {
        Arc::clone(&self.scan_manager)
    }

    /// Get the config
    #[must_use]
    pub fn config(&self) -> &ApiConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_api_server_creation() {
        let config = ApiConfig::default();
        let server = ApiServer::new(&config).unwrap();

        assert_eq!(server.config.max_concurrent_scans, 5);
        assert!(server.config.is_valid_key(&server.config.api_keys[0]));
    }

    #[tokio::test]
    async fn test_api_server_state() {
        let config = ApiConfig::default();
        let server = ApiServer::new(&config).unwrap();
        let state = server.state();

        assert_eq!(state.config.max_concurrent_scans, 5);
        assert!(state.config.is_valid_key(&state.config.api_keys[0]));
    }
}
