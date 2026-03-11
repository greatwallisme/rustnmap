//! API Server example - Start the REST API server
//!
//! This example demonstrates how to start the `RustNmap` REST API server.
//!
//! # Usage
//!
//! ```bash
//! cargo run --package rustnmap-api --example server
//! ```
//!
//! Or run the compiled binary:
//! ```bash
//! ./target/release/examples/server
//! ```

use std::net::SocketAddr;

use rustnmap_api::{ApiConfig, ApiServer};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false).with_thread_ids(false))
        .with(env_filter)
        .init();

    // Create API configuration
    let config = ApiConfig::new()
        .with_listen_addr("127.0.0.1:8080".to_string())
        .with_max_concurrent_scans(5);

    // Log server startup information
    tracing::info!("============================================");
    tracing::info!("   RustNmap REST API Server");
    tracing::info!("============================================");
    tracing::info!("Listen address: http://{}", config.listen_addr);
    tracing::info!("Max concurrent scans: {}", config.max_concurrent_scans);
    tracing::info!("API Keys (use in Authorization header):");
    for (i, key) in config.api_keys.iter().enumerate() {
        tracing::info!("  [{}]: {}", i + 1, key);
    }
    tracing::info!("Test endpoints:");
    tracing::info!("  Health check: curl http://127.0.0.1:8080/api/v1/health");
    tracing::info!("  Create scan:  curl -X POST http://127.0.0.1:8080/api/v1/scans \\");
    tracing::info!("                -H 'Authorization: Bearer <API_KEY>' \\");
    tracing::info!("                -H 'Content-Type: application/json' \\");
    tracing::info!(
        "                -d '{{\"targets\":[\"127.0.0.1\"],\"scan_type\":\"connect\"}}'"
    );
    tracing::info!("Press Ctrl+C to stop the server");
    tracing::info!("============================================");

    // Create and run server
    let server = ApiServer::new(&config)?;
    let addr: SocketAddr = config.listen_addr.parse()?;

    server.run(addr).await?;

    Ok(())
}
