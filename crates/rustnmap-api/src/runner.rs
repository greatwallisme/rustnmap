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

//! Background scan runner that picks up queued scans and executes them.

use std::sync::Arc;

use tracing::{error, info};

use crate::manager::ScanManager;
use crate::ScanStatus;

/// Interval between polling for queued scans.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Background scan runner that polls for queued scans and executes them.
#[derive(Debug)]
pub struct ScanRunner {
    manager: Arc<ScanManager>,
}

impl ScanRunner {
    /// Create a new scan runner.
    #[must_use]
    pub fn new(manager: Arc<ScanManager>) -> Self {
        Self { manager }
    }

    /// Start the background runner loop.
    ///
    /// Spawns a tokio task that polls for queued scans and executes them.
    pub fn start(self: &Arc<Self>) {
        let runner = Arc::clone(self);
        tokio::spawn(async move {
            info!("Scan runner started, polling every {:?}", POLL_INTERVAL);
            let mut interval = tokio::time::interval(POLL_INTERVAL);

            loop {
                interval.tick().await;
                runner.process_queued_scans();
            }
        });
    }

    /// Find and execute one queued scan.
    fn process_queued_scans(&self) {
        let queued = self.manager.list_scans();
        let Some(queued_scan) = queued.into_iter().find(|t| t.status == ScanStatus::Queued) else {
            return;
        };

        let scan_id = queued_scan.id.clone();
        let targets = queued_scan.targets.clone();
        let scan_type_str = queued_scan.scan_type.clone();

        info!("Starting scan {scan_id} with targets {targets:?}");

        if let Err(e) = self.manager.update_status(&scan_id, ScanStatus::Running) {
            error!("Failed to update scan {scan_id} to Running: {e}");
            return;
        }

        let manager = Arc::clone(&self.manager);

        tokio::spawn(async move {
            match Self::execute_scan(&scan_id, &targets, &scan_type_str).await {
                Ok(result) => {
                    let api_result = crate::ScanResultsResponse {
                        scan_id: scan_id.clone(),
                        status: ScanStatus::Completed,
                        completed_at: Some(chrono::Utc::now()),
                        hosts: result.hosts,
                        statistics: result.statistics,
                    };

                    if let Err(e) = manager.store_results(&scan_id, api_result) {
                        error!("Failed to store results for scan {scan_id}: {e}");
                    }
                    if let Err(e) = manager.update_status(&scan_id, ScanStatus::Completed) {
                        error!("Failed to update scan {scan_id} to Completed: {e}");
                    }
                    info!("Scan {scan_id} completed successfully");
                }
                Err(e) => {
                    error!("Scan {scan_id} failed: {e}");
                    if let Err(update_err) = manager.update_status(&scan_id, ScanStatus::Failed) {
                        error!("Failed to update scan {scan_id} to Failed: {update_err}");
                    }
                }
            }
        });
    }

    /// Execute a scan using `ScanOrchestrator`.
    async fn execute_scan(
        scan_id: &str,
        targets: &[String],
        scan_type_str: &str,
    ) -> Result<rustnmap_output::ScanResult, String> {
        let scan_type = parse_scan_type(scan_type_str)?;

        let config = rustnmap_core::session::ScanConfig {
            scan_types: vec![scan_type],
            ..Default::default()
        };

        let parser = rustnmap_target::parser::TargetParser::new();
        let target_str = targets.join(",");
        let target_group = parser
            .parse(&target_str)
            .map_err(|e| format!("Invalid targets: {e}"))?;

        let session = rustnmap_core::session::ScanSession::new(config, target_group)
            .map_err(|e| format!("Failed to create scan session for {scan_id}: {e}"))?;

        let orchestrator = rustnmap_core::orchestrator::ScanOrchestrator::new(Arc::new(session));
        orchestrator
            .run()
            .await
            .map_err(|e| format!("Scan execution failed: {e}"))
    }
}

/// Parse scan type string into `ScanType` enum.
fn parse_scan_type(s: &str) -> Result<rustnmap_core::session::ScanType, String> {
    match s {
        "syn" => Ok(rustnmap_core::session::ScanType::TcpSyn),
        "connect" => Ok(rustnmap_core::session::ScanType::TcpConnect),
        "fin" => Ok(rustnmap_core::session::ScanType::TcpFin),
        "null" => Ok(rustnmap_core::session::ScanType::TcpNull),
        "xmas" => Ok(rustnmap_core::session::ScanType::TcpXmas),
        "ack" => Ok(rustnmap_core::session::ScanType::TcpAck),
        "window" => Ok(rustnmap_core::session::ScanType::TcpWindow),
        "maimon" => Ok(rustnmap_core::session::ScanType::TcpMaimon),
        "udp" => Ok(rustnmap_core::session::ScanType::Udp),
        "sctp_init" => Ok(rustnmap_core::session::ScanType::SctpInit),
        other => Err(format!("Unsupported scan type: {other}")),
    }
}
