#!/usr/bin/env python3
"""
Scan Comparison Logic

Provides functionality to execute scans and compare their results.
"""

import asyncio
import logging
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import lxml.etree as ET

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of a scan execution."""

    exit_code: int
    duration_ms: int
    stdout: str
    stderr: str
    output_path: Optional[Path] = None
    raw_output: bytes = b""

    @property
    def stdout_line_count(self) -> int:
        return len(self.stdout.strip().split("\n")) if self.stdout.strip() else 0

    @property
    def stderr_line_count(self) -> int:
        return len(self.stderr.strip().split("\n")) if self.stderr.strip() else 0

    @property
    def success(self) -> bool:
        return self.exit_code == 0

    @property
    def duration_seconds(self) -> float:
        return self.duration_ms / 1000.0

    def get_ports(self) -> dict[str, dict[str, str]]:
        """Parse port information from scan output."""
        ports = {}

        # Try parsing normal output format
        lines = self.stdout.split("\n")
        in_port_section = False

        for line in lines:
            line = line.strip()

            # Detect port section
            if "PORT" in line and "STATE" in line:
                in_port_section = True
                continue

            if in_port_section:
                # Parse port line: PORT    STATE    SERVICE
                # Example: 22/tcp  open  ssh
                if not line or line.startswith(("=", "|", "_")):
                    continue

                parts = line.split()
                if len(parts) >= 2:
                    port_proto = parts[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"

                    ports[port_proto] = {
                        "state": state,
                        "service": service,
                    }

        return ports

    def get_xml_ports(self) -> dict[str, dict[str, str]]:
        """Parse port information from XML output."""
        if not self.raw_output:
            return {}

        ports = {}
        try:
            root = ET.fromstring(self.raw_output)

            for port in root.xpath(".//port"):
                port_id = port.get("portid")
                protocol = port.get("protocol")
                port_proto = f"{port_id}/{protocol}"

                state_elem = port.find("state")
                state = state_elem.get("state") if state_elem is not None else "unknown"

                service_elem = port.find("service")
                service = service_elem.get("name", "unknown") if service_elem is not None else "unknown"

                ports[port_proto] = {
                    "state": state,
                    "service": service,
                }
        except ET.XMLSyntaxError:
            return {}

        return ports

    def get_service_info(self) -> list[dict[str, str]]:
        """Parse service version information from scan output."""
        services = []

        lines = self.stdout.split("\n")
        for line in lines:
            line = line.strip()

            # Parse service version line
            # Example: 22/tcp  open  ssh  OpenSSH 8.4p1 Debian 5+deb11u3
            if "open" in line and ("ssh" in line or "http" in line or "ftp" in line or "telnet" in line):
                parts = line.split()
                if len(parts) >= 4:
                    services.append({
                        "port": parts[0],
                        "state": parts[1],
                        "service": parts[2],
                        "version": " ".join(parts[3:]),
                    })

        return services

    def get_os_info(self) -> dict[str, Any]:
        """Parse OS detection information from scan output."""
        os_info = {
            "detected": False,
            "os_matches": [],
            "accuracy": None,
        }

        lines = self.stdout.split("\n")
        in_os_section = False

        for line in lines:
            line = line.strip()

            if "OS details" in line or "Running" in line:
                os_info["detected"] = True
                in_os_section = True
                # Extract OS info
                if "OS details:" in line:
                    os_str = line.split("OS details:")[-1].strip()
                    os_info["os_matches"].append(os_str)

            if in_os_section and "OS CPE:" in line:
                cpe = line.split("OS CPE:")[-1].strip()
                if os_info["os_matches"]:
                    os_info["os_matches"][-1] += f" (CPE: {cpe})"

        return os_info

    def get_timing_info(self) -> dict[str, Any]:
        """Parse timing information from scan output."""
        timing_info = {
            "scanned_ports": 0,
            "elapsed_time": 0.0,
        }

        lines = self.stdout.split("\n")
        for line in lines:
            line = line.strip()

            # Parse: "Nmap done: 1 IP address (1 host up) scanned in 2.45 seconds"
            if "scanned in" in line:
                match = re.search(r"scanned in ([\d.]+) seconds?", line)
                if match:
                    timing_info["elapsed_time"] = float(match.group(1))

            # Parse: "Scanned in X seconds"
            if "Scanned in" in line:
                match = re.search(r"Scanned in ([\d.]+) seconds?", line)
                if match:
                    timing_info["elapsed_time"] = float(match.group(1))

        return timing_info


class ScanComparator:
    """Compare scan results between rustnmap and nmap."""

    def __init__(self, config):
        self.config = config
        self.temp_dir = Path(tempfile.gettempdir())

    async def run_scan(
        self,
        command: str,
        scanner_name: str,
        use_xml_output: bool = False,
    ) -> ScanResult:
        """Execute a scan command and capture results."""
        logger.info(f"Running {scanner_name}: {command}")

        start_time = datetime.now()
        output_file = None

        if use_xml_output:
            output_file = self.temp_dir / f"{scanner_name}_{datetime.now().timestamp()}.xml"
            full_command = f"{command} -oX {output_file}"
        else:
            full_command = command

        try:
            process = await asyncio.create_subprocess_shell(
                full_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.config.scan_timeout,
            )

            # process.communicate() already waits for process to end
            # The return code is available via process.returncode
            exit_code = process.returncode
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            raw_output = b""
            if output_file and output_file.exists():
                raw_output = output_file.read_bytes()

            result = ScanResult(
                exit_code=exit_code,
                duration_ms=duration_ms,
                stdout=stdout_str,
                stderr=stderr_str,
                output_path=output_file,
                raw_output=raw_output,
            )

            logger.info(f"{scanner_name} completed: exit_code={exit_code}, duration={duration_ms}ms")
            return result

        except asyncio.TimeoutError:
            logger.warning(f"{scanner_name} timed out after {self.config.scan_timeout}s")
            return ScanResult(
                exit_code=-1,
                duration_ms=self.config.scan_timeout * 1000,
                stdout="",
                stderr="Scan timed out",
            )
        except Exception as e:
            logger.error(f"{scanner_name} failed: {e}")
            return ScanResult(
                exit_code=-1,
                duration_ms=int((datetime.now() - start_time).total_seconds() * 1000),
                stdout="",
                stderr=str(e),
            )

    def compare_results(
        self,
        rustnmap_result: ScanResult,
        nmap_result: ScanResult,
        expected_fields: list[str],
    ) -> dict[str, Any]:
        """Compare two scan results and return comparison data."""

        comparison = {
            "status": "PASS",
            "warnings": [],
            "errors": [],
            "metrics": {},
        }

        # Compare exit codes
        if rustnmap_result.exit_code != nmap_result.exit_code:
            comparison["errors"].append(
                f"Exit code mismatch: rustnmap={rustnmap_result.exit_code}, nmap={nmap_result.exit_code}"
            )
            comparison["status"] = "FAIL"

        # Both should succeed
        if not rustnmap_result.success or not nmap_result.success:
            if rustnmap_result.success and not nmap_result.success:
                comparison["warnings"].append("nmap failed but rustnmap succeeded")
            elif not rustnmap_result.success and nmap_result.success:
                comparison["errors"].append("rustnmap failed but nmap succeeded")
                comparison["status"] = "FAIL"
            else:
                comparison["errors"].append("Both scanners failed")
                comparison["status"] = "FAIL"

        # Compare port results
        rustnmap_ports = rustnmap_result.get_ports()
        nmap_ports = nmap_result.get_ports()

        if rustnmap_ports != nmap_ports:
            # Find differences
            rustnmap_only = set(rustnmap_ports.keys()) - set(nmap_ports.keys())
            nmap_only = set(nmap_ports.keys()) - set(rustnmap_ports.keys())

            if rustnmap_only:
                comparison["warnings"].append(f"Ports only in rustnmap: {rustnmap_only}")
            if nmap_only:
                comparison["warnings"].append(f"Ports only in nmap: {nmap_only}")

            # Compare states for common ports
            common_ports = set(rustnmap_ports.keys()) & set(nmap_ports.keys())
            state_mismatches = []

            for port in common_ports:
                if rustnmap_ports[port]["state"] != nmap_ports[port]["state"]:
                    state_mismatches.append(
                        f"{port}: rustnmap={rustnmap_ports[port]['state']}, "
                        f"nmap={nmap_ports[port]['state']}"
                    )

            if state_mismatches:
                comparison["errors"].append(f"State mismatches: {state_mismatches}")
                comparison["status"] = "FAIL"

        # Performance comparison
        comparison["metrics"] = {
            "rustnmap_duration_ms": rustnmap_result.duration_ms,
            "nmap_duration_ms": nmap_result.duration_ms,
            "speedup_factor": round(nmap_result.duration_ms / rustnmap_result.duration_ms, 2)
            if rustnmap_result.duration_ms > 0 else 0,
            "rustnmap_faster": rustnmap_result.duration_ms < nmap_result.duration_ms,
        }

        # Field validation
        for field in expected_fields:
            if field not in rustnmap_result.stdout:
                comparison["warnings"].append(f"Expected field '{field}' not found in rustnmap output")

        return comparison

    def compare_service_detection(
        self,
        rustnmap_result: ScanResult,
        nmap_result: ScanResult,
    ) -> dict[str, Any]:
        """Compare service detection results."""

        comparison = self.compare_results(rustnmap_result, nmap_result, ["SERVICE", "VERSION"])

        rustnmap_services = rustnmap_result.get_service_info()
        nmap_services = nmap_result.get_service_info()

        comparison["service_metrics"] = {
            "rustnmap_services_detected": len(rustnmap_services),
            "nmap_services_detected": len(nmap_services),
        }

        return comparison

    def compare_os_detection(
        self,
        rustnmap_result: ScanResult,
        nmap_result: ScanResult,
    ) -> dict[str, Any]:
        """Compare OS detection results."""

        comparison = self.compare_results(rustnmap_result, nmap_result, ["OS", "details"])

        rustnmap_os = rustnmap_result.get_os_info()
        nmap_os = nmap_result.get_os_info()

        comparison["os_metrics"] = {
            "rustnmap_os_detected": rustnmap_os["detected"],
            "nmap_os_detected": nmap_os["detected"],
            "rustnmap_os_matches": len(rustnmap_os["os_matches"]),
            "nmap_os_matches": len(nmap_os["os_matches"]),
        }

        return comparison
