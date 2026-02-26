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
from typing import Any

import lxml.etree as ET

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of a scan execution."""

    exit_code: int
    duration_ms: int
    stdout: str
    stderr: str
    output_path: Path | None = None
    raw_output: bytes = b""
    hidden_closed_count: int = 0

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
        hidden_closed_count = 0

        # Try parsing normal output format
        lines = self.stdout.split("\n")
        in_port_section = False

        for line in lines:
            line = line.strip()

            # Parse "Not shown: X closed ports" line (nmap format)
            if "Not shown:" in line and "closed ports" in line:
                import re
                match = re.search(r'Not shown:\s*(\d+)\s+closed ports?', line)
                if match:
                    hidden_closed_count = int(match.group(1))
                continue

            # Detect port section - handle both "PORT" and "STATE" on same line
            if "PORT" in line and "STATE" in line:
                in_port_section = True
                continue

            # Exit port section on blank line, summary line, or non-port content
            if in_port_section:
                if not line:
                    in_port_section = False
                    continue
                if "done:" in line.lower() or "scanned in" in line.lower():
                    break
                # Exit on OS detection, service info, traceroute, or other sections
                if line.startswith(("=", "|", "_", "OS ", "Service Info:",
                                    "Device type:", "Running:", "Aggressive",
                                    "Network Distance:", "TRACEROUTE", "HOP",
                                    "No exact OS", "Too many fingerprints")):
                    in_port_section = False
                    continue

                # Parse port line: PORT    STATE    SERVICE
                # Example: 22/tcp  open  ssh
                parts = line.split()
                if len(parts) >= 2:
                    port_proto = parts[0]
                    # Validate port format: must be number/protocol
                    if "/" in port_proto and port_proto.split("/")[0].isdigit():
                        state = parts[1]
                        service = parts[2] if len(parts) > 2 else "unknown"
                        ports[port_proto] = {
                            "state": state,
                            "service": service,
                        }
                    else:
                        # Not a port line, exit port section
                        in_port_section = False

        # Store hidden closed count for comparison
        self.hidden_closed_count = hidden_closed_count
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
            # Updated format may include version info after service name
            if "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    # Look for common service names
                    common_services = ["ssh", "http", "https", "ftp", "telnet", "smtp", "dns", "pop3", "imap"]
                    if any(svc in line.lower() for svc in common_services):
                        service_info = {
                            "port": parts[0],
                            "state": parts[1],
                            "service": parts[2],
                        }
                        if len(parts) >= 4:
                            service_info["version"] = " ".join(parts[3:])
                        services.append(service_info)

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

            # Handle both nmap and rustnmap OS detection output formats
            if "OS details" in line or "Running" in line or "OS guesses" in line:
                os_info["detected"] = True
                in_os_section = True
                # Extract OS info
                if "OS details:" in line:
                    os_str = line.split("OS details:")[-1].strip()
                    os_info["os_matches"].append(os_str)
                elif "Running:" in line:
                    os_str = line.split("Running:")[-1].strip()
                    os_info["os_matches"].append(os_str)

            if in_os_section and ("OS CPE:" in line or "OS guess" in line):
                cpe = line.split("OS CPE:")[-1].strip() if "OS CPE:" in line else ""
                guess = line.split("OS guess")[-1].strip() if "OS guess" in line else ""
                if cpe and os_info["os_matches"]:
                    os_info["os_matches"][-1] += f" (CPE: {cpe})"
                if guess:
                    os_info["os_matches"].append(guess)

            # Exit OS section when we hit other sections
            if in_os_section and ("PORT" in line or "Service detection" in line):
                break

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
        full_command = command

        # Extract output file path from command if present
        # Supports -oX, --output-xml, -oG, --output-grepable, --output-json
        import shlex
        parts = shlex.split(command)
        for i, part in enumerate(parts):
            if part in ("-oX", "--output-xml", "-oG", "--output-grepable", "--output-json"):
                if i + 1 < len(parts):
                    output_file = Path(parts[i + 1])
                    break
            elif part.startswith("-oX=") or part.startswith("--output-xml="):
                output_file = Path(part.split("=", 1)[1])
                break
            elif part.startswith("--output-json="):
                output_file = Path(part.split("=", 1)[1])
                break

        # For backward compatibility, if use_xml_output is True and no output file specified
        if use_xml_output and output_file is None:
            output_file = self.temp_dir / f"{scanner_name}_{datetime.now().timestamp()}.xml"
            full_command = f"{command} -oX {output_file}"

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
                output_path=output_file,
            )
        except Exception as e:
            logger.error(f"{scanner_name} failed: {e}")
            return ScanResult(
                exit_code=-1,
                duration_ms=int((datetime.now() - start_time).total_seconds() * 1000),
                stdout="",
                stderr=str(e),
                output_path=output_file,
            )

    def compare_results(
        self,
        rustnmap_result: ScanResult,
        nmap_result: ScanResult,
        expected_fields: list[str],
        expected_differences: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Compare two scan results and return comparison data.

        Args:
            rustnmap_result: Result from rustnmap scan
            nmap_result: Result from nmap scan
            expected_fields: List of fields expected in output
            expected_differences: Dict of documented expected differences between scanners
                Supported keys:
                - "allow_nmap_failure": bool - nmap may fail while rustnmap succeeds
                - "state_remaps": dict - Maps port/proto to allowed state differences
                    Format: {"22/udp": {"rustnmap": "closed", "nmap": "open|filtered"}}
        """

        comparison = {
            "status": "PASS",
            "warnings": [],
            "errors": [],
            "metrics": {},
            "expected_differences_applied": [],
        }

        # Default expected differences (P2 documented differences)
        default_expected_diffs = {
            "state_remaps": {
                "22/udp": {"rustnmap": "closed", "nmap": "open|filtered"},
                "53/udp": {"rustnmap": "closed", "nmap": "open|filtered"},
                "123/udp": {"rustnmap": "closed", "nmap": "open|filtered"},
            }
        }

        # Merge expected differences
        if expected_differences:
            if "state_remaps" in expected_differences:
                default_expected_diffs["state_remaps"].update(
                    expected_differences["state_remaps"]
                )

        # Compare exit codes
        if rustnmap_result.exit_code != nmap_result.exit_code:
            # Check if this is an expected difference (nmap timeout/failure)
            allow_nmap_failure = (
                expected_differences.get("allow_nmap_failure", False)
                if expected_differences
                else False
            )

            if allow_nmap_failure and rustnmap_result.success and not nmap_result.success:
                comparison["warnings"].append(
                    f"Expected difference: nmap failed (exit={nmap_result.exit_code}) "
                    f"but rustnmap succeeded (exit={rustnmap_result.exit_code})"
                )
                comparison["expected_differences_applied"].append("nmap_failure_allowed")
            else:
                comparison["errors"].append(
                    f"Exit code mismatch: rustnmap={rustnmap_result.exit_code}, nmap={nmap_result.exit_code}"
                )
                comparison["status"] = "FAIL"

        # Both should succeed
        if not rustnmap_result.success or not nmap_result.success:
            if rustnmap_result.success and not nmap_result.success:
                if not comparison["expected_differences_applied"]:
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

            # Nmap hides closed ports by default - filter them out from rustnmap_only
            # if nmap has hidden closed ports count
            if rustnmap_only and nmap_result.hidden_closed_count > 0:
                # Get actual closed ports from rustnmap that nmap would hide
                hidden_closed_in_nmap = {
                    p for p in rustnmap_only
                    if rustnmap_ports[p]["state"] == "closed"
                }
                # These are expected to be hidden by nmap, not real differences
                rustnmap_only -= hidden_closed_in_nmap
                if hidden_closed_in_nmap:
                    comparison["expected_differences_applied"].append(
                        f"nmap_hides_closed_ports ({len(hidden_closed_in_nmap)} ports)"
                    )

            if rustnmap_only:
                comparison["warnings"].append(f"Ports only in rustnmap: {rustnmap_only}")
            if nmap_only:
                comparison["warnings"].append(f"Ports only in nmap: {nmap_only}")

            # Compare states for common ports
            common_ports = set(rustnmap_ports.keys()) & set(nmap_ports.keys())
            state_mismatches = []
            state_diffs_expected = []

            for port in common_ports:
                rustnmap_state = rustnmap_ports[port]["state"]
                nmap_state = nmap_ports[port]["state"]

                # Check if this is an expected state difference
                expected_remap = default_expected_diffs["state_remaps"].get(port)
                is_expected_diff = (
                    expected_remap is not None
                    and expected_remap.get("rustnmap") == rustnmap_state
                    and expected_remap.get("nmap") == nmap_state
                )

                if rustnmap_state != nmap_state:
                    if is_expected_diff:
                        state_diffs_expected.append(
                            f"{port}: rustnmap={rustnmap_state}, nmap={nmap_state} (documented difference)"
                        )
                    else:
                        state_mismatches.append(
                            f"{port}: rustnmap={rustnmap_state}, nmap={nmap_state}"
                        )

            if state_diffs_expected:
                comparison["warnings"].append(
                    f"Expected state differences: {state_diffs_expected}"
                )
                comparison["expected_differences_applied"].append("state_remaps")

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

        # Field validation - check stdout and output files
        output_to_check = rustnmap_result.stdout

        # If output file exists, read its contents for validation
        if rustnmap_result.output_path and rustnmap_result.output_path.exists():
            try:
                with open(rustnmap_result.output_path, 'r', encoding='utf-8', errors='replace') as f:
                    output_to_check = f.read()
            except Exception as e:
                logger.warning(f"Failed to read output file: {e}")

        for field in expected_fields:
            if field not in output_to_check:
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
