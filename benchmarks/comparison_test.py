#!/usr/bin/env python3
"""
RustNmap vs Nmap Comparison Test Runner

Main test script that orchestrates comparison testing between rustnmap and nmap.
Loads configuration from .env file and test configuration TOML files.
"""

import argparse
import asyncio
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import toml
from dotenv import load_dotenv
from loguru import logger as loguru_logger

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from compare_scans import ScanComparator, ScanResult

# Remove default handler and configure loguru
loguru_logger.remove()
loguru_logger.add(
    sys.stdout,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
    level="INFO",
)

# Create log directory
log_dir = Path(__file__).parent / "logs"
log_dir.mkdir(exist_ok=True)

# Add file handler with rotation
loguru_logger.add(
    log_dir / "comparison_{time:YYYY-MM-DD_HH-mm-ss}.log",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
    level="DEBUG",
    rotation="100 MB",
    retention="7 days",
    compression="zip",
)

# Create logger alias for compatibility
logger = loguru_logger


@dataclass
class TestConfig:
    """Configuration for running comparison tests."""

    # Target configuration
    target_ip: str = "45.33.32.156"
    secondary_target_ip: str | None = None

    # Scanner paths
    rustnmap_release: str = "./target/release/rustnmap"
    rustnmap_debug: str = "./target/debug/rustnmap"
    nmap_binary: str = "/usr/bin/nmap"

    # Test configuration
    test_ports: str = "22,80,113,443,8080"
    test_port_range: str = "1-1024"
    test_top_ports: int = 100

    # Timing and performance
    scan_timeout: int = 300
    perf_iterations: int = 3

    # Output configuration
    reports_dir: str = "benchmarks/reports"
    report_format: str = "all"

    # Test flags
    enable_service_detection: bool = True
    enable_os_detection: bool = True
    enable_advanced_scans: bool = True

    @classmethod
    def from_env(cls, env_file: Path|None = None) -> "TestConfig":
        """Load configuration from .env file."""
        if env_file is None:
            env_file = Path(__file__).parent.parent / ".env"

        load_dotenv(env_file)

        import os

        # Resolve paths relative to project root
        project_root = Path(__file__).parent.parent

        def resolve_path(path_str: str) -> str:
            """Resolve path relative to project root if relative, otherwise keep as-is."""
            path = Path(path_str)
            if path.is_absolute():
                return path_str
            return str(project_root / path)

        return cls(
            target_ip=os.getenv("TEST_TARGET_IP", "45.33.32.156"),
            secondary_target_ip=os.getenv("TEST_TARGET_IP_2"),
            rustnmap_release=resolve_path(os.getenv("RUSTNMAP_RELEASE", "./target/release/rustnmap")),
            rustnmap_debug=resolve_path(os.getenv("RUSTNMAP_DEBUG", "./target/debug/rustnmap")),
            nmap_binary=os.getenv("NMAP_BINARY", "/usr/bin/nmap"),
            test_ports=os.getenv("TEST_PORTS", "22,80,113,443,8080"),
            test_port_range=os.getenv("TEST_PORT_RANGE", "1-1024"),
            test_top_ports=int(os.getenv("TEST_TOP_PORTS", "100")),
            scan_timeout=int(os.getenv("SCAN_TIMEOUT", "300")),
            perf_iterations=int(os.getenv("PERF_ITERATIONS", "3")),
            reports_dir=resolve_path(os.getenv("REPORTS_DIR", "benchmarks/reports")),
            report_format=os.getenv("REPORT_FORMAT", "all"),
            enable_service_detection=os.getenv("ENABLE_SERVICE_DETECTION", "true").lower() == "true",
            enable_os_detection=os.getenv("ENABLE_OS_DETECTION", "true").lower() == "true",
            enable_advanced_scans=os.getenv("ENABLE_ADVANCED_SCANS", "true").lower() == "true",
        )


@dataclass
class TestCaseResult:
    """Result of a single test case."""

    name: str
    description: str
    rustnmap_result: ScanResult
    nmap_result: ScanResult
    comparison_result: dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "rustnmap": {
                "exit_code": self.rustnmap_result.exit_code,
                "duration_ms": self.rustnmap_result.duration_ms,
                "stdout_lines": self.rustnmap_result.stdout_line_count,
                "stderr_lines": self.rustnmap_result.stderr_line_count,
                "output_path": str(self.rustnmap_result.output_path) if self.rustnmap_result.output_path else None,
            },
            "nmap": {
                "exit_code": self.nmap_result.exit_code,
                "duration_ms": self.nmap_result.duration_ms,
                "stdout_lines": self.nmap_result.stdout_line_count,
                "stderr_lines": self.nmap_result.stderr_line_count,
                "output_path": str(self.nmap_result.output_path) if self.nmap_result.output_path else None,
            },
            "comparison": self.comparison_result,
        }


@dataclass
class TestSuiteResult:
    """Result of a complete test suite."""

    name: str
    description: str
    category: str
    test_cases: list[TestCaseResult] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def total_tests(self) -> int:
        return len(self.test_cases)

    @property
    def passed_tests(self) -> int:
        return sum(1 for tc in self.test_cases if tc.comparison_result.get("status") == "PASS")

    @property
    def failed_tests(self) -> int:
        return sum(1 for tc in self.test_cases if tc.comparison_result.get("status") == "FAIL")

    @property
    def skipped_tests(self) -> int:
        return sum(1 for tc in self.test_cases if tc.comparison_result.get("status") == "SKIP")


class ComparisonTestRunner:
    """Main test runner for comparing rustnmap and nmap."""

    def __init__(self, config: TestConfig):
        self.config = config
        self.reports_dir = Path(config.reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        self.test_configs_dir = Path(__file__).parent / "test_configs"
        self.comparator = ScanComparator(config)

    def load_test_suite(self, config_file: Path) -> dict[str, Any]:
        """Load a test suite configuration from a TOML file."""
        return toml.load(config_file)

    async def run_test_suite(self, suite_config: dict[str, Any]) -> TestSuiteResult:
        """Run a complete test suite."""
        suite_name = suite_config["config"]["name"]
        suite_description = suite_config["config"]["description"]
        category = suite_config["config"]["category"]

        loguru_logger.info("="*60)
        loguru_logger.info(f"Test Suite: {suite_name}")
        loguru_logger.info(f"Description: {suite_description}")
        loguru_logger.info(f"Category: {category}")
        loguru_logger.info("="*60)

        result = TestSuiteResult(
            name=suite_name,
            description=suite_description,
            category=category,
        )

        for test_case in suite_config.get("test_case", []):
            loguru_logger.info(f"[Test Case] {test_case['name']}: {test_case['description']}")

            try:
                test_result = await self.run_test_case(test_case)
                result.test_cases.append(test_result)

                status = test_result.comparison_result.get("status", "UNKNOWN")
                loguru_logger.success(f"Status: {status}")

                if status == "PASS":
                    metrics = test_result.comparison_result.get("metrics", {})
                    loguru_logger.info(
                        f"Performance: rustnmap={metrics.get('rustnmap_duration_ms', 0)}ms, "
                        f"nmap={metrics.get('nmap_duration_ms', 0)}ms, "
                        f"speedup={metrics.get('speedup_factor', 0):.2f}x"
                    )
                elif status == "FAIL":
                    loguru_logger.warning(f"Test FAILED - see errors above")
                elif status == "SKIP":
                    loguru_logger.info(f"Test SKIPPED")

                # Immediately output this test case result
                self._output_test_case_result(test_result)

            except Exception as e:
                loguru_logger.error(f"Test case failed: {e}")
                result.test_cases.append(TestCaseResult(
                    name=test_case["name"],
                    description=test_case["description"],
                    rustnmap_result=ScanResult(exit_code=-1, duration_ms=0, stdout="", stderr=""),
                    nmap_result=ScanResult(exit_code=-1, duration_ms=0, stdout="", stderr=""),
                    comparison_result={"status": "ERROR", "error": str(e)},
                ))

        # Output suite summary
        self._output_suite_summary(result)

        return result

    def _output_test_case_result(self, test_result: TestCaseResult):
        """Immediately output a single test case result."""
        status = test_result.comparison_result.get("status", "UNKNOWN")
        metrics = test_result.comparison_result.get("metrics", {})

        loguru_logger.info("-" * 50)
        loguru_logger.info(f"[{status}] {test_result.name}")
        loguru_logger.info(f"  Description: {test_result.description}")

        # Performance data
        if metrics:
            rustnmap_ms = metrics.get('rustnmap_duration_ms', 0)
            nmap_ms = metrics.get('nmap_duration_ms', 0)
            speedup = metrics.get('speedup_factor', 0)

            if speedup >= 1.0:
                loguru_logger.success(f"  Speed: {speedup:.2f}x faster (rustnmap={rustnmap_ms}ms, nmap={nmap_ms}ms)")
            elif speedup > 0:
                loguru_logger.warning(f"  Speed: {speedup:.2f}x slower (rustnmap={rustnmap_ms}ms, nmap={nmap_ms}ms)")

        # Warnings
        warnings = test_result.comparison_result.get("warnings", [])
        if warnings:
            loguru_logger.warning(f"  Warnings ({len(warnings)}):")
            for warning in warnings:
                loguru_logger.warning(f"    - {warning}")

        # Errors
        errors = test_result.comparison_result.get("errors", [])
        if errors:
            loguru_logger.error(f"  Errors ({len(errors)}):")
            for error in errors:
                loguru_logger.error(f"    - {error}")

    def _output_suite_summary(self, result: TestSuiteResult):
        """Output suite summary after all tests in suite complete."""
        loguru_logger.info("="*50)
        loguru_logger.info(f"Suite Summary: {result.name}")
        loguru_logger.info(f"  Total: {result.total_tests}, Passed: {result.passed_tests}, Failed: {result.failed_tests}")
        if result.passed_tests == result.total_tests:
            loguru_logger.success("All tests PASSED")
        elif result.failed_tests > 0:
            loguru_logger.error(f"{result.failed_tests} test(s) FAILED")

    def _translate_nmap_to_rustnmap(self, command: str) -> str:
        """Translate nmap command flags to rustnmap flags."""
        # Flag translation mapping
        flag_map = {
            "-sS": "--scan-syn",
            "-sT": "--scan-connect",
            "-sU": "--scan-udp",
            "-sF": "--scan-fin",
            "-sN": "--scan-null",
            "-sX": "--scan-xmas",
            "-sM": "--scan-maimon",
            "-sA": "--scan-ack",  # If supported
            "-sW": "--scan-window",  # If supported
            "-sI": "--scan-idle",  # If supported
            "-sO": "--scan-ip-protocol",  # If supported
            "-sV": "--service-detection",
            "-O": "--os-detection",
            "-F": "--fast-scan",
            "-v": "--verbose",
            "-oX": "--output-xml",
            "-oG": "--output-grepable",
            "-oN": "--output-normal",
            "--output-json": "--output-json",
            "-T0": "--timing 0",
            "-T1": "--timing 1",
            "-T2": "--timing 2",
            "-T3": "--timing 3",
            "-T4": "--timing 4",
            "-T5": "--timing 5",
            "--min-rate": "--min-rate",
            "--max-rate": "--max-rate",
            "--host-timeout": "--host-timeout",
            "--exclude-port": "--exclude-port",
        }

        result = command
        for nmap_flag, rustnmap_flag in flag_map.items():
            # Replace whole flags, not substrings
            import re
            result = re.sub(rf"(?<![\w-]){re.escape(nmap_flag)}(?![\w-])", rustnmap_flag, result)

        return result

    async def run_test_case(self, test_case: dict[str, Any]) -> TestCaseResult:
        """Run a single test case comparing rustnmap and nmap."""

        # Prepare command templates
        template = test_case["command_template"]

        # Run with nmap (use template as-is)
        nmap_cmd = template.format(
            scanner="sudo " + self.config.nmap_binary,
            target=self.config.target_ip,
            ports=self.config.test_ports,
            port_range=self.config.test_port_range,
            top_ports=self.config.test_top_ports,
        )

        # Run with rustnmap (translate flags)
        rustnmap_template = self._translate_nmap_to_rustnmap(template)
        rustnmap_cmd = rustnmap_template.format(
            scanner="sudo " + self.config.rustnmap_release,
            target=self.config.target_ip,
            ports=self.config.test_ports,
            port_range=self.config.test_port_range,
            top_ports=self.config.test_top_ports,
        )

        loguru_logger.debug(f"rustnmap command: {rustnmap_cmd}")
        loguru_logger.debug(f"nmap command: {nmap_cmd}")

        # Execute scans
        rustnmap_result = await self.comparator.run_scan(rustnmap_cmd, "rustnmap")
        nmap_result = await self.comparator.run_scan(nmap_cmd, "nmap")

        # Compare results
        comparison = self.comparator.compare_results(
            rustnmap_result,
            nmap_result,
            test_case.get("expected_fields", []),
            test_case.get("expected_differences"),
        )

        return TestCaseResult(
            name=test_case["name"],
            description=test_case["description"],
            rustnmap_result=rustnmap_result,
            nmap_result=nmap_result,
            comparison_result=comparison,
        )

    async def run_all_tests(self) -> list[TestSuiteResult]:
        """Run all configured test suites."""
        results = []

        # Load all test configuration files (including new test suites)
        config_files = [
            self.test_configs_dir / "basic_scan.toml",
            self.test_configs_dir / "service_detection.toml",
            self.test_configs_dir / "os_detection.toml",
            self.test_configs_dir / "advanced_scan.toml",
            self.test_configs_dir / "timing_tests.toml",
            self.test_configs_dir / "output_formats.toml",
            self.test_configs_dir / "multi_target.toml",
            self.test_configs_dir / "stealth_extended.toml",
        ]

        for config_file in config_files:
            if not config_file.exists():
                loguru_logger.warning(f"Test config file not found: {config_file}")
                continue

            # Check if we should skip this suite
            suite_config = self.load_test_suite(config_file)
            category = suite_config["config"]["category"]

            if category == "detection":
                if "service" in suite_config["config"]["name"].lower() and not self.config.enable_service_detection:
                    loguru_logger.info(f"Skipping {suite_config['config']['name']} (service detection disabled)")
                    continue
                if "os" in suite_config["config"]["name"].lower() and not self.config.enable_os_detection:
                    loguru_logger.info(f"Skipping {suite_config['config']['name']} (OS detection disabled)")
                    continue

            if category == "advanced" and not self.config.enable_advanced_scans:
                loguru_logger.info(f"Skipping {suite_config['config']['name']} (advanced scans disabled)")
                continue

            # New categories - always enabled for comprehensive testing
            if category in ("timing", "output", "multi_target"):
                loguru_logger.info(f"Running {suite_config['config']['name']} ({category} test)")

            suite_result = await self.run_test_suite(suite_config)
            results.append(suite_result)

        return results

    def generate_reports(self, results: list[TestSuiteResult]) -> list[Path]:
        """Generate comparison reports."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_paths = []

        # Generate requested format(s)
        formats = ["all"] if self.config.report_format == "all" else [self.config.report_format]

        for fmt in formats:
            if fmt in ("text", "all"):
                path = self._generate_text_report(results, timestamp)
                report_paths.append(path)

            if fmt in ("json", "all"):
                path = self._generate_json_report(results, timestamp)
                report_paths.append(path)

        return report_paths

    def _generate_text_report(self, results: list[TestSuiteResult], timestamp: str) -> Path:
        """Generate a text format comparison report."""
        report_path = self.reports_dir / f"comparison_report_{timestamp}.txt"

        with open(report_path, "w") as f:
            f.write("=" * 80 + "\n")
            f.write("RustNmap vs Nmap Comparison Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")

            # Summary
            total_tests = sum(r.total_tests for r in results)
            passed_tests = sum(r.passed_tests for r in results)
            failed_tests = sum(r.failed_tests for r in results)

            f.write("SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total Tests: {total_tests}\n")
            f.write(f"Passed: {passed_tests}\n")
            f.write(f"Failed: {failed_tests}\n")
            f.write(f"Success Rate: {passed_tests / total_tests * 100:.1f}%\n\n")

            # Detailed results
            for suite in results:
                f.write(f"\n{'='*80}\n")
                f.write(f"Test Suite: {suite.name}\n")
                f.write(f"Description: {suite.description}\n")
                f.write(f"{'='*80}\n")

                for test_case in suite.test_cases:
                    f.write(f"\n[{test_case.comparison_result.get('status', 'UNKNOWN')}] {test_case.name}\n")
                    f.write(f"Description: {test_case.description}\n")

                    metrics = test_case.comparison_result.get("metrics", {})
                    f.write("Performance:\n")
                    f.write(f"  rustnmap: {metrics.get('rustnmap_duration_ms', 0)}ms\n")
                    f.write(f"  nmap: {metrics.get('nmap_duration_ms', 0)}ms\n")
                    f.write(f"  speedup: {metrics.get('speedup_factor', 0)}x\n")

                    warnings = test_case.comparison_result.get("warnings", [])
                    if warnings:
                        f.write("Warnings:\n")
                        for warning in warnings:
                            f.write(f"  - {warning}\n")

                    errors = test_case.comparison_result.get("errors", [])
                    if errors:
                        f.write("Errors:\n")
                        for error in errors:
                            f.write(f"  - {error}\n")

        loguru_logger.info(f"Text report generated: {report_path}")
        return report_path

    def _generate_json_report(self, results: list[TestSuiteResult], timestamp: str) -> Path:
        """Generate a JSON format comparison report."""
        import json

        report_path = self.reports_dir / f"comparison_report_{timestamp}.json"

        report_data = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_tests": sum(r.total_tests for r in results),
                "passed_tests": sum(r.passed_tests for r in results),
                "failed_tests": sum(r.failed_tests for r in results),
            },
            "test_suites": [],
        }

        for suite in results:
            suite_data = {
                "name": suite.name,
                "description": suite.description,
                "category": suite.category,
                "total_tests": suite.total_tests,
                "passed_tests": suite.passed_tests,
                "failed_tests": suite.failed_tests,
                "test_cases": [tc.to_dict() for tc in suite.test_cases],
            }
            report_data["test_suites"].append(suite_data)

        with open(report_path, "w") as f:
            json.dump(report_data, f, indent=2)

        loguru_logger.info(f"JSON report generated: {report_path}")
        return report_path


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Compare rustnmap and nmap functionality and performance"
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to .env configuration file",
    )
    parser.add_argument(
        "--target",
        help="Override target IP address",
    )
    parser.add_argument(
        "--suite",
        help="Run specific test suite (basic, service, os, advanced, timing, output, multi, stealth)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "all"],
        default="all",
        help="Report format (default: all)",
    )
    parser.add_argument(
        "--no-service-detection",
        action="store_true",
        help="Disable service detection tests",
    )
    parser.add_argument(
        "--no-os-detection",
        action="store_true",
        help="Disable OS detection tests",
    )
    parser.add_argument(
        "--no-advanced-scans",
        action="store_true",
        help="Disable advanced scan tests",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output (DEBUG level)",
    )

    args = parser.parse_args()

    if args.verbose:
        loguru_logger.remove()
        loguru_logger.add(
            sys.stdout,
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
            level="DEBUG",
        )
        loguru_logger.add(
            log_dir / "comparison_{time:YYYY-MM-DD_HH-mm-ss}.log",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
            level="DEBUG",
            rotation="100 MB",
            retention="7 days",
            compression="zip",
        )

    # Load configuration
    config = TestConfig.from_env(args.config)

    # Apply command line overrides
    if args.target:
        config.target_ip = args.target
    if args.no_service_detection:
        config.enable_service_detection = False
    if args.no_os_detection:
        config.enable_os_detection = False
    if args.no_advanced_scans:
        config.enable_advanced_scans = False
    config.report_format = args.format

    # Verify binaries exist
    for binary in [config.rustnmap_release, config.nmap_binary]:
        if not Path(binary).exists():
            loguru_logger.error(f"Binary not found: {binary}")
            sys.exit(1)

    # Create test runner
    runner = ComparisonTestRunner(config)

    # Run tests
    if args.suite:
        suite_map = {
            "basic": "basic_scan.toml",
            "service": "service_detection.toml",
            "os": "os_detection.toml",
            "advanced": "advanced_scan.toml",
            "timing": "timing_tests.toml",
            "output": "output_formats.toml",
            "multi": "multi_target.toml",
            "stealth": "stealth_extended.toml",
        }
        config_file = runner.test_configs_dir / suite_map.get(args.suite, args.suite + ".toml")
        if not config_file.exists():
            loguru_logger.error(f"Test suite not found: {config_file}")
            sys.exit(1)

        suite_config = runner.load_test_suite(config_file)
        results = [await runner.run_test_suite(suite_config)]
    else:
        results = await runner.run_all_tests()

    # All tests complete, generate final summary
    loguru_logger.info("="*60)
    loguru_logger.info("All Tests Complete")
    loguru_logger.info("="*60)

    # Generate reports
    loguru_logger.info("")
    loguru_logger.info("Generating final reports...")
    report_paths = runner.generate_reports(results)

    # Final summary
    total_tests = sum(r.total_tests for r in results)
    passed_tests = sum(r.passed_tests for r in results)
    failed_tests = sum(r.failed_tests for r in results)
    success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0

    loguru_logger.info("="*60)
    loguru_logger.info(f"Final: {total_tests} tests | {passed_tests} passed | {failed_tests} failed | {success_rate:.1f}%")
    loguru_logger.info("="*60)

    if failed_tests > 0:
        loguru_logger.warning("Failed test suites:")
        for result in results:
            if result.failed_tests > 0:
                loguru_logger.warning(f"  - {result.name}: {result.failed_tests} failed")
        sys.exit(1)
    else:
        loguru_logger.success("All tests PASSED!")

    loguru_logger.info("Reports generated:")
    for path in report_paths:
        loguru_logger.info(f"  - {path}")

    sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
