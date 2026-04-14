# RustNmap 2.0 Changelog

> **RustNmap 2.0 Documentation Change Log**

This document tracks all documentation changes during the RustNmap 2.0 development process.

---

## Version 2.0.0 (In Development)

**Target Release Date**: TBD

### New Features

#### 2026-03-10: CLI Migration to lexopt ✅

| Change | Status | Documentation Impact |
|------|------|---------|
| Migrated from clap to lexopt | ✅ Complete | Updated `architecture.md`, `structure.md` |
| Added CLI module documentation | ✅ Complete | Added `modules/cli.md` |
| Compound short options support (-sS -sV -sC) | ✅ Complete | Updated related options documentation |
| Output format compound options (-oN/-oX/-oG/-oA) | ✅ Complete | Updated output format documentation |
| Binary size reduced by 12% | ✅ Complete | Updated performance metrics |

**Key Changes:**
- Removed dependency: `clap = { version = "4.5", features = ["derive", "wrap_help", "cargo"] }`
- Added dependency: `lexopt = "0.3"`
- Added file: `crates/rustnmap-cli/src/help.rs` (manual help system, 170 lines)
- Refactored file: `crates/rustnmap-cli/src/args.rs` (~1100 lines rewritten)

**Nmap Compatibility Improvements:**
- ✅ `-sS -sV -sC -T4` fully compatible
- ✅ `-oN file`, `-oX file`, `-oG file`, `-oA basename` fully compatible
- ✅ `-Pn` host discovery option fully compatible
- ✅ All T0-T5 timing templates fully compatible

**Detailed Documentation:** See `LEXOPT_MIGRATION_COMPLETE.md` and `doc/modules/cli.md`

#### Phase 0: Baseline Fixes (Week 1-2)

| Feature | Status | Documentation Impact |
|------|------|---------|
| Host Discovery actual implementation | Not started | Update `modules/host-discovery.md` |
| `scan_types` execution pipeline integration | Not started | Update `modules/port-scanning.md` |
| OutputSink connected to output system | Not started | Update `modules/output.md`, `manual/output-formats.md` |
| ResumeStore minimum viable version | Not started | Add `--resume` option documentation |

#### Phase 1: User Experience and Pipeline Friendliness (Week 3-4)

| Feature | Status | Documentation Impact |
|------|------|---------|
| Streaming output (host-level) | Not started | Add `--stream` option documentation |
| NDJSON Pipeline output | Not started | Update `manual/output-formats.md` |
| Shell completion scripts | Not started | Update `manual/options.md` |
| Markdown reports | Not started | Add `-oM` option documentation |

#### Phase 2: Vulnerability Intelligence Main Pipeline (Week 5-7)

| Feature | Status | Documentation Impact |
|------|------|---------|
| CVE/CPE correlation engine | Not started | Add `modules/vulnerability.md` |
| EPSS/KEV aggregation and risk ranking | Not started | Update `manual/options.md` |
| HTML reports | Not started | Add `manual/html-report.md` |
| SARIF format | Not started | Update `manual/output-formats.md` |

#### Phase 3: Scan Management Capabilities (Week 8-9)

| Feature | Status | Documentation Impact |
|------|------|---------|
| Scan result persistence (SQLite) | Not started | Add `modules/scan-management.md` |
| Scan Diff | Not started | Add `--diff` option documentation |
| Configuration as code (YAML Profile) | Not started | Add `manual/profiles.md` |
| `--history` query capability | Not started | Update `manual/options.md` |

#### Phase 4: Performance Backbone Optimization (Week 10-11)

| Feature | Status | Documentation Impact |
|------|------|---------|
| Two-phase scanning (discovery + detailed scan) | Not started | Update `modules/port-scanning.md` |
| Adaptive batch size | Not started | Update `modules/concurrency.md` |
| Stateless fast scanning (experimental feature) | Not started | Add `modules/stateless-scan.md` |

#### Phase 5: Platform Minimal Closed Loop (Week 12)

| Feature | Status | Documentation Impact |
|------|------|---------|
| REST API / Daemon (minimal set) | Not started | Add `modules/rest-api.md` |
| Rust SDK (stable Builder API) | Not started | Add `modules/sdk.md` |

---

## Documentation Status

### Core Documentation

| Document | 1.0 Status | 2.0 Update | Owner |
|------|---------|---------|--------|
| `README.md` | Marked | Pending update | - |
| `architecture.md` | Current | Pending update | - |
| `structure.md` | Current | Pending update | - |
| `user-guide.md` | Marked | Pending update | - |

### User Manual

| Document | 1.0 Status | 2.0 Update | Owner |
|------|---------|---------|--------|
| `manual/README.md` | Marked | Pending update | - |
| `manual/options.md` | Marked | Pending update | - |
| `manual/quick-reference.md` | Marked | Pending update | - |
| `manual/scan-types.md` | Marked | Pending update | - |
| `manual/output-formats.md` | Marked | Pending update | - |
| `manual/nse-scripts.md` | Marked | Pending update | - |
| `manual/exit-codes.md` | Marked | Pending update | - |
| `manual/environment.md` | Marked | Pending update | - |
| `manual/configuration.md` | Marked | Pending update | - |

### Module Documentation

| Document | 1.0 Status | 2.0 Update | Owner |
|------|---------|---------|--------|
| `modules/host-discovery.md` | Current | Pending update | - |
| `modules/port-scanning.md` | Current | Pending update | - |
| `modules/service-detection.md` | Current | Pending update | - |
| `modules/os-detection.md` | Current | Pending update | - |
| `modules/nse-engine.md` | Current | Pending update | - |
| `modules/traceroute.md` | Current | Pending update | - |
| `modules/evasion.md` | Current | Pending update | - |
| `modules/output.md` | Current | Pending update | - |
| `modules/target-parsing.md` | Current | Pending update | - |
| `modules/raw-packet.md` | Current | Pending update | - |
| `modules/concurrency.md` | Current | Pending update | - |

### New Documentation (2.0)

| Document | Topic | Status | Owner |
|------|------|------|--------|
| `modules/vulnerability.md` | Vulnerability intelligence module | To be created | - |
| `modules/rest-api.md` | REST API module | To be created | - |
| `modules/sdk.md` | Rust SDK module | To be created | - |
| `modules/scan-management.md` | Scan management module | To be created | - |
| `modules/stateless-scan.md` | Stateless scanning module | To be created | - |
| `manual/profiles.md` | Configuration as code guide | To be created | - |
| `manual/html-report.md` | HTML report guide | To be created | - |

---

## Version Marking

During RustNmap 2.0 development, all 1.0 documents have been tagged with a version banner:

```markdown
> **Version**: 1.0.0
> **Status**: This document describes RustNmap 1.0.0 features. Version 2.0 is under development, see [CHANGELOG.md](CHANGELOG.md).
```

When 2.0 features are complete, the corresponding document version tag will be updated to:

```markdown
> **Version**: 2.0.0
> **Status**: This document describes RustNmap 2.0.0 features.
```

---

## Related Links

- [RETHINK.md](../RETHINK.md) - RustNmap 2.0 Evolution Roadmap
- [Project README](../README.md) - Project Overview
- [GitHub Repository](https://github.com/greatwallisme/rust-nmap) - Code Repository

---

**Last Updated**: 2026-02-17
