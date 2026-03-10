# CLI Compatibility Audit Summary

> **Date**: 2026-03-09 22:10
> **Status**: Audit Complete, Implementation Pending

## Executive Summary

**Problem**: RustNmap CLI is missing **50+ command-line options** that nmap users expect.

**User Impact**: Users cannot use familiar nmap short options like `-Pn`, `-sV`, `-sC`, `-oN`, etc.

**Critical Missing Options (P0)**:
1. `-Pn` - Skip host discovery (CRITICAL - used daily)
2. `-sV` - Service version detection (CRITICAL - used daily)
3. `-sC` - Default scripts (CRITICAL - used daily)
4. `-oN/-oX/-oG/-oA` - Output file short options (HIGH - scripting)
5. `-n/-R` - DNS control (HIGH - automation)
6. `--exclude-ports` - Currently wrong name (`--exclude-port`)

## Statistics

| Category | Missing | Total | Complete |
|----------|---------|-------|----------|
| Short Options | 17 | 50 | 66% |
| Long Options | 35 | 80 | 56% |
| **Overall** | **52** | **130** | **60%** |

## Implementation Priority

### Phase 1: Critical Short Options (1-2 hours)
- Add `-Pn` for `--disable-ping`
- Add `-sV` for `--service-detection`
- Add `-sC` for default scripts
- Add `-oN`, `-oX`, `-oG`, `-oA` output options
- Add `-n`, `-R` DNS options
- Fix `--exclude-port` → `--exclude-ports`

### Phase 2: Host Discovery Options (2-3 hours)
- Add `-PS`, `-PA`, `-PU`, `-PY` TCP/UDP/SCTP discovery probes
- Add `-PE`, `-PP`, `-PM` ICMP discovery probes
- Add `-PO` IP Protocol Ping
- Add `-sL` List Scan
- Add `-sn` Ping Scan
- Add `--dns-servers`, `--system-dns`
- Add `--traceroute`

### Phase 3: Timing & Evasion Options (3-4 hours)
- Add `--min-rtt-timeout`, `--max-rtt-timeout`, `--initial-rtt-timeout`
- Add `--max-retries`, `--host-timeout`, `--max-scan-delay`
- Add `--proxies`, `--ip-options`, `--ttl`, `--spoof-mac`, `--badsum`
- Add `-r` sequential scan (note: nmap's -r means sequential, not random)

### Phase 4: Helper & Misc Options (1-2 hours)
- Add `--version-light`, `--version-all`, `--version-trace`
- Add `--script-trace`, `--script-args-file`
- Add `--privileged`, `--unprivileged`
- Add `-6` IPv6 support
- Add `--stylesheet`, `--webxml`, `--no-stylesheet`, `--noninteractive`

### Phase 5: Advanced Scans (Future)
- Add `-sI` Idle Scan
- Add `-sY`, `-sZ` SCTP scans
- Add `-sO` IP Protocol scan
- Add `-b` FTP Bounce scan

## Files to Modify

1. **`crates/rustnmap-cli/src/args.rs`** (850 lines)
   - Add short option attributes
   - Add new long option fields
   - Fix option names

2. **`crates/rustnmap-cli/src/cli.rs`** (2700+ lines)
   - Wire new options to ScanConfig
   - Handle new logic (DNS control, discovery probes, etc.)

3. **`crates/rustnmap-core/src/session.rs`**
   - Add new ScanConfig fields if needed

## Success Criteria

- ✅ All nmap short options work
- ✅ All nmap long options work (P0-P3)
- ✅ `rustnmap -Pn` works
- ✅ `rustnmap -sV` works
- ✅ `rustnmap -sC` works
- ✅ `rustnmap -oN/-oX/-oG/-oA` work
- ✅ `cargo test -p rustnmap-cli` passes
- ✅ `cargo clippy -p rustnmap-cli -- -D warnings` passes
- ✅ Zero warnings, zero errors

## Documentation

- **Task Plan**: `task_plan.md` - Workstream: CLI Compatibility Enhancement
- **Findings**: `findings.md` - CLI COMPATIBILITY AUDIT section
- **This Summary**: `cli_audit_summary.md`

## Next Steps

1. Review and approve this audit
2. Implement Phase 1 (Critical Short Options)
3. Test Phase 1 thoroughly
4. Implement Phase 2 (Host Discovery)
5. Continue with remaining phases

---

**Total Estimated Time**: 10-15 hours for full P0-P3 implementation
**Phase 1 (Critical)**: 1-2 hours - Can be done immediately
