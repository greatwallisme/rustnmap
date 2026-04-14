# Task Plan: English-Only doc/ + Chinese zh_doc/

## Goal
1. All content in `doc/` must be in English only
2. Create `zh_doc/` as a Chinese translation mirror of `doc/`

## Approach
- Step 1: Copy `doc/` to `zh_doc/` (preserves Chinese originals)
- Step 2: Translate all Chinese content in `doc/` files to English
- Step 3: Verify no Chinese remains in `doc/`

## File Inventory (38 files with Chinese, 5 already English)

### Already English (skip translation)
- database-integration.md
- modules/cli.md
- modules/nse-libraries.md
- manual/README.md (mostly, minor Chinese)

### Files to Translate (grouped by directory)

**Root level** (5 files):
- README.md (83 lines CN)
- CHANGELOG.md (107)
- architecture.md (314)
- database.md (63)
- roadmap.md (226)
- structure.md (105)

**appendix/** (5 files):
- deployment.md (78)
- nmap-constants.md (109)
- nmap-data-structures.md (278)
- nmap-function-reference.md (107)
- references.md (4)

**manual/** (8 files):
- README.md (33)
- configuration.md (84)
- environment.md (167)
- exit-codes.md (72)
- nse-scripts.md (170)
- options.md (165)
- output-formats.md (132)
- quick-reference.md (100)
- scan-types.md (202)

**modules/** (19 files):
- concurrency.md (83)
- evasion.md (71)
- host-discovery.md (15)
- localhost-scanning.md (142)
- nse-engine.md (236)
- os-detection.md (152)
- output.md (26)
- packet-engineering.md (276)
- port-scanning.md (229)
- raw-packet.md (143)
- rest-api.md (151)
- scan-management.md (181)
- sdk.md (135)
- service-detection.md (4)
- stateless-scan.md (141)
- target-parsing.md (34)
- traceroute.md (3)
- vulnerability.md (135)

## Phases

### Phase 1: Create zh_doc/ mirror [pending]
- Copy doc/ to zh_doc/ preserving structure

### Phase 2: Translate doc/ to English [pending]
- Translate all 38 files with Chinese content
- Process in parallel batches for efficiency

### Phase 3: Verification [pending]
- Grep for any remaining Chinese in doc/
- Spot-check translations for accuracy
