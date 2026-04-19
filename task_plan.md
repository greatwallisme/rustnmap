# Task Plan: zh_doc Chinese Documentation Cleanup

> **Created**: 2026-04-18
> **Goal**: Organize zh_doc/ so it contains proper Chinese translations (not mixed English/Chinese)

## Current State

- 41 files in zh_doc/
- 26 (63%) properly translated to Chinese
- 9 (22%) structured bilingual (manual/ + CHANGELOG.md)
- 5 (12%) entirely English (untranslated copies from doc/)
- 1 anomaly: doc/modules/nse-engine.md is in Chinese (should be English)

## Phase 1: Translate 5 en-only files in zh_doc/ [pending]

These files are exact English copies from doc/ with zero Chinese content:

| File | Size Estimate | Priority |
|------|--------------|----------|
| `zh_doc/database-integration.md` | Medium | High |
| `zh_doc/rustnmap.1` | Small | High |
| `zh_doc/modules/cli.md` | Large | High |
| `zh_doc/modules/nse-libraries.md` | Medium | High |
| `zh_doc/modules/packet-engineering.md` | Large | High |

Approach: Read the corresponding doc/ English file, translate all prose/headers/comments to Chinese, keep code blocks and technical identifiers as-is.

## Phase 2: Convert manual/ bilingual files to Chinese-only [pending]

9 files use structured bilingual format ("English / Chinese" headings):
- `zh_doc/manual/README.md`
- `zh_doc/manual/configuration.md`
- `zh_doc/manual/environment.md`
- `zh_doc/manual/quick-reference.md`
- `zh_doc/manual/options.md`
- `zh_doc/manual/output-formats.md`
- `zh_doc/manual/exit-codes.md`
- `zh_doc/manual/scan-types.md`
- `zh_doc/manual/nse-scripts.md`
- `zh_doc/CHANGELOG.md`

Approach: Remove English portions, keep Chinese-only. Convert "Overview / 概述" to "概述", remove English description columns from tables, etc.

## Phase 3: Fix doc/modules/nse-engine.md (English doc has Chinese content) [pending]

The file `doc/modules/nse-engine.md` is in Chinese but belongs in the English doc tree.
Need to translate it to English, matching the style of other doc/ files.

## Phase 4: Verify consistency [pending]

- Check all zh_doc/ files have consistent Chinese formatting
- Check all doc/ files are in English
- Spot-check translations for accuracy

## Errors Encountered

| Error | Attempt | Resolution |
|-------|---------|------------|
| (none yet) | | |
