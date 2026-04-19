# Findings: zh_doc Language Mixing Analysis

> **Date**: 2026-04-18

## Summary

Analysis of 41 files in zh_doc/ revealed three categories of language mixing:

### Category 1: en-only files (5 files) - NEEDS TRANSLATION

These are exact copies from doc/ with zero Chinese content:

1. `zh_doc/database-integration.md` - English only
2. `zh_doc/rustnmap.1` - English only (man page)
3. `zh_doc/modules/cli.md` - English only
4. `zh_doc/modules/nse-libraries.md` - English only
5. `zh_doc/modules/packet-engineering.md` - English only

### Category 2: mixed-bilingual files (9 files) - NEEDS CONSOLIDATION

Structured bilingual format with "English / Chinese" paired headings:

- All 8 files in `zh_doc/manual/` subdirectory
- `zh_doc/CHANGELOG.md`

Pattern: Each section has both English and Chinese, e.g.:
- Headings: "Overview / 概述"
- Tables: Two description columns (English + Chinese)
- Paragraphs: English text followed by Chinese translation

### Category 3: zh-only files (26 files) - NO ACTION NEEDED

Properly translated Chinese documentation.

### Anomaly in doc/

`doc/modules/nse-engine.md` is entirely in Chinese - it was never translated to English. The zh_doc/ copy is also Chinese. This means both sides have the same Chinese content for this module.
