---
description: Compare completed code against technical design documents to detect deviations and feature simplifications. Accepts an optional doc path (default: doc/technical) and --full to scan the entire codebase instead of git-scoped files.
argument-hint: [path/to/design/docs] [--full]
allowed-tools: Read, Glob, Grep, Bash
---

# Setup

Arguments: `$ARGUMENTS`

- If `--full` is present, set FULL_SCAN = true (remove it from the remaining token).
- The remaining token is the doc path; default to `doc/technical` if absent.

Print before starting:
> Doc path: `{DESIGN_DOC_PATH}` | Mode: [git-scoped | full]

---

# Step 0 - Determine Review Scope

Reviewing a large codebase in one pass is not reliable. Use git to focus on what has actually changed.

Run the following. If `git rev-parse --is-inside-work-tree` fails, skip to full-scan mode.

```bash
git branch --show-current
git log --oneline -40
git log --format="%ad %s" --date=short -40
git diff --name-only HEAD~40 HEAD 2>/dev/null || git diff --name-only $(git rev-list --max-parents=0 HEAD) HEAD
git status --short
```

**Critical - treat commit messages with low trust.**
Commit messages (especially those written by AI) frequently overstate what was actually done. They are useful only for rough orientation - for example, identifying which module an author was working on. Never use a commit message as evidence that a feature is complete or correctly implemented. All conclusions about what the code does must be based on reading the actual source files.

If FULL_SCAN is false, derive the in-scope file list from the changed files above (exclude lock files, generated files, build artifacts). Print:
> Scope: {N} files across {M} modules. Reviewing these against the design.

If FULL_SCAN is true, the scope is the entire source tree (exclude `node_modules`, `dist`, `.git`, `__pycache__`, `build`, `vendor`, `.next`, `target`, `out`).

---

# Step 1 - Read Design Documents

If `{DESIGN_DOC_PATH}` does not exist, stop:
> ERROR: `{DESIGN_DOC_PATH}` not found. Supply the correct path, e.g.: `/review-design-conformance path/to/docs`

Read all files in `{DESIGN_DOC_PATH}` (`.md`, `.txt`, `.pdf`, `.docx`). Extract: architecture and tech stack, module boundaries, data models, interface contracts, business rules, non-functional requirements.

Cross-reference the design's module map against the in-scope file list. Design areas with no recently changed files are out-of-scope for this run - note them but do not analyze them deeply.

---

# Step 2 - Read In-Scope Code

Read only the files from Step 0. For each file, identify which design section it corresponds to, the technology and patterns used, data model definitions, and API implementations. Flag anything that may constitute a deviation or simplification.

---

# Step 3 - Classify Findings

For each design requirement mapped to an in-scope file, assign one category.

**[A] Unacceptable - Technical direction deviation**
The code took a fundamentally different route: different architecture pattern, replaced core technology choice, broken module boundaries, or interface semantics that contradict the design.

**[B] Unacceptable - Feature simplification**
Functionality explicitly required by the design is absent or reduced: missing modules, missing API fields or behaviors, omitted business rules or validation, unimplemented non-functional requirements.

**[C] Acceptable - Code exceeds design**
The code follows the original direction but goes further than the design described: fills in design gaps sensibly, adds reasonable optimizations, or adds defensive engineering (error handling, logging, monitoring).

---

# Step 4 - Report

```
# Technical Design Conformance Report

Doc path      : {DESIGN_DOC_PATH}
Mode          : [git-scoped (last 40 commits) | full]
Branch        : {branch}
Files reviewed: {N} across {M} modules
Design docs   : {files read}

## Summary

| Category                                          | Count |
|---------------------------------------------------|-------|
| [A] Unacceptable - Technical direction deviation  | X     |
| [B] Unacceptable - Feature simplification         | X     |
| [C] Acceptable - Code exceeds design (update doc) | X     |
| Fully conformant                                  | X     |
| Out-of-scope (not reviewed this run)              | X     |

Verdict: [Requires remediation | Acceptable, update docs | Fully conformant]

---

## Must-Fix Items

### [A-001] Technical Direction Deviation: {title}
- Design doc   : `{DESIGN_DOC_PATH}/{file}` - {section}
- Design spec  : {what the design required}
- Actual impl  : {what the code does instead}
- Nature       : {why this is a route change, not an improvement}
- Affected files: {list}
- Git reference: {commit hash only - do not rely on the commit message as proof of intent}
- Action: Align with architecture team; revert or formally revise the design.

### [B-001] Feature Simplification: {title}
- Design doc   : `{DESIGN_DOC_PATH}/{file}` - {section}
- Design spec  : {what the design required}
- Missing items: {enumerate each gap}
- Affected files: {list}
- Git reference: {commit hash - note if feature was never committed or was removed}
- Action: Implement missing functionality per the cited design section.

---

## Recommended Design Document Updates

### [C-001] Code Exceeds Design: {title}
- Design doc   : `{DESIGN_DOC_PATH}/{file}` - {section}
- Original design: {the design's gap or shortcoming}
- Actual impl  : {the better approach in the code}
- Action: Update `{DESIGN_DOC_PATH}/{file}`, {section}, to adopt the current implementation as the formal design.

---

## Conformant Modules
- {module}: {brief note}

## Out-of-Scope (Not Reviewed This Run)
Run with --full to include these.
- {design area}: no recent changes, last touched {date/commit}

## Action Plan
### Immediate
1. [ ] {action item}

### Recommended (doc updates)
1. [ ] Update `{DESIGN_DOC_PATH}/{file}` to reflect [C-001].
```

---

# Analysis Guidelines

- **Code is the only source of truth.** Commit messages indicate which area was worked on; they do not prove correctness or completeness. Always verify against the actual source.
- **Scope discipline.** Do not read files outside the git-scoped list unless a design section has no corresponding file at all (flag that as a gap).
- **Default to C, not A/B.** Code that adds something the design did not mention is Category C unless there is clear evidence it violates design intent.
- **Substance over style.** Naming conventions and code organization are not deviations. Focus on architecture, tech choices, feature completeness, and interface semantics.
- **Cite precisely.** Every finding needs a specific design doc location and a specific file path.