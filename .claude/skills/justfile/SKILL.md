---
name: justfile
description: |
  Use just command runner to create and maintain task automation. Trigger when user needs to create, modify, or understand justfiles; when user asks about task running, build automation, development workflow setup, or needs to write Makefile-like task scripts. Keywords: just, justfile, task runner, command runner, recipe, devops, automation.
---

# Justfile

## When to Use Justfile

### Decision Tree: Justfile vs Alternatives

| Scenario | Recommended Tool | Rationale |
|----------|-----------------|-----------|
| Shell-heavy task automation | **Justfile** | Shebang recipes, clean syntax, no tab vs spaces issues |
| Existing Makefile in project | Make | Ecosystem compatibility, pattern rules |
| Rust project with cargo workspaces | **cargo-make** or Just | cargo-make has built-in Rust awareness, Just is simpler |
| Complex cross-platform builds | CMake / Meson | True build system with dependency graph |
| Simple npm scripts | package.json scripts | Already in Node.js ecosystem |
| One-off shell commands | shell script / alias | No additional tool needed |
| Mixed-language automation tasks | **Justfile** | Shebang recipes allow Python, Node, Rust in same file |

## Shebang Recipes

Shebang recipes are Justfile's defining feature.

**When to use shebang vs shell:**
- **Shebang**: Data processing, API calls, complex logic, non-trivial programs
- **Shell**: Simple commands, file operations, calling other tools

```just
# Python recipe - no shell escaping needed
process-data:
  #!/usr/bin/env python3
  import pandas as pd
  df = pd.read_csv('data.csv')
  print(df.describe())

# Node.js recipe
bundle:
  #!/usr/bin/env node
  const esbuild = require('esbuild');
  esbuild.buildSync({ bundle: true });
```

**MANDATORY**: If user needs multi-language recipes, read [`references/shebang-recipes.md`](references/shebang-recipes.md) completely before proceeding.

## Private Recipes

Control visibility to keep `just --list` clean:

```just
# Public recipe - shows in list
deploy: _build-image _push-image
  echo 'Deployed!'

# Private recipe - hidden, use as dependency only
[private]
_build-image:
  docker build -t app .

# Alternative: underscore prefix (also private)
_push-image:
  docker push app:latest
```

**Before creating a recipe, ask:** Is this a user-facing task or an implementation detail? If implementation detail, make it private.

## Cross-Platform Attributes

```just
[unix]
install:
  brew install package

[windows]
install:
  scoop install package

[no-cd]
# Recipe doesn't change to justfile directory
commit message:
  git add .
  git commit -m "{{message}}"
```

**MANDATORY**: If user needs platform-specific logic, read [`references/cross-platform.md`](references/cross-platform.md) completely before proceeding.

## Anti-Patterns

### Justfile-Specific Anti-Patterns

1. **NEVER mix shebang and non-shebang recipes in same dependency chain**
   - This causes unpredictable shell behavior
   - Each recipe type has different execution models

2. **AVOID `set shell := ['powershell']` without testing on Linux first**
   - This breaks cross-platform compatibility
   - Use `[windows]` attributes for platform-specific shell instead

3. **NEVER use recursive `just` calls without `--justfile` explicit path**
   ```just
   # BAD - will fail if called from subdirectory
   submodule:
     just -f submodule/justfile build

   # GOOD
   submodule:
     just --justfile submodule/justfile build
   ```

4. **AVOID exporting everything with `set export`**
   - Explicitly export only needed variables with `export VAR := ...`
   - Reduces namespace pollution in child processes

5. **DON'T ignore errors with `-` prefix without documenting why**
   ```just
   # BAD - silent failure
   clean:
     -rm -rf /tmp/stuff

   # GOOD - document expected failure
   clean:
     # May fail if directory doesn't exist
     -rm -rf /tmp/stuff
   ```

## Built-in Functions

Just provides functions for cross-platform logic:

| Category | Functions |
|----------|-----------|
| Platform | `os()`, `os_family()`, `arch()` |
| Environment | `env_var()`, `env_var_or_default()` |
| Paths | `absolute_path()`, `path_exists()`, `justfile_directory()` |
| Strings | `replace()`, `trim()`, `uppercase()`, `lowercase()` |

**MANDATORY**: If user needs function reference or settings, read [`references/functions-and-settings.md`](references/functions-and-settings.md) completely before proceeding.

## Expert Patterns

### Error Handling

**Always use strict mode in bash shebang recipes:**
```just
# GOOD - errors are caught immediately
process:
  #!/usr/bin/env bash
  set -euo pipefail  # Exit on error, undefined vars, pipe failures

  for file in *.txt; do
    process "$file"
  done
```

**Handle missing environment variables gracefully:**
```just
# GOOD - provide safe default
api_key := env_var_or_default("API_KEY", "dev-default")

# BAD - will abort if API_KEY not set
api_key := env_var("API_KEY")
```

**Document expected failures with inline comments:**
```just
# May fail if directory doesn't exist (that's ok)
clean:
  -rm -rf /tmp/stuff
```

### Module Structure

**When justfile grows beyond 100 lines, split into modules:**
```just
# Root justfile - orchestration only
import? '.just/hugo.just'
import? '.just/github.just'

# list recipes
default:
  just --list
```

**Module organization:**
```
.just/
  hugo.just      # Hugo-specific commands
  github.just    # GitHub workflow automation
  utility.just   # Helper recipes
```

Use `import?` with `?` for optional modules useful in shared contexts.

### Sanity Check Dependencies

**Use private recipes as guards for preconditions:**
```just
# Create PR only if on feature branch and has commits
pr: _on_feature_branch && _has_commits
  gh pr create --title "Update"

# Private: error if on main branch
[no-cd]
[private]
_on_feature_branch:
  #!/usr/bin/env bash
  [[ $(git branch --show-current) == "main" ]] && exit 100 || exit 0
```

### Testing Automation

**Dry-run and verbose flags for debugging:**
```bash
just --dry-run recipe    # Show what would run
just --verbose recipe    # Show commands before execution
```

## When NOT to Use Just

### Avoid Just For:

| Scenario | Why NOT Just | Better Alternative |
|----------|--------------|-------------------|
| Complex multi-stage builds where outputs become inputs | No dependency graph, no incremental builds | Make, Ninja, CMake |
| CI/CD pipelines requiring conditional execution, artifacts, caching | No native CI/CD primitives | GitHub Actions, GitLab CI, Taskfile |
| Projects already heavily invested in Make ecosystem | Toolchain already expects Makefiles | Make |
| Large distributed team with heterogeneous tooling | Requires installing Just binary | npm scripts, cargo make |

### Recipe Explosion Anti-Pattern

**AVOID creating 50+ single-line recipes.** Combine related operations:
```just
# BAD - recipe explosion
fmt-go:
  go fmt ./go/...
fmt-js:
  cd js && npm run format
fmt-py:
  cd py && black .

# GOOD - grouped by domain
[group('Format')]
fmt *args:
  #!/usr/bin/env bash
  case "{{args}}" in
    go) go fmt ./go/... ;;
    js) cd js && npm run format ;;
    py) cd py && black . ;;
    *) echo "Usage: just fmt [go\|js\|py]" ;;
  esac
```
