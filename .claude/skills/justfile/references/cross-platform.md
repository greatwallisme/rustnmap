# Cross-Platform Attributes and Settings

## Platform Attributes

| Attribute | Platform |
|-----------|----------|
| `[unix]` | Linux, macOS, BSD, etc. |
| `[linux]` | Linux |
| `[macos]` | macOS |
| `[windows]` | Windows |

```just
[unix]
install:
  brew install package

[windows]
install:
  scoop install package

# Different compilers by platform
[unix]
run:
  cc main.c
  ./a.out

[windows]
run:
  cl main.c
  main.exe
```

## Other Key Attributes

| Attribute | Purpose |
|-----------|---------|
| `[no-cd]` | Do not change working directory to justfile directory |
| `[no-exit-message]` | Suppress error output on failure |
| `[private]` | Hide from `--list` |

```just
[no-cd]
commit message:
  git add .
  git commit -m "{{message}}"

[private]
_build:
  cargo build --release
```

## Shell Configuration Priority

From highest to lowest:
1. `--shell` and `--shell-arg` command-line options
2. `set windows-shell := [...]`
3. `set shell := [...]`

**Cross-platform shell setup example**:
```just
set shell := ["bash", "-cu"]
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

hello:
  echo 'Hello on Unix'
```

**Anti-pattern**: AVOID `set shell := ['powershell']` without testing on Linux first - this breaks cross-platform compatibility.
