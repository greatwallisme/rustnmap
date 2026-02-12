# Functions and Settings Reference

## Built-in Functions

### Platform Detection
| Function | Returns |
|----------|---------|
| `os()` | `"android"`, `"bitrig"`, `"dragonfly"`, `"emscripten"`, `"freebsd"`, `"haiku"`, `"ios"`, `"linux"`, `"macos"`, `"netbsd"`, `"openbsd"`, `"solaris"`, `"windows"` |
| `os_family()` | `"unix"` or `"windows"` |
| `arch()` | `"aarch64"`, `"arm"`, `"x86"`, `"x86_64"` |

### Environment Variables
| Function | Description |
|----------|-------------|
| `env_var(key)` | Get environment variable, aborts if not found |
| `env_var_or_default(key, default)` | Get environment variable, returns default if not found |

### Paths and Directories
| Function | Description |
|----------|-------------|
| `invocation_directory()` | Directory where just was invoked |
| `justfile_directory()` | Directory containing the justfile |
| `absolute_path(path)` | Convert to absolute path |
| `path_exists(path)` | Whether path exists |
| `clean(path)` | Normalize path (remove `..` and `.`) |

### String Processing
| Function | Description |
|----------|-------------|
| `replace(s, from, to)` | Replace all matches |
| `replace_regex(s, regex, replacement)` | Regex replacement |
| `trim(s)` / `trim_start(s)` / `trim_end(s)` | Remove whitespace |
| `quote(s)` | Shell-escape with single quotes |
| `lowercase(s)` / `uppercase(s)` | Case conversion |
| `capitalize(s)`, `kebabcase(s)`, `snakecase(s)` | Naming convention conversion |

### Other
| Function | Description |
|----------|-------------|
| `error(message)` | Abort with error message |
| `uuid()` | Random UUID |
| `sha256(string)` / `sha256_file(path)` | SHA256 hash |

## Settings

### Common Settings

```just
set dotenv-load
set export
set positional-arguments
set shell := ["bash", "-cu"]
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]
```

### Complete Settings List

| Setting | Default | Description |
|---------|---------|-------------|
| `allow-duplicate-recipes` | false | Allow duplicate recipe names |
| `allow-duplicate-variables` | false | Allow duplicate variable names |
| `dotenv-load` | false | Load .env file |
| `dotenv-filename` | - | Custom .env filename |
| `dotenv-path` | - | Custom .env path |
| `dotenv-required` | false | Error if .env not found |
| `export` | false | Export variables as environment |
| `fallback` | false | Search parent directories for justfile |
| `ignore-comments` | false | Ignore comment lines in recipes |
| `positional-arguments` | false | Allow positional argument passing |
| `shell` | - | Set shell command |
| `tempdir` | - | Custom temp directory |
| `windows-powershell` | false | (Deprecated) Use PowerShell on Windows |
| `windows-shell` | - | Windows-specific shell |

### Boolean Settings Shorthand

```just
# Both are equivalent
set dotenv-load
set dotenv-load := true
```
