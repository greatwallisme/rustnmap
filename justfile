# Initialize project directory structure with interactive configuration selection
init:
    #!/usr/bin/env bash
    set -euo pipefail

    PROFILE_DIR="$HOME/Private/claude_profile/.claude"
    PROJECT_DIR="$(pwd)/.claude"

    echo "======================================"
    echo "  Claude Project Initialization"
    echo "======================================"
    echo ""

    # Create directory structure
    echo "Creating project directories..."
    mkdir -p "$PROJECT_DIR/agents" "$PROJECT_DIR/commands" "$PROJECT_DIR/skills"
    mkdir -p reference doc
    echo "Directory structure created."
    echo ""

    # Check if profile directory exists
    if [ ! -d "$PROFILE_DIR" ]; then
        echo "Warning: Profile directory not found: $PROFILE_DIR"
        echo "Skipping configuration copy."
    else
        # Scan available configurations
        echo "Scanning available configurations from profile..."

        # Get list of agents
        mapfile -t AGENTS < <(find "$PROFILE_DIR/agents" -maxdepth 1 -name "*.md" -type f -exec basename {} \; 2>/dev/null | sort)
        # Get list of commands
        mapfile -t COMMANDS < <(find "$PROFILE_DIR/commands" -maxdepth 1 -name "*.md" -type f -exec basename {} \; 2>/dev/null | sort)
        # Get list of skills (directories)
        mapfile -t SKILLS < <(find "$PROFILE_DIR/skills" -maxdepth 1 -type d ! -name "skills" -exec basename {} \; 2>/dev/null | sort)

        echo ""
        echo "Found:"
        echo "  - ${#AGENTS[@]} agents"
        echo "  - ${#COMMANDS[@]} commands"
        echo "  - ${#SKILLS[@]} skills"
        echo ""

        # Selection mode
        echo "Select configuration mode:"
        echo "  1) Select all configurations"
        echo "  2) Select by category (agents/commands/skills)"
        echo "  3) Interactive selection"
        echo "  4) Skip configuration copy"
        echo ""
        read -rp "Enter choice [1-4] (default: 3): " MODE_CHOICE
        MODE_CHOICE=${MODE_CHOICE:-3}
        echo ""

        SELECTED_AGENTS=()
        SELECTED_COMMANDS=()
        SELECTED_SKILLS=()

        case "$MODE_CHOICE" in
            1)  # Select all
                SELECTED_AGENTS=("${AGENTS[@]}")
                SELECTED_COMMANDS=("${COMMANDS[@]}")
                SELECTED_SKILLS=("${SKILLS[@]}")
                echo "Selected all configurations."
                ;;
            2)  # Select by category
                echo "Select categories to include (y/n):"
                read -rp "  Include agents? [Y/n]: " INCLUDE_AGENTS
                [[ "${INCLUDE_AGENTS:-y}" =~ ^[Yy]$ ]] && SELECTED_AGENTS=("${AGENTS[@]}")
                read -rp "  Include commands? [Y/n]: " INCLUDE_COMMANDS
                [[ "${INCLUDE_COMMANDS:-y}" =~ ^[Yy]$ ]] && SELECTED_COMMANDS=("${COMMANDS[@]}")
                read -rp "  Include skills? [Y/n]: " INCLUDE_SKILLS
                [[ "${INCLUDE_SKILLS:-y}" =~ ^[Yy]$ ]] && SELECTED_SKILLS=("${SKILLS[@]}")
                ;;
            3)  # Interactive selection
                # Agent selection
                if [ ${#AGENTS[@]} -gt 0 ]; then
                    echo ""
                    echo "=== AGENTS ==="
                    echo "Available agents:"
                    for i in "${!AGENTS[@]}"; do
                        echo "  $((i+1))) ${AGENTS[$i]}"
                    done
                    echo "  a) Select all"
                    echo "  n) Select none"
                    read -rp "Enter agent numbers (comma-separated, or 'a'/'n'): " AGENT_INPUT
                    case "$AGENT_INPUT" in
                        a|A) SELECTED_AGENTS=("${AGENTS[@]}") ;;
                        n|N) ;;
                        *)
                            IFS=',' read -ra IDX <<< "$AGENT_INPUT"
                            for idx in "${IDX[@]}"; do
                                idx=$((idx-1))
                                if [ $idx -ge 0 ] && [ $idx -lt ${#AGENTS[@]} ]; then
                                    SELECTED_AGENTS+=("${AGENTS[$idx]}")
                                fi
                            done
                            ;;
                    esac
                fi

                # Command selection
                if [ ${#COMMANDS[@]} -gt 0 ]; then
                    echo ""
                    echo "=== COMMANDS ==="
                    echo "Available commands:"
                    for i in "${!COMMANDS[@]}"; do
                        echo "  $((i+1))) ${COMMANDS[$i]}"
                    done
                    echo "  a) Select all"
                    echo "  n) Select none"
                    read -rp "Enter command numbers (comma-separated, or 'a'/'n'): " CMD_INPUT
                    case "$CMD_INPUT" in
                        a|A) SELECTED_COMMANDS=("${COMMANDS[@]}") ;;
                        n|N) ;;
                        *)
                            IFS=',' read -ra IDX <<< "$CMD_INPUT"
                            for idx in "${IDX[@]}"; do
                                idx=$((idx-1))
                                if [ $idx -ge 0 ] && [ $idx -lt ${#COMMANDS[@]} ]; then
                                    SELECTED_COMMANDS+=("${COMMANDS[$idx]}")
                                fi
                            done
                            ;;
                    esac
                fi

                # Skill selection
                if [ ${#SKILLS[@]} -gt 0 ]; then
                    echo ""
                    echo "=== SKILLS ==="
                    echo "Available skills:"
                    for i in "${!SKILLS[@]}"; do
                        echo "  $((i+1))) ${SKILLS[$i]}"
                    done
                    echo "  a) Select all"
                    echo "  n) Select none"
                    read -rp "Enter skill numbers (comma-separated, or 'a'/'n'): " SKILL_INPUT
                    case "$SKILL_INPUT" in
                        a|A) SELECTED_SKILLS=("${SKILLS[@]}") ;;
                        n|N) ;;
                        *)
                            IFS=',' read -ra IDX <<< "$SKILL_INPUT"
                            for idx in "${IDX[@]}"; do
                                idx=$((idx-1))
                                if [ $idx -ge 0 ] && [ $idx -lt ${#SKILLS[@]} ]; then
                                    SELECTED_SKILLS+=("${SKILLS[$idx]}")
                                fi
                            done
                            ;;
                    esac
                fi
                ;;
            4)  # Skip
                echo "Skipping configuration copy."
                ;;
        esac

        # Copy selected configurations
        echo ""
        echo "======================================"
        echo "Copying configurations..."
        echo "======================================"

        COPIED_COUNT=0

        # Copy agents
        for agent in "${SELECTED_AGENTS[@]}"; do
            if [ -f "$PROFILE_DIR/agents/$agent" ]; then
                cp "$PROFILE_DIR/agents/$agent" "$PROJECT_DIR/agents/"
                echo "  [agent] $agent"
                COPIED_COUNT=$((COPIED_COUNT + 1))
            fi
        done

        # Copy commands
        for cmd in "${SELECTED_COMMANDS[@]}"; do
            if [ -f "$PROFILE_DIR/commands/$cmd" ]; then
                cp "$PROFILE_DIR/commands/$cmd" "$PROJECT_DIR/commands/"
                echo "  [command] $cmd"
                COPIED_COUNT=$((COPIED_COUNT + 1))
            fi
        done

        # Copy skills
        for skill in "${SELECTED_SKILLS[@]}"; do
            if [ -d "$PROFILE_DIR/skills/$skill" ]; then
                cp -r "$PROFILE_DIR/skills/$skill" "$PROJECT_DIR/skills/"
                echo "  [skill] $skill"
                COPIED_COUNT=$((COPIED_COUNT + 1))
            fi
        done

        echo ""
        echo "Copied $COPIED_COUNT configuration(s)."
    fi

    # Create settings.local.json if not exists
    if [ ! -f "$PROJECT_DIR/settings.local.json" ]; then
        printf '%s\n' \
            '{' \
            '  "permissions": {' \
            '    "allow": [' \
            '      "Bash(cargo check:*)",' \
            '      "Bash(cargo test:*)",' \
            '      "Bash(cargo run:*)",' \
            '      "Bash(timeout 10s cargo run:*)",' \
            '      "Bash(cargo build:*)",' \
            '      "mcp__Context7__resolve-library-id",' \
            '      "mcp__Context7__get-library-docs",' \
            '      "mcp__Bocha__bocha_web_search",' \
            '      "mcp__Bocha__bocha_ai_search",' \
            '      "mcp__Docs-rs__docs_rs_search_crates",' \
            '      "mcp__Docs-rs__docs_rs_readme",' \
            '      "mcp__Docs-rs__docs_rs_search_in_crate",' \
            '      "mcp__Docs-rs__docs_rs_get_item",' \
            '      "mcp__rust-analyzer__rust_analyzer_diagnostics",' \
            '      "Bash(cargo doc:*)",' \
            '      "mcp__rust-analyzer__rust_analyzer_hover",' \
            '      "Bash(cargo tree:*)",' \
            '      "Bash(cargo clippy:*)",' \
            '      "mcp__Playwright__browser_navigate",' \
            '      "Bash(curl:*)",' \
            '      "mcp__web-reader__webReader",' \
            '      "mcp__Playwright__browser_console_messages",' \
            '      "mcp__Playwright__browser_wait_for",' \
            '      "mcp__Playwright__browser_take_screenshot",' \
            '      "Bash(mkdir:*)",' \
            '      "Bash(find:*)",' \
            '      "Bash(ss:*)"' \
            '    ],' \
            '    "deny": [],' \
            '    "ask": []' \
            '  }' \
            '}' > "$PROJECT_DIR/settings.local.json"
        echo ""
        echo "Created .claude/settings.local.json"
    else
        echo ""
        echo ".claude/settings.local.json already exists, skipping"
    fi

    echo ""
    echo "======================================"
    echo "Project initialization complete!"
    echo "======================================"

# Build recipes
build *args="":
    cargo build {{args}}

check *args="":
    cargo check --workspace {{args}}

test *args="":
    cargo test --workspace {{args}}

clippy *args="":
    cargo clippy --workspace -- -D warnings {{args}}

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

run *args="":
    cargo run --release {{args}}

release:
    cargo build --workspace --release

clean:
    cargo clean

doc:
    cargo doc --workspace --no-deps --all-features

# Update dependencies
update:
    cargo update

# Lock and check
lock-check:
    cargo check --locked

# Show dependency tree
tree:
    cargo tree

# Full check (fmt + clippy + test)
ci: fmt-check clippy test

# Workspace info
info:
    cargo workspace info

# List all crates
list:
    echo "RustNmap workspace crates:"
    cargo tree --depth 0

# Install development tools
install-tools:
    cargo install cargo-watch
    cargo install cargo-edit
    cargo install cargo-criterion
