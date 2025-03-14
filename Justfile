default:
  @just --list --unsorted --color=always

# Run pre-commit hooks on all files, including autoformatting
pre-commit-all:
    pre-commit run --all-files

# Run 'cargo run' on the project
run *ARGS:
    cargo run {{ARGS}}

# Run 'bacon' to run the project (auto-recompiles)
watch *ARGS:
	bacon --job run -- -- {{ ARGS }}

# Build the library and binary
build:
    cargo build --all

# Run all tests (ensures Vault is up via docker-compose)
test:
    @echo "Starting Vault for tests..."
    cargo test -- --test-threads=3 --nocapture --color=always

# Run clippy (lint) and format check
lint:
    cargo clippy --all-targets -- -D warnings

fmt:
    cargo fmt -- --check

fix:
    cargo fmt --all -- --check --verbose --color=always

# Clean build artifacts
clean:
    cargo clean

code2prompt:
    code2prompt --include '*.yml,*.yaml,*.toml,*.md,*.rs' .