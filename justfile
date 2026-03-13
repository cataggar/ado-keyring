set windows-shell := ["cmd.exe", "/c"]

# Show the current version
version:
    uvx --with hatch-vcs hatchling version

# Build the wheel
build:
    uv build

# Install into the system keyring tool environment
install: build
    uv tool install --force keyring --with dist/ado_keyring-*.whl

# Verify the backend is registered
check:
    keyring --list-backends

# Build, install, and verify
all: install check

# Run tests
test:
    uv run pytest tests/ -v

# Clean build artifacts
clean:
    rm -rf dist/ build/ *.egg-info
