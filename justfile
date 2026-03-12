# Build the wheel
build:
    uv build

# Install into the system keyring tool environment
install: build
    uv tool install --force keyring --with dist/ado_keyring-0.1.0-py3-none-any.whl

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
