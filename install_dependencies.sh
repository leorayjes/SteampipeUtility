#!/usr/bin/env bash
# install_dependencies.sh
#
# Installs Steampipe, Powerpipe, and required plugins on macOS or Linux (WSL).
# Reads required plugins from mods.json via Python.
# Safe to re-run — skips installation if binaries are already present.
#
# NOTE: Steampipe and Powerpipe are system-level binaries, not Python packages.
# They cannot be installed into a virtual environment. On Linux/WSL the curl
# installers place binaries in ~/.local/bin — this script ensures that path is
# on $PATH before attempting to use either binary.

set -euo pipefail

MODS_CONFIG="mods.json"

log()  { echo "[INFO]  $*"; }
warn() { echo "[WARN]  $*"; }
err()  { echo "[ERROR] $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Detect OS
# ---------------------------------------------------------------------------

detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif grep -qi microsoft /proc/version 2>/dev/null; then
        echo "wsl"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    else
        err "Unsupported operating system: $OSTYPE"
    fi
}

OS=$(detect_os)
log "Detected OS: $OS"

# ---------------------------------------------------------------------------
# Ensure ~/.local/bin is on PATH (Linux/WSL curl installers write here)
# ---------------------------------------------------------------------------

ensure_local_bin_on_path() {
    if [[ "$OS" != "macos" ]]; then
        if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
            log "Adding ~/.local/bin to PATH for this session..."
            export PATH="$HOME/.local/bin:$PATH"
        fi
    fi
}

ensure_local_bin_on_path

# ---------------------------------------------------------------------------
# Install Steampipe
# ---------------------------------------------------------------------------

install_steampipe() {
    if command -v steampipe &>/dev/null; then
        log "Steampipe already installed: $(steampipe --version)"
        return
    fi

    log "Installing Steampipe..."
    if [[ "$OS" == "macos" ]]; then
        brew install turbot/tap/steampipe
    else
        curl -fsSL https://steampipe.io/install/steampipe.sh | sh
        # Reload PATH in case the installer just wrote the binary.
        export PATH="$HOME/.local/bin:$PATH"
    fi

    if command -v steampipe &>/dev/null; then
        log "Steampipe installed: $(steampipe --version)"
    else
        err "Steampipe installation succeeded but binary not found on PATH. Add ~/.local/bin to your PATH and re-run."
    fi
}

# ---------------------------------------------------------------------------
# Install Powerpipe
# ---------------------------------------------------------------------------

install_powerpipe() {
    local min_major=1

    if command -v powerpipe &>/dev/null; then
        local installed_version
        installed_version=$(powerpipe --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        local installed_major
        installed_major=$(echo "$installed_version" | cut -d. -f1)

        if (( installed_major >= min_major )); then
            log "Powerpipe already installed and up to date: v$installed_version"
            return
        else
            warn "Powerpipe v$installed_version is installed but v${min_major}.x or higher is required. Updating..."
        fi
    else
        log "Powerpipe not found. Installing..."
    fi

    if [[ "$OS" == "macos" ]]; then
        brew upgrade turbot/tap/powerpipe 2>/dev/null || brew install turbot/tap/powerpipe
    else
        curl -fsSL https://powerpipe.io/install/powerpipe.sh | sh
        # Reload PATH in case the installer just wrote the binary.
        export PATH="$HOME/.local/bin:$PATH"
    fi

    if command -v powerpipe &>/dev/null; then
        log "Powerpipe installed: $(powerpipe --version)"
    else
        err "Powerpipe installation succeeded but binary not found on PATH. Add ~/.local/bin to your PATH and re-run."
    fi
}

# ---------------------------------------------------------------------------
# Install Steampipe plugins (read from mods.json)
# ---------------------------------------------------------------------------

install_plugins() {
    if [[ ! -f "$MODS_CONFIG" ]]; then
        err "mods.json not found. Cannot determine required plugins."
    fi

    # Parse plugin list from mods.json using Python (already in venv).
    # Deduplication is handled in Python so we never attempt a double install.
    PLUGINS=()
    while IFS= read -r plugin; do
        PLUGINS+=("$plugin")
    done < <(python3 -c "
import json
with open('$MODS_CONFIG') as f:
    config = json.load(f)
seen = set()
for plugin in config.get('steampipe', {}).get('plugins', []):
    if plugin not in seen:
        seen.add(plugin)
        print(plugin)
")

    if [[ ${#PLUGINS[@]} -eq 0 ]]; then
        warn "No plugins listed in mods.json — skipping plugin installation."
        return
    fi

    # Fetch the list of already-installed plugins once.
    local installed_plugins
    installed_plugins=$(steampipe plugin list 2>/dev/null || true)

    for plugin in "${PLUGINS[@]}"; do
        if echo "$installed_plugins" | grep -q "turbot/${plugin}@"; then
            log "Steampipe plugin already installed: $plugin — checking for updates..."
            steampipe plugin update "$plugin"
        else
            log "Installing Steampipe plugin: $plugin"
            steampipe plugin install "$plugin"
        fi
    done
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

install_steampipe
install_powerpipe
install_plugins

log "All dependencies installed successfully."
log "Steampipe and Powerpipe are installed system-wide (not inside the virtual environment)."
