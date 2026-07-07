#!/bin/sh
# Copyright (c) 2026 Huitzo Inc. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

# Huitzo CLI — one-command bootstrap (Linux, macOS, WSL)
# Usage: curl -sSf https://raw.githubusercontent.com/Huitzo-Inc/huitzo-launcher/main/install.sh | sh
#
# This single command:
#   1. Asks for informed consent before installing anything. The grant is
#      recorded to the launcher's local, metadata-only consent ledger
#      (~/.huitzo/consent.jsonl) by the launcher binary on first run.
#   2. Installs the Huitzo launcher binary (which manages the Huitzo CLI).
#   3. Runs a capability check (huitzo / claude / git) so you know exactly
#      what is present and what is still missing — all in one shot.
#
# Supported: macOS, Linux, and WSL2. Native Windows (non-WSL) and
# admin-locked corporate machines are NOT yet officially supported — see
# https://github.com/Huitzo-Inc/huitzo-launcher/blob/main/docs/SUPPORT_MATRIX.md
#
# Environment variables:
#   HUITZO_HOME            — override install root (default: ~/.huitzo)
#   HUITZO_NO_MODIFY_PATH  — set to 1 to skip shell profile modification
#   HUITZO_ASSUME_YES      — set to 1 to grant install consent non-interactively
#                            (recorded in the consent ledger for auditability)
set -eu

REPO="Huitzo-Inc/huitzo-launcher"
HUITZO_HOME="${HUITZO_HOME:-$HOME/.huitzo}"
INSTALL_DIR="$HUITZO_HOME/bin"
VENV_DIR="$HUITZO_HOME/venv"
CACHE_DIR="$HUITZO_HOME/cache"

main() {
    echo "==> Installing Huitzo CLI"
    detect_platform
    consent_gate
    fetch_latest_version
    clean_conflicts
    download_and_verify
    install_binary
    modify_path
    capability_check

    echo ""
    echo "✓ Huitzo CLI installed to: $INSTALL_DIR/huitzo"
    echo ""
    echo "Run 'huitzo --version' to get started."
    echo "If 'huitzo' is not found, restart your shell or run:"
    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
}

# Logged informed consent BEFORE downloading or executing third-party
# software (S29 consent pattern). Here we obtain the up-front affirmative so
# the curl|sh flow never silently installs. The corresponding GRANT is then
# recorded to the launcher's local, metadata-only consent ledger
# (~/.huitzo/consent.jsonl) by the launcher binary itself on its first-run
# bootstrap (the HUITZO_BOOTSTRAP_CONSENTED path), so the audit trail always
# exists even though this script does not write the ledger.
consent_gate() {
    echo ""
    echo "  Huitzo is about to download and install the Huitzo launcher + CLI"
    echo "  onto this machine, and will detect git and your AI tool (Claude Code)."
    echo "  This installs/executes third-party software. Nothing is uploaded."

    if [ "${HUITZO_ASSUME_YES:-0}" = "1" ]; then
        echo "  HUITZO_ASSUME_YES=1 — proceeding with recorded consent."
    elif [ -t 0 ]; then
        printf '  Proceed? [y/N] '
        read -r answer
        case "$answer" in
            y|Y|yes|YES) : ;;
            *) echo "  Declined. Nothing was installed."; exit 1 ;;
        esac
    else
        # Piped (curl | sh) with no TTY and no explicit override: fail closed.
        echo "  No interactive terminal detected. Re-run with HUITZO_ASSUME_YES=1"
        echo "  to consent non-interactively, or run the command in a terminal."
        exit 1
    fi

    # Tell the launcher's first-run bootstrap that consent was already given,
    # so the user is asked exactly once (not again on first 'huitzo' run).
    # The launcher records the GRANT on this path — no install without an
    # audit trail. We deliberately do NOT export a session-wide
    # HUITZO_ASSUME_YES: this consent covers only the bootstrap install, and
    # the capability check that follows is read-only (installs nothing).
    export HUITZO_BOOTSTRAP_CONSENTED=1
}

detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        linux)  OS_TARGET="unknown-linux-musl" ;;
        darwin) OS_TARGET="apple-darwin" ;;
        *) echo "Error: Unsupported OS: $OS"; exit 1 ;;
    esac

    case "$ARCH" in
        x86_64|amd64)  ARCH_TARGET="x86_64" ;;
        aarch64|arm64) ARCH_TARGET="aarch64" ;;
        *) echo "Error: Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    ASSET="huitzo-${ARCH_TARGET}-${OS_TARGET}"
    echo "  Platform: ${ARCH_TARGET}-${OS_TARGET}"
}

fetch_latest_version() {
    echo "  Fetching latest launcher release..."

    # Fetch up to 20 releases (newest first).  /releases/latest returns the most
    # recently *published* release — which may be a cli-v* CLI release, not a
    # launcher release.  We filter for the first v* tag that is NOT cli-v*.
    API_RESPONSE=$(curl -sSf "https://api.github.com/repos/$REPO/releases?per_page=20")

    VERSION=$(printf '%s\n' "$API_RESPONSE" \
        | grep '"tag_name"' \
        | grep -v '"cli-v' \
        | grep '"v[0-9]' \
        | head -1 \
        | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

    if [ -z "$VERSION" ]; then
        echo "Error: No launcher release found."
        echo "Check: https://github.com/$REPO/releases"
        exit 1
    fi

    echo "  Version: $VERSION"

    # Construct URLs directly — we know the asset naming convention.
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$ASSET"
    SHA256_URL="${DOWNLOAD_URL}.sha256"
}

clean_conflicts() {
    # Remove launcher-managed venv so the new binary performs a fresh CLI install
    if [ -d "$VENV_DIR" ]; then
        echo "  Removing old launcher venv..."
        rm -rf "$VENV_DIR"
    fi

    # Remove cached wheels so the launcher re-fetches the current release
    if [ -d "$CACHE_DIR" ]; then
        echo "  Clearing wheel cache..."
        rm -rf "$CACHE_DIR"
    fi

    # Remove any conflicting pip-installed huitzo
    for pip_cmd in pip3 pip; do
        if command -v "$pip_cmd" > /dev/null 2>&1; then
            if "$pip_cmd" show huitzo > /dev/null 2>&1; then
                echo "  Removing conflicting pip-installed huitzo..."
                "$pip_cmd" uninstall huitzo -y --quiet 2>/dev/null || true
                echo "  Done."
            fi
            break
        fi
    done
}

download_and_verify() {
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    TMPBIN="$TMPDIR/huitzo"

    echo "  Downloading $ASSET..."
    curl -sSfL "$DOWNLOAD_URL" -o "$TMPBIN"

    if [ -n "${SHA256_URL:-}" ]; then
        echo "  Verifying checksum..."
        EXPECTED=$(curl -sSfL "$SHA256_URL" | awk '{print $1}')

        if command -v sha256sum > /dev/null 2>&1; then
            ACTUAL=$(sha256sum "$TMPBIN" | awk '{print $1}')
        elif command -v shasum > /dev/null 2>&1; then
            ACTUAL=$(shasum -a 256 "$TMPBIN" | awk '{print $1}')
        else
            echo "  Warning: No sha256 tool found, skipping verification."
            ACTUAL="$EXPECTED"
        fi

        if [ "$ACTUAL" != "$EXPECTED" ]; then
            echo "Error: Checksum mismatch — download may be corrupted."
            echo "  Expected: $EXPECTED"
            echo "  Got:      $ACTUAL"
            exit 1
        fi
        echo "  Checksum OK"
    fi

    chmod +x "$TMPBIN"
    VERIFIED_BIN="$TMPBIN"
}

install_binary() {
    mkdir -p "$INSTALL_DIR"

    if [ -f "$INSTALL_DIR/huitzo" ]; then
        echo "  Replacing existing launcher binary..."
    fi

    cp "$VERIFIED_BIN" "$INSTALL_DIR/huitzo"
    echo "  Installed → $INSTALL_DIR/huitzo"
}

modify_path() {
    [ "${HUITZO_NO_MODIFY_PATH:-0}" = "1" ] && return

    echo "$PATH" | tr ':' '\n' | grep -qxF "$INSTALL_DIR" && return

    SHELL_NAME=$(basename "${SHELL:-/bin/sh}")
    case "$SHELL_NAME" in
        zsh)  RC="$HOME/.zshrc" ;;
        bash)
            RC="$HOME/.bashrc"
            [ "$(uname -s)" = "Darwin" ] && RC="$HOME/.bash_profile"
            ;;
        fish) RC="$HOME/.config/fish/config.fish" ;;
        *)    RC="" ;;
    esac

    EXPORT_LINE="export PATH=\"$INSTALL_DIR:\$PATH\""

    if [ -n "$RC" ]; then
        if ! grep -qF "$INSTALL_DIR" "$RC" 2>/dev/null; then
            printf '\n# Huitzo CLI\n%s\n' "$EXPORT_LINE" >> "$RC"
            echo "  Added PATH entry to $RC"
            echo "  Run: source $RC   (or restart your shell)"
        fi
    else
        echo "  Add this to your shell profile:"
        echo "    $EXPORT_LINE"
    fi
}

# Run the in-launcher capability prober so the one command finishes by
# telling the user exactly what is present and what is still missing
# (huitzo / claude / git), plus the host support classification. The
# prober ships INSIDE the launcher we just installed — no separate tool to
# fetch — which resolves the prober chicken-and-egg (roadmap S55).
capability_check() {
    echo ""
    echo "==> Checking local capabilities"
    # --launcher-detect exits non-zero when a required tool is missing; that
    # is informational here, not an install failure, so we never abort on it.
    "$INSTALL_DIR/huitzo" --launcher-detect --human || true
}

main
