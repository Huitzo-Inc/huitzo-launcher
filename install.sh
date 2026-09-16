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
# Supported: macOS on Apple Silicon, Linux on glibc (x86_64 / aarch64), and
# WSL2. Intel macOS (D2), musl/Alpine (D8), native Windows (non-WSL) and
# admin-locked corporate machines are NOT supported — detect_platform refuses
# the first two before anything is downloaded. See
# https://github.com/Huitzo-Inc/huitzo-launcher/blob/main/docs/SUPPORT_MATRIX.md
#
# Environment variables:
#   HUITZO_HOME            — override install root (default: ~/.huitzo)
#   HUITZO_NO_MODIFY_PATH  — set to 1 to skip shell profile modification
#   HUITZO_ASSUME_YES      — set to 1 to grant install consent non-interactively
#                            (recorded in the consent ledger for auditability)
set -eu

REPO="Huitzo-Inc/huitzo-launcher"

# Remember whether the caller pointed us somewhere other than the default home
# BEFORE we apply the default: a sandboxed/alternate install must not reason
# about — let alone mutate — the machine-wide Python environment.
if [ -n "${HUITZO_HOME:-}" ]; then
    HUITZO_HOME_IS_OVERRIDE=1
else
    HUITZO_HOME_IS_OVERRIDE=0
fi
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

    answer=""
    if [ "${HUITZO_ASSUME_YES:-0}" = "1" ]; then
        echo "  HUITZO_ASSUME_YES=1 — proceeding with recorded consent."
    else
        # Read consent from the controlling terminal. With the documented
        # `curl ... | sh` invocation sh's stdin is the script pipe (not a TTY),
        # so [ -t 0 ] is false and we must prompt on /dev/tty; fall back to
        # stdin when it is itself a TTY. Only a genuinely non-interactive run
        # (CI, `docker run` without -t, no controlling terminal) fails closed.
        #
        # A bare [ -r /dev/tty ] passes even with no controlling terminal (the
        # later read then fails), so probe that /dev/tty can actually be OPENED.
        # `true` (a regular builtin) is used on purpose: unlike `exec`, a
        # redirect failure here won't abort a `set -e` POSIX shell.
        consent_tty=0
        # shellcheck disable=SC2217
        if { true < /dev/tty; } 2>/dev/null; then consent_tty=1; fi

        if [ -t 0 ]; then
            printf '  Proceed? [y/N] '
            read -r answer || answer=""
        elif [ "$consent_tty" = "1" ]; then
            printf '  Proceed? [y/N] ' > /dev/tty
            read -r answer < /dev/tty || answer=""
        else
            echo "  No interactive terminal detected. Re-run with HUITZO_ASSUME_YES=1"
            echo "  to consent non-interactively, or run the command in a terminal."
            exit 1
        fi
        case "$answer" in
            y|Y|yes|YES) : ;;
            *) echo "  Declined. Nothing was installed."; exit 1 ;;
        esac
    fi

    # Tell the launcher's first-run bootstrap that consent was already given,
    # so the user is asked exactly once (not again on first 'huitzo' run).
    # The launcher records the GRANT on this path — no install without an
    # audit trail. We deliberately do NOT export a session-wide
    # HUITZO_ASSUME_YES: this consent covers only the bootstrap install, and
    # the capability check that follows is read-only (installs nothing).
    export HUITZO_BOOTSTRAP_CONSENTED=1
}

# Does this host run musl libc rather than glibc?
#
# Mirrors `host_is_musl()` in src/download.rs and must stay in step with it:
# positive evidence only, and an explicit glibc check so `apt install musl` on
# a Debian host does not get that host refused. `ldd --version` is not used —
# busybox's ldd on Alpine writes usage to stderr and exits non-zero, so the
# check would have to parse a failure, whereas the loader path is a plain
# filesystem fact present on every musl system.
host_is_musl() {
    [ -f /etc/alpine-release ] && return 0
    for loader in /lib/ld-musl-*.so.1; do
        [ -e "$loader" ] || continue
        # A musl loader alongside a glibc one means a cross-libc toolchain on a
        # glibc host, which is supported.
        for glibc in /lib/x86_64-linux-gnu/libc.so.6 /lib/aarch64-linux-gnu/libc.so.6 \
                     /lib64/libc.so.6 /lib/libc.so.6 /lib64/ld-linux-x86-64.so.2 \
                     /lib/ld-linux-aarch64.so.1; do
            [ -e "$glibc" ] && return 1
        done
        return 0
    done
    return 1
}

# Refuse an unsupported host BEFORE anything is fetched. `main` calls this
# first, ahead of the consent prompt and the launcher download, so an Intel Mac
# or an Alpine container never gets asked to approve an install that cannot
# work and never has a byte written to $HUITZO_HOME.
#
# The wording here is the same wording the launcher itself prints
# (`Error::UnsupportedPlatform` in src/errors.rs) — D2 and D8 are one decision
# each, stated once.
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        linux)  OS_TARGET="unknown-linux-musl" ;;
        darwin) OS_TARGET="apple-darwin" ;;
        *)
            echo "Error: Huitzo does not support this platform."
            echo "  Detected: $OS on $ARCH"
            echo "  Required: macOS (Apple Silicon), Linux/glibc (x86_64, aarch64), or Windows (x86_64)"
            echo ""
            echo "Nothing was installed. See"
            echo "https://github.com/Huitzo-Inc/huitzo-launcher/blob/main/docs/SUPPORT_MATRIX.md"
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)  ARCH_TARGET="x86_64" ;;
        aarch64|arm64) ARCH_TARGET="aarch64" ;;
        *)
            echo "Error: Huitzo does not support this platform."
            echo "  Detected: $OS on $ARCH"
            echo "  Required: Apple Silicon (arm64), or Linux/glibc on x86_64 or aarch64"
            echo ""
            echo "Nothing was installed. See"
            echo "https://github.com/Huitzo-Inc/huitzo-launcher/blob/main/docs/SUPPORT_MATRIX.md"
            exit 1
            ;;
    esac

    # D2 — Intel macOS is unsupported. The CLI ships only as a compiled wheel
    # and cli-release.json carries macos-arm64 keys only; there is no
    # macos-x86_64 build at any Python version, so the launcher would download
    # and then find nothing to install.
    if [ "$OS" = "darwin" ] && [ "$ARCH_TARGET" = "x86_64" ]; then
        echo "Error: Huitzo does not support Intel macOS."
        echo "  Detected: macOS on x86_64 (Intel)"
        echo "  Required: Apple Silicon (arm64 — M-series)"
        echo ""
        echo "The Huitzo CLI ships only as a compiled wheel and no macos-x86_64 wheel"
        echo "is published at any Python version, so there is nothing that could be"
        echo "installed here. Run Huitzo on an Apple Silicon Mac."
        echo ""
        echo "Nothing was installed. See"
        echo "https://github.com/Huitzo-Inc/huitzo-launcher/blob/main/docs/SUPPORT_MATRIX.md"
        exit 1
    fi

    # D8 — musl/Alpine is unsupported. The release feed publishes manylinux
    # wheels only (zero musllinux), and pip on a musl host computes
    # musllinux_* tags and rejects every one of them.
    if [ "$OS" = "linux" ] && host_is_musl; then
        echo "Error: Huitzo does not support musl-based Linux (Alpine)."
        echo "  Detected: Linux on $ARCH_TARGET with musl libc"
        echo "  Required: glibc"
        echo ""
        echo "The Huitzo CLI ships only as a compiled wheel and the release feed"
        echo "publishes manylinux wheels only — there is no musllinux build, so pip on"
        echo "a musl host has nothing it can install."
        echo ""
        echo "Use a glibc base image instead (for example \`debian-slim\` or \`ubuntu\`),"
        echo "or, on Windows, WSL2 with Ubuntu."
        echo ""
        echo "Nothing was installed. See"
        echo "https://github.com/Huitzo-Inc/huitzo-launcher/blob/main/docs/SUPPORT_MATRIX.md"
        exit 1
    fi

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

    # A pip-installed "huitzo" can shadow the launcher on PATH, so we REPORT it.
    # We do not uninstall it: the user's global Python is not ours to mutate, and
    # a silent `pip uninstall` during a bootstrap is exactly the kind of implicit
    # side effect this installer must not have. When HUITZO_HOME points somewhere
    # other than the default, the machine-wide interpreter is not even in scope.
    if [ "$HUITZO_HOME_IS_OVERRIDE" = "1" ]; then
        return 0
    fi

    for pip_cmd in pip3 pip; do
        if command -v "$pip_cmd" > /dev/null 2>&1; then
            if "$pip_cmd" show huitzo > /dev/null 2>&1; then
                echo "  Note: a pip-installed 'huitzo' exists in $pip_cmd's environment."
                echo "        It may shadow $INSTALL_DIR/huitzo on your PATH. Remove it with:"
                echo "          $pip_cmd uninstall huitzo"
            fi
            break
        fi
    done

    return 0
}

download_and_verify() {
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    TMPBIN="$TMPDIR/huitzo"

    echo "  Downloading $ASSET..."
    curl -sSfL "$DOWNLOAD_URL" -o "$TMPBIN"

    # Verification is unconditional. Every path out of this block either has a
    # real, matching SHA-256 or exits non-zero: an installer that "verifies"
    # by assuming success is worse than one that never claimed to.
    echo "  Verifying checksum..."
    EXPECTED=$(curl -sSfL "$SHA256_URL" | awk '{print $1}' | tr 'A-F' 'a-f')
    # Anything that is not a 64-char hex digest (empty body, an error page, a
    # truncated fetch) is a verification failure, not something to compare against.
    if ! printf '%s' "$EXPECTED" | grep -Eq '^[0-9a-f]{64}$'; then
        echo "Error: Published checksum for $ASSET is missing or not a SHA-256 digest."
        echo "  Refusing to install an unverified binary."
        echo "  Checksum URL: $SHA256_URL"
        exit 1
    fi

    if command -v sha256sum > /dev/null 2>&1; then
        ACTUAL=$(sha256sum "$TMPBIN" | awk '{print $1}' | tr 'A-F' 'a-f')
    elif command -v shasum > /dev/null 2>&1; then
        ACTUAL=$(shasum -a 256 "$TMPBIN" | awk '{print $1}' | tr 'A-F' 'a-f')
    elif command -v openssl > /dev/null 2>&1; then
        # openssl 3.x prints "SHA2-256(file)= <hex>", openssl 1.x "SHA256(file)= <hex>"
        ACTUAL=$(openssl dgst -sha256 "$TMPBIN" | awk '{print $NF}' | tr 'A-F' 'a-f')
    else
        echo "Error: No SHA-256 tool found (tried sha256sum, shasum, openssl)."
        echo "  Refusing to install an unverified binary. Install one of them"
        echo "  (e.g. coreutils, perl, or openssl) and re-run this installer."
        exit 1
    fi

    if [ "$ACTUAL" != "$EXPECTED" ]; then
        echo "Error: Checksum mismatch — download may be corrupted."
        echo "  Expected: $EXPECTED"
        echo "  Got:      $ACTUAL"
        exit 1
    fi
    echo "  Checksum OK"

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
