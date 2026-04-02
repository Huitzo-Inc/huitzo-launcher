#!/bin/sh
# Huitzo CLI Launcher Installer
# Usage: curl -sSf https://raw.githubusercontent.com/Huitzo-Inc/huitzo-launcher/main/install.sh | sh
set -eu

REPO="Huitzo-Inc/huitzo-launcher"
INSTALL_DIR="${HUITZO_HOME:-$HOME/.huitzo}/bin"

main() {
    detect_platform
    fetch_latest_version
    download_binary
    install_binary
    add_to_path
    echo ""
    echo "Huitzo CLI launcher installed to: $INSTALL_DIR/huitzo"
    echo "Run 'huitzo --launcher-version' to verify."
}

detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        linux)  OS_TARGET="unknown-linux-musl" ;;
        darwin) OS_TARGET="apple-darwin" ;;
        *)      echo "Error: Unsupported OS: $OS"; exit 1 ;;
    esac

    case "$ARCH" in
        x86_64|amd64)  ARCH_TARGET="x86_64" ;;
        aarch64|arm64) ARCH_TARGET="aarch64" ;;
        *)             echo "Error: Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    ASSET="huitzo-${ARCH_TARGET}-${OS_TARGET}"
    echo "Platform: ${ARCH_TARGET}-${OS_TARGET}"
}

fetch_latest_version() {
    echo "Fetching latest release..."
    RELEASE_URL="https://api.github.com/repos/$REPO/releases/latest"
    DOWNLOAD_URL=$(curl -sSf "$RELEASE_URL" | grep "browser_download_url.*$ASSET\"" | head -1 | cut -d '"' -f 4)

    if [ -z "$DOWNLOAD_URL" ]; then
        echo "Error: Could not find binary for $ASSET"
        echo "Check releases at: https://github.com/$REPO/releases"
        exit 1
    fi
}

download_binary() {
    TMPDIR=$(mktemp -d)
    echo "Downloading $ASSET..."
    curl -sSfL "$DOWNLOAD_URL" -o "$TMPDIR/huitzo"
    chmod +x "$TMPDIR/huitzo"
}

install_binary() {
    mkdir -p "$INSTALL_DIR"
    mv "$TMPDIR/huitzo" "$INSTALL_DIR/huitzo"
    rm -rf "$TMPDIR"
}

add_to_path() {
    case "$INSTALL_DIR" in
        */.huitzo/bin)
            # Add to PATH if not already there
            if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
                SHELL_NAME=$(basename "${SHELL:-/bin/sh}")
                case "$SHELL_NAME" in
                    zsh)  RC="$HOME/.zshrc" ;;
                    bash) RC="$HOME/.bashrc" ;;
                    fish) RC="$HOME/.config/fish/config.fish" ;;
                    *)    RC="" ;;
                esac

                if [ -n "$RC" ] && [ -f "$RC" ]; then
                    if ! grep -q "$INSTALL_DIR" "$RC" 2>/dev/null; then
                        echo "" >> "$RC"
                        echo "# Huitzo CLI" >> "$RC"
                        echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$RC"
                        echo "Added $INSTALL_DIR to PATH in $RC"
                        echo "Run 'source $RC' or restart your shell."
                    fi
                else
                    echo "Add this to your shell profile:"
                    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
                fi
            fi
            ;;
    esac
}

main
