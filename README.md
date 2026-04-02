# Huitzo Launcher

Native launcher for the [Huitzo CLI](https://huitzo.ai). Manages a Python virtual environment and transparently keeps the CLI up to date.

## What It Does

The launcher is a lightweight Rust binary (~3-5 MB) that:

1. **Discovers** Python 3.11+ on your system
2. **Creates** a managed virtual environment at `~/.huitzo/venv/`
3. **Installs** the `huitzo` CLI from PyPI
4. **Checks** for updates in the background (non-blocking)
5. **Execs** into the Python CLI -- zero runtime overhead

## Install

### Homebrew (macOS)

```sh
brew install huitzo/tap/huitzo
```

### curl (Linux / macOS)

```sh
curl -sSf https://raw.githubusercontent.com/Huitzo-Inc/huitzo-launcher/main/install.sh | sh
```

### Manual

Download the latest binary for your platform from [Releases](https://github.com/Huitzo-Inc/huitzo-launcher/releases).

## Usage

```sh
# All commands pass through to the Python CLI
huitzo --version
huitzo pack new my-pack
huitzo pack dev

# Launcher-specific flags
huitzo --launcher-version      # Print launcher version
huitzo --launcher-bootstrap    # Force re-create the venv
huitzo --launcher-update       # Update the launcher binary itself
```

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `HUITZO_HOME` | Override home directory (default: `~/.huitzo/`) |
| `HUITZO_INDEX_URL` | Override PyPI index (e.g., TestPyPI URL) |
| `HUITZO_SKIP_UPDATE_CHECK` | Disable background update checks |

## Build from Source

```sh
cargo build --release
```

## License

Proprietary - Huitzo Inc.
