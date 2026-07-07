# Huitzo Launcher

Native launcher for the [Huitzo CLI](https://huitzo.ai). Manages a Python virtual environment, transparently keeps the CLI up to date, and ships the **in-launcher capability prober** that powers Huitzo Studio onboarding.

## What It Does

The launcher is a lightweight Rust binary (~3-5 MB) that:

1. **Discovers** Python 3.11+ on your system
2. **Creates** a managed virtual environment at `~/.huitzo/venv/`
3. **Installs** the `huitzo` CLI (compiled wheel from GitHub Releases, PyPI fallback)
4. **Checks** for updates in the background (non-blocking)
5. **Probes** your local prerequisites (`huitzo` / `claude` / `git`) and emits a structured capability report
6. **Execs** into the Python CLI -- zero runtime overhead

## Install — one command per supported OS

The bootstrap installs the launcher + CLI **and** runs the capability check
in a single copy-paste command. It asks for (and records) your informed
consent before installing any third-party software.

### macOS / Linux / WSL2

```sh
curl -sSf https://raw.githubusercontent.com/Huitzo-Inc/huitzo-launcher/main/install.sh | sh
```

### Homebrew (macOS)

```sh
brew install Huitzo-Inc/tap/huitzo
```

### Manual

Download the latest binary for your platform from [Releases](https://github.com/Huitzo-Inc/huitzo-launcher/releases).

> **Windows:** native Windows (non-WSL) is **not yet officially supported** —
> use **WSL2** and run the Linux command inside your distro. See
> [`docs/SUPPORT_MATRIX.md`](docs/SUPPORT_MATRIX.md) for the honest support
> matrix and rationale (Windows-non-WSL and admin-locked corporate machines
> are marked unsupported).

## Capability check

The launcher ships the prober that resolves the Studio onboarding
chicken-and-egg (the prober lives in the first thing you install, not in a
CLI you have not installed yet):

```sh
huitzo --launcher-detect          # structured JSON capability report
huitzo --launcher-detect --human  # readable summary
```

Exit code is `0` when every required tool (`huitzo`, `claude`, `git`) is
present and `1` when a required gap is open — so scripts can branch on
readiness. The JSON shape is the contract the Hub onboarding rail consumes.

## Consent & privacy

Before installing/executing any third-party software the launcher records
your decision (grant **and** decline) to a local, append-only,
**metadata-only** ledger at `~/.huitzo/consent.jsonl`. This is **not**
telemetry — it is never transmitted. No secrets are ever written there.

## Usage

```sh
# All commands pass through to the Python CLI
huitzo --version
huitzo pack new my-pack
huitzo pack dev

# Launcher-specific flags
huitzo --launcher-version              # Print launcher version
huitzo --launcher-bootstrap            # Force re-create the venv
huitzo --launcher-update               # Update the launcher binary itself
huitzo --launcher-detect               # Emit the capability report (JSON)
huitzo --launcher-detect --human       # Capability report (readable summary)
```

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `HUITZO_HOME` | Override home directory (default: `~/.huitzo/`) |
| `HUITZO_INDEX_URL` | Override PyPI index (e.g., TestPyPI URL) |
| `HUITZO_SKIP_UPDATE_CHECK` | Disable background update checks |
| `HUITZO_ASSUME_YES` | Grant install consent non-interactively (still recorded in the consent ledger) |
| `HUITZO_BOOTSTRAP_CONSENTED` | Set by `install.sh`/`install.ps1` after up-front consent so first-run bootstrap does not re-prompt |

## Build from Source

```sh
cargo build --release
```

## License

Source-available under the **Huitzo Source-Available License** — see
[LICENSE](LICENSE). The source is public for transparency and installation;
copying, modification, and redistribution require written permission from
Huitzo Inc.

"Huitzo" and the Huitzo logo are trademarks of Huitzo Inc. — see
[TRADEMARKS.md](TRADEMARKS.md).
