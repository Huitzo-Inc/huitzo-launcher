# Huitzo Launcher — AI Development Instructions

> **Single source of truth for AI tools working in this repository.**
> This is a submodule of the [Huitzo monorepo](https://github.com/Huitzo-Inc/huitzo).

## What This Repository Is

A lightweight Rust binary (~3-5 MB) that manages the Huitzo CLI's Python environment. It discovers Python, creates a managed venv, installs/updates the CLI, and execs into it with zero runtime overhead. It also ships the in-launcher capability prober that powers Huitzo Studio onboarding.

## Technology Stack

| Component | Version | Notes |
|-----------|---------|-------|
| Rust | edition 2024, MSRV 1.85 | Stable channel |
| serde | 1 | JSON serialization (derive) |
| ureq | 3 | HTTP client (minimal, no async runtime) |
| ed25519-dalek | 2 | Capability-report and SDK-bundle signature verification (`capabilities.rs`, `bundle.rs`) — not the release manifest |
| sha2 | 0.11 | SHA256 for binary integrity |
| nix | 0.31 | Unix process management (unix only) |
| flate2 | 1 | gzip decompression (pure Rust, no system zlib) |
| zip | 7 | Windows release archive (windows only) |

## Architecture

```
src/
├── main.rs           # CLI entry point, flag parsing, dispatch
├── lib.rs            # Crate root, re-exports
├── python.rs         # Python discovery (which, version check)
├── venv.rs           # Virtual environment creation
├── install.rs        # CLI wheel installation
├── update.rs         # Launcher self-update + CLI update check
├── manifest.rs       # Release manifest parsing
├── uv_manifest.rs    # uv release manifest (for bootstrapping uv itself)
├── uv.rs             # uv bootstrap and invocation
├── download.rs       # Binary download + integrity verification
├── bundle.rs         # Release bundle extraction
├── keys.rs           # Ed25519 public keys + signature verification
├── consent.rs        # Consent ledger (~/.huitzo/consent.jsonl)
├── capabilities.rs   # Capability detection types
├── prober.rs         # Capability prober (huitzo/claude/git detection)
├── local_cli.rs      # Local huitzo_cli detection (delegate / run-local / refuse)
├── exec.rs           # Exec into Python CLI
├── dirs.rs           # Platform-specific directory resolution
└── errors.rs         # Error types
```

**Key design decisions (with rationale):**

- **No async runtime** — the launcher does short-lived I/O (HTTP GET, file writes, process spawn). An async runtime would add ~1 MB to the binary for no throughput benefit. `ureq` (blocking HTTP) is the right fit.
- **Never hijack a source checkout** (#53) — before delegating to the managed venv the launcher checks whether it was invoked from a `huitzo-cli` checkout or an environment that already has `huitzo_cli`, and runs *that* interpreter instead (announcing it on stderr), or refuses when it cannot. Detection is filesystem-only — it never spawns an interpreter to probe — because it runs on every invocation (~3 µs). An **explicit** `VIRTUAL_ENV` / `UV_PROJECT_ENVIRONMENT` is trusted; a checkout found by **walking up from the cwd** is trusted only if it and its `.venv` are owned by the invoking user and not world-writable (git's `safe.directory` lesson). `--use-installed` / `HUITZO_LAUNCHER_FORCE=1` opt out.
- **`-P` on the Python exec line** — the CLI is always started as `python -P -m huitzo_cli` so the invocation directory never lands on `sys.path`. The managed venv is guaranteed 3.11+ so `-P` always applies there; a locally detected interpreter gets it only when its `pyvenv.cfg` proves 3.11+ (the flag does not exist before then).
- **Exec, don't subprocess** — after bootstrapping, the launcher `exec`s into the Python CLI rather than spawning it as a child process. This means zero memory overhead while the CLI runs and correct signal propagation (Ctrl-C goes to the CLI, not the launcher).
- **Pure Rust decompression** — `flate2` with `miniz_oxide` backend and `zip` with `deflate` backend avoid system library dependencies. This is necessary for cross-compilation to Linux musl and macOS.
- **Release manifest integrity is SHA-256 only, unsigned** — `download.rs` fetches `cli-release.json` and verifies each wheel against a SHA-256 published *inside that same feed*. There is no signature on the manifest itself, so a compromised feed (or an unpinned `HUITZO_RELEASE_URL`/`HUITZO_RELEASE_DOWNLOAD_URL`) controls both the hash and the wheel it hashes. Ed25519 signing of the release manifest is tracked separately as **S57** and is not implemented — do not claim it is.
- **Consent ledger is append-only and local** — `~/.huitzo/consent.jsonl` records every install consent decision (grant and decline) but is never transmitted. This is a legal requirement, not a feature preference.

## Build & Test

```bash
# Build (release, optimized for size)
cargo build --release

# Run tests
cargo test

# Run specific test
cargo test prober_test

# Check formatting
cargo fmt --check

# Lint
cargo clippy -- -D warnings
```

**Release profile** is optimized for binary size: `opt-level = "z"`, LTO, single codegen unit, symbol stripping, abort on panic. The launcher is downloaded by every user; every kilobyte matters.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `HUITZO_HOME` | Override home directory (default: `~/.huitzo/`) |
| `HUITZO_INDEX_URL` | Override PyPI index (e.g., TestPyPI URL) |
| `HUITZO_SKIP_UPDATE_CHECK` | Disable background update checks |
| `HUITZO_ASSUME_YES` | Grant install consent non-interactively |
| `HUITZO_BOOTSTRAP_CONSENTED` | Set by install scripts after up-front consent |
| `HUITZO_LAUNCHER_FORCE` | Always delegate to `~/.huitzo/venv`, skipping local-CLI detection (same as `--use-installed`) |
| `HUITZO_NO_MODIFY_PATH` | Skip the installer's `PATH` modification (`install.sh` / `install.ps1`) |

## What NOT to Do

- **Don't add an async runtime** — the launcher's I/O pattern is request-response, not concurrent connections. Tokio would add binary size and complexity for no benefit.
- **Don't add system library dependencies** — the launcher must cross-compile to Linux musl and macOS. Every C library dependency is a cross-compilation hazard. Pure Rust alternatives exist for everything we need.
- **Don't change the consent ledger format** — `consent.jsonl` is append-only JSON lines. Changing the format breaks the audit trail. If new fields are needed, add them; never remove or rename existing ones.
- **Don't add telemetry** — the launcher must never phone home beyond what's necessary for its function (release manifest fetch, wheel download). The consent ledger is local-only by design.
- **Don't change the `livecheck` regex in the Homebrew tap without updating `update.rs`** — both filter on `v*` tags. A mismatch means `brew upgrade` and `huitzo --launcher-update` disagree on the latest version.
