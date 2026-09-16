# Huitzo Launcher

Native launcher for the [Huitzo CLI](https://huitzo.ai). Manages a Python virtual environment, transparently keeps the CLI up to date, and ships the **in-launcher capability prober** that powers Huitzo Studio onboarding.

## What It Does

The launcher is a lightweight Rust binary (~3-5 MB) that:

1. **Selects** a Python the published CLI wheels support -- reusing one already on your system, or downloading a managed CPython when none matches. You do not need to install Python yourself.
2. **Creates** a managed virtual environment at `~/.huitzo/venv/`
3. **Installs** the `huitzo` CLI (compiled wheel from GitHub Releases)
4. **Checks** for updates in the background (non-blocking)
5. **Probes** your local prerequisites (`huitzo` / `claude` / `git`) and emits a structured capability report
6. **Execs** into the Python CLI -- zero runtime overhead

## Install — one command per supported OS

The bootstrap installs the launcher + CLI **and** runs the capability check
in a single copy-paste command. It asks for (and records) your informed
consent before installing any third-party software.

### macOS / Linux / WSL2

```sh
curl -sSf https://huitzo.ai/install.sh | sh
```

Run in a terminal, this prompts for consent before installing. For
non-interactive environments (CI, containers, provisioning scripts), grant
consent up front with `HUITZO_ASSUME_YES=1`:

```sh
curl -sSf https://huitzo.ai/install.sh | HUITZO_ASSUME_YES=1 sh
```

### Windows (PowerShell)

```powershell
iwr -useb https://raw.githubusercontent.com/Huitzo-Inc/huitzo-launcher/main/install.ps1 | iex
```

The Huitzo **CLI** installs and runs natively on Windows — no WSL required.
The Studio **runner** requires **WSL2** (its own outbound daemon and process
model assume a POSIX shell, and its bootstrap is the `curl | sh` script): to
pair a local runner on a Windows machine, install into WSL2 (Ubuntu) and run
the Linux command above inside your distro. See
[`docs/SUPPORT_MATRIX.md`](docs/SUPPORT_MATRIX.md) for the full support
matrix and rationale (admin-locked corporate machines are marked
unsupported).

### Homebrew (macOS)

```sh
brew install Huitzo-Inc/tap/huitzo
```

### Manual

Download the latest binary for your platform from [Releases](https://github.com/Huitzo-Inc/huitzo-launcher/releases).

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
huitzo --use-installed <command>       # Force the managed ~/.huitzo/venv, skipping
                                       # local-checkout detection
```

### Running from a source checkout

Invoked from a `huitzo-cli` source checkout — or with an environment active
that already has `huitzo_cli` installed — the launcher runs **that** CLI
instead of the managed one and says so on stderr. It never silently substitutes
a different version. If a checkout is detected but no local `huitzo_cli` can be
found, the launcher refuses and names both paths rather than running code you
did not ask for. Use `--use-installed` (or `HUITZO_LAUNCHER_FORCE=1`) to
delegate to `~/.huitzo/venv` deliberately.

A checkout discovered by walking up from the current directory is only used
when it — and the `.venv` it selects — belong to you and are not
world-writable, so a `pyproject.toml` left in a shared directory cannot decide
which interpreter runs. An environment you activated yourself (`VIRTUAL_ENV`,
`UV_PROJECT_ENVIRONMENT`) is always honoured.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `HUITZO_HOME` | Override home directory (default: `~/.huitzo/`) |
| `HUITZO_INDEX_URL` | Override PyPI index (e.g., TestPyPI URL) |
| `HUITZO_SKIP_UPDATE_CHECK` | Disable background update checks |
| `HUITZO_ASSUME_YES` | Grant install consent non-interactively (still recorded in the consent ledger) |
| `HUITZO_BOOTSTRAP_CONSENTED` | Set by `install.sh`/`install.ps1` after up-front consent so first-run bootstrap does not re-prompt |
| `HUITZO_LAUNCHER_FORCE` | Always delegate to `~/.huitzo/venv`, skipping local-checkout detection (same as `--use-installed`) |
| `HUITZO_NO_MODIFY_PATH` | Skip the installer's `PATH` modification (`install.sh` / `install.ps1`) |
| `HUITZO_CA_BUNDLE` | PEM file of trust anchors to verify TLS against **instead of** the CA list compiled into the launcher. Needed behind a TLS-intercepting proxy, which the bundled list rejects by design. May hold a chain; on a managed machine the system bundle (`/etc/ssl/certs/ca-certificates.crt`) is usually the right value, since it already carries the public roots plus the corporate one. Covers the launcher's own requests; `uv` runs as a subprocess and needs `SSL_CERT_FILE` set to the same path. |
| `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` | Proxy to route the release-feed and download requests through, e.g. `http://proxy.corp:8080`. The scheme-less form (`proxy.corp:8080`) is accepted too, as are `https://`, `socks5://` and `user:password@` (credentials are redacted out of error messages). A value that cannot be parsed is refused rather than silently bypassed. |
| `NO_PROXY` | Comma-separated hosts to reach directly, e.g. `localhost,.internal.corp`. |

**These proxy variables used to be ignored.** Earlier launcher releases never
read them and always connected direct, so a stale value — a leftover VPN
profile, a decommissioned corporate proxy — did no harm. It does now: the
launcher routes through whatever they name, and an install that used to work
will fail if that proxy is dead. Unset the variable, or name the hosts it must
not apply to in `NO_PROXY`.

Requests on the install and update path are bounded: 15 s to connect (DNS, TCP,
proxy `CONNECT` and the TLS handshake), 30 s for response headers, and then 30 s
for a whole feed request or 15 minutes for a whole artefact download. Nothing
hangs indefinitely; a TLS failure names the proxy and CA settings that were in
effect. See [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md), "Behind a
TLS-intercepting proxy".

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
