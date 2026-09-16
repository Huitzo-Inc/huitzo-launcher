# Huitzo — Officially Supported OS / Shell Matrix

> Roadmap: `docs/roadmaps/huitzo-studio.md` row **S55**
> (`feat/launcher-one-command-bootstrap`).
> See also: `docs/architecture/huitzo-studio.md` §8.2 (the Onboard phase).

This is the **honest** support matrix for the one-command bootstrap and the
Huitzo Studio local runner. We publish what actually works and explicitly
mark what does **not**, rather than over-promising. Activation is gated on
hitting the activation floor **on this supported matrix** — not on covering
every environment.

The in-launcher capability prober (`huitzo --launcher-detect`) reports the
host's classification using the rules below. The prober classifies on OS
family only; the **install** path is stricter and is the authority on what can
actually be installed — see the `Known gap` note under *Classification rules*.

## Officially supported

| Platform | Shells | One-command bootstrap | Notes |
|----------|--------|-----------------------|-------|
| **macOS** (Apple Silicon only) | `zsh`, `bash`, `fish` | `curl -sSf https://raw.githubusercontent.com/Huitzo-Inc/huitzo-launcher/main/install.sh \| sh` | Primary target. Intel macOS (`x86_64`) is **unsupported** (D2) — no `macos-x86_64` CLI wheel is published at any Python version; both `install.sh` and the launcher refuse before anything is downloaded, rather than falling through to an unusable install. |
| **Linux** (**glibc only**, x86_64 + aarch64) | `bash`, `zsh`, `fish` | `curl -sSf https://raw.githubusercontent.com/Huitzo-Inc/huitzo-launcher/main/install.sh \| sh` | Primary target. **musl (Alpine) is unsupported** — the CLI release feed publishes `manylinux` wheels only, with zero `musllinux` builds, so pip on a musl host has nothing it can install. Both `install.sh` and the launcher refuse before anything is downloaded. |
| **WSL2** (Windows Subsystem for Linux, Ubuntu) | `bash`, `zsh` | run the Linux command **inside** the WSL distro | Treated as Linux. The launcher detects WSL and classifies it `supported`. |

A machine in the supported set with all three required tools present
(`huitzo`, `claude`, `git`) is **ready to pair a runner**.

## Native Windows (PowerShell) — CLI supported, runner on WSL2

The Huitzo **CLI** installs and runs on native Windows via the PowerShell
bootstrap:

```powershell
iwr -useb https://raw.githubusercontent.com/Huitzo-Inc/huitzo-launcher/main/install.ps1 | iex
```

`install.ps1` downloads the launcher, verifies its SHA-256 checksum, installs
to `%USERPROFILE%\.huitzo\bin`, and adds it to your user `PATH`. CLI and pack
development work natively.

The Studio **runner**, however, requires WSL2: its own outbound daemon and
process model assume a POSIX shell, and its `curl | sh` bootstrap is
POSIX-only. To pair a local runner on a Windows machine, install into WSL2
(Ubuntu) and run the Linux bootstrap there. The prober therefore classifies
native Windows off the runner matrix (`host.support = unsupported`) with a
reason that spells this out.

## Limitations

| Environment | Status | Why |
|-------------|--------|-----|
| **Native Windows (non-WSL) — Studio runner** | **WSL2 only** (CLI runs natively) | The **CLI** installs and runs natively (see the section above). The Studio **runner** assumes a POSIX shell + process model — its own outbound daemon and the `curl \| sh` bootstrap both target POSIX. To pair a local runner on Windows, install into **WSL2** (Ubuntu) and run the Linux bootstrap there. |
| **musl-based Linux (Alpine, and any musl distro)** | **Unsupported** (D8) | The Huitzo CLI ships only as a compiled wheel. `cli-v0.11.1` publishes 8 wheels and every Linux one is `manylinux2014` / `manylinux_2_17` / `manylinux_2_28`; there is no `musllinux` build. pip on a musl host computes `musllinux_*` platform tags and rejects all of them, so the install cannot succeed at any Python version. Use a **glibc** base image (`debian-slim`, `ubuntu`) or, on Windows, WSL2 with Ubuntu. `install.sh`'s `detect_platform` and the launcher's `Error::UnsupportedPlatform` both refuse before the launcher is downloaded — nothing is written to `$HUITZO_HOME`. |
| **Intel macOS (`x86_64`)** | **Unsupported** (D2) | `cli-release.json` carries `macos-arm64-cp312` and `macos-arm64-cp313` and no `macos-x86_64` key at any Python version, so there is no wheel to install. Refused early by the same two code paths. Apple Silicon (M-series) is required. |
| **Windows on ARM (`aarch64`)** | **Unsupported** | No launcher asset and no pinned `uv` asset is published for `aarch64-pc-windows-*`, so the bootstrap cannot stage itself. Refused by name rather than being handed an x86_64 or Linux platform key. |
| **Admin-locked / corporate-managed machines** | **Unsupported** | Locked-down corporate endpoints (no admin rights, MDM-enforced execution policy, mandatory EDR/antivirus that quarantines unsigned downloads, blocked package registries) break the install and/or the outbound runner channel in ways Huitzo cannot reliably detect or remediate from the launcher. The prober cannot positively identify "corporate-locked" from inside the process, so this is flagged in docs (and in onboarding copy) rather than auto-classified. Signed-binary distribution integrity that survives EDR is tracked separately as **S57** (`feat/runner-distribution-integrity`). **TLS-intercepting proxies are no longer part of this row** — they have a documented remedy; see the section below. |

## Behind a TLS-intercepting proxy

The launcher verifies TLS against the CA list **compiled into the binary**
(Mozilla's roots, via `webpki-roots`), not against the machine's certificate
store. That is deliberate — it is what makes the launcher behave the same on
every host — but it has one consequence worth stating plainly: a proxy that
terminates and re-signs TLS is rejected here no matter how thoroughly its root
was installed system-wide. The handshake fails with `UnknownIssuer`.

Two environment variables make such a host work:

| Variable | Value |
|----------|-------|
| `HTTPS_PROXY` (or `HTTP_PROXY` / `ALL_PROXY`) | `http://proxy.corp:8080`. The scheme-less spelling `proxy.corp:8080` is accepted too, as are `https://`, `socks5://` and `user:password@` (credentials are redacted before any error message is printed). `NO_PROXY=localhost,.internal.corp` carves out direct routes. A value the launcher cannot parse is a hard error, not a silent direct connection. |
| `HUITZO_CA_BUNDLE` | Path to a PEM file holding the intercepting CA. It **replaces** the bundled roots rather than adding to them — same semantics as `CURL_CA_BUNDLE` — so on a machine that must also reach the public internet, point it at the system bundle, which already holds both: `/etc/ssl/certs/ca-certificates.crt` (Debian/Ubuntu), `/etc/pki/tls/certs/ca-bundle.crt` (RHEL/Fedora). |

**The proxy variables were previously ignored.** Earlier launcher releases
never read `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` and always connected
direct, so a stale value — a leftover VPN profile, a decommissioned corporate
proxy — was harmless. It is not harmless now: the launcher routes through
whatever those variables name, so an install that previously worked will fail
if the proxy they point at is dead. Unset them, or list the hosts they must
not apply to in `NO_PROXY`, before installing.

```sh
export HTTPS_PROXY=http://proxy.corp:8080
export HTTP_PROXY=http://proxy.corp:8080
export NO_PROXY=localhost,127.0.0.1
export HUITZO_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
# uv runs as a subprocess with its own TLS trust — see the note below.
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
curl -sSf https://raw.githubusercontent.com/Huitzo-Inc/huitzo-launcher/main/install.sh | sh
```

If `HUITZO_CA_BUNDLE` points at something that yields no certificate, the
launcher **refuses** rather than quietly falling back to the bundled roots: a
silent fallback would turn a typo into the very TLS failure the variable was
set to fix. A DER/`.crt` binary file will not do — convert it first
(`openssl x509 -inform der -in corp.crt -out corp.pem`).

### What `HUITZO_CA_BUNDLE` does and does not cover

It covers every request the **launcher process** makes: the release feed,
`cli-release.json`, the wheel, the launcher self-update, the `uv` archive
download, and capability bundles.

It does **not** cover `uv` when the launcher runs it as a subprocess — `uv venv`
and `uv python install` are a separate binary with their own trust store, and
they fail with `invalid peer certificate: UnknownIssuer` behind an intercepting
proxy no matter what `HUITZO_CA_BUNDLE` says. `uv` reads the conventional
`SSL_CERT_FILE`, so set that to the same path, as in the snippet above.
Likewise the Python CLI once it is running, and `pip`/`uv` reaching a package
index, read their own configuration.

## Request timeouts

No request on the install or update path is unbounded (M12):

| Phase | Budget |
|-------|--------|
| Connect — DNS, TCP, proxy `CONNECT`, TLS handshake | 15 s |
| Response headers | 30 s |
| A whole feed request (release list, `cli-release.json`, a checksum) | 30 s |
| A whole artefact download (CLI wheel, launcher binary, `uv` archive) | 15 min |

The 15-minute figure is a floor of roughly 57 kB/s across the ~50 MB CLI
wheel — slower than any usable link, so a genuinely slow connection still
finishes, while a blackholed or stalled one fails with a message naming the
budget instead of hanging forever. It is a total budget, not an idle one.

## Classification rules (what the prober reports)

`huitzo --launcher-detect` emits `host.support` as one of:

- `supported` — macOS, Linux, or WSL2 (ready to pair a runner).
- `unsupported` — native Windows (the CLI runs, but the Studio runner needs
  WSL2; the `unsupported_reason` says exactly that), or any OS not in the
  supported set.

> **Known gap:** the prober classifies on OS family alone, so it still reports
> `supported` on Intel macOS and on musl/Alpine. The *install* path refuses
> both (`install.sh` `detect_platform`, and `Error::UnsupportedPlatform` in the
> launcher), so no such host can complete an install — but the report is
> optimistic. Teaching `prober.rs` the libc and macOS-arch distinctions is
> tracked separately.

Corporate-lock is **not** auto-detected (it is not reliably observable from
the process); it is documented here and surfaced in onboarding copy so users
on such machines are told up front.

## What "supported" means

- The one-command bootstrap installs the launcher + CLI and runs the
  capability check in a single copy-paste command.
- A required tool gap (`huitzo` / `claude` / `git` missing) is reported with a
  copy-paste install hint, and the command exits non-zero so a script can
  branch on readiness.
- **The exit code reflects required-tool presence only, not `host.support`.**
  A tooled native-Windows host (all of `huitzo`/`claude`/`git` present) exits
  `0` even though it prints `host.support: unsupported` — the runner-pairing
  gap is visible only in the JSON/human report, never in the exit code. A
  script that needs to gate on runner eligibility, not just tool presence,
  must inspect `host.support` itself.
- Distribution-integrity verification of downloaded binaries beyond the
  existing SHA-256 checksum (install scripts) and the Ed25519 signed
  capability/bundle trust root (launcher) is the scope of **S57** and is not
  claimed here.
