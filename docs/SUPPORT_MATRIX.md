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
host's classification using the rules below. The prober and the install path
share one platform resolver (`download::current_platform`), so a host the
installer refuses is reported `unsupported` — in the installer's own wording —
rather than being classified on OS family alone.

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
| **Admin-locked / corporate-managed machines** | **Unsupported** | Locked-down corporate endpoints (no admin rights, MDM-enforced execution policy, mandatory EDR/antivirus that quarantines unsigned downloads, TLS-intercepting proxies, blocked package registries) break the install and/or the outbound runner channel in ways Huitzo cannot reliably detect or remediate from the launcher. The prober cannot positively identify "corporate-locked" from inside the process, so this is flagged in docs (and in onboarding copy) rather than auto-classified. Signed-binary distribution integrity that survives EDR is tracked separately as **S57** (`feat/runner-distribution-integrity`). |

## Classification rules (what the prober reports)

`huitzo --launcher-detect` emits `host.support` as one of:

- `supported` — macOS (Apple Silicon), glibc Linux, or WSL2 (ready to pair a
  runner).
- `unsupported` — in precedence order:
  1. **A host the installer refuses**: Intel macOS (D2), musl/Alpine (D8),
     Windows on ARM, or any unrecognised OS/arch. The prober calls the same
     `download::current_platform()` the bootstrap calls before it downloads
     anything, and `unsupported_reason` is that refusal's own rendered text —
     one wording per decision, so the report and the installer cannot drift.
  2. **Native Windows (non-WSL)**: the CLI runs, but the Studio runner needs
     WSL2; the `unsupported_reason` says exactly that.

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
