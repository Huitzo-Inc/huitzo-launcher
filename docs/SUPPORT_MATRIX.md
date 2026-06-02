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
host's classification using exactly the rules below, so the matrix and the
code cannot silently diverge.

## Officially supported

| Platform | Shells | One-command bootstrap | Notes |
|----------|--------|-----------------------|-------|
| **macOS** (Apple Silicon + Intel) | `zsh`, `bash`, `fish` | `curl -sSf https://huitzo.ai/install.sh \| sh` | Primary target. |
| **Linux** (glibc + musl, x86_64 + aarch64) | `bash`, `zsh`, `fish` | `curl -sSf https://huitzo.ai/install.sh \| sh` | Primary target. |
| **WSL2** (Windows Subsystem for Linux, Ubuntu) | `bash`, `zsh` | run the Linux command **inside** the WSL distro | Treated as Linux. The launcher detects WSL and classifies it `supported`. |

A machine in the supported set with all three required tools present
(`huitzo`, `claude`, `git`) is **ready to pair a runner**.

## NOT yet supported

| Environment | Status | Why |
|-------------|--------|-----|
| **Native Windows (non-WSL)** — `PowerShell` / `cmd` | **Unsupported** | The runner's outbound daemon, the launcher's POSIX `execvp` hand-off to the CLI, and the `curl \| sh` bootstrap all assume a POSIX shell + process model. Native-Windows process/PATH/signal semantics differ enough that we will not claim support until it is tested end-to-end. **Use WSL2 instead** — it is fully supported and is the documented Windows path. `install.ps1` will install the launcher binary but prints this warning and does not promise runner pairing. |
| **Admin-locked / corporate-managed machines** | **Unsupported** | Locked-down corporate endpoints (no admin rights, MDM-enforced execution policy, mandatory EDR/antivirus that quarantines unsigned downloads, TLS-intercepting proxies, blocked package registries) break the install and/or the outbound runner channel in ways Huitzo cannot reliably detect or remediate from the launcher. The prober cannot positively identify "corporate-locked" from inside the process, so this is flagged in docs (and in onboarding copy) rather than auto-classified. Signed-binary distribution integrity that survives EDR is tracked separately as **S57** (`feat/runner-distribution-integrity`). |

## Classification rules (what the prober reports)

`huitzo --launcher-detect` emits `host.support` as one of:

- `supported` — macOS, Linux, or WSL2.
- `unsupported` — native Windows (with a `unsupported_reason` pointing here),
  or any OS not in the supported set.

Corporate-lock is **not** auto-detected (it is not reliably observable from
the process); it is documented here and surfaced in onboarding copy so users
on such machines are told up front.

## What "supported" means

- The one-command bootstrap installs the launcher + CLI and runs the
  capability check in a single copy-paste command.
- A required tool gap (`huitzo` / `claude` / `git` missing) is reported with a
  copy-paste install hint, and the command exits non-zero so a script can
  branch on readiness.
- Distribution-integrity verification of downloaded binaries beyond the
  existing SHA-256 checksum (install scripts) and the Ed25519 signed
  capability/bundle trust root (launcher) is the scope of **S57** and is not
  claimed here.
