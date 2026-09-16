// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

mod bundle;
mod capabilities;
mod consent;
mod dirs;
mod download;
mod errors;
mod exec;
mod install;
mod keys;
mod local_cli;
mod manifest;
mod prober;
mod python;
mod update;
mod uv;
mod uv_manifest;
mod venv;

use std::path::Path;

use errors::Error;
use local_cli::{Decision, LocalSource};
use manifest::Manifest;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Opt out of local-CLI detection (#53): delegate to the managed venv
    // unconditionally. Consumed here — like `--launcher-trust-rotate` — so it
    // never reaches the Python CLI on exec.
    let use_installed = args.iter().any(|a| a == local_cli::USE_INSTALLED_FLAG);
    let args: Vec<String> = args
        .into_iter()
        .filter(|a| a != local_cli::USE_INSTALLED_FLAG)
        .collect();

    // Intercept launcher-specific flags
    if args.iter().any(|a| a == "--launcher-version") {
        println!("huitzo-launcher {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    // Capability prober (S55): emit the local prerequisite report consumed
    // by S56's Hub onboarding rail. `--launcher-detect` prints JSON to
    // stdout for machine consumption; `--launcher-detect --human` prints a
    // readable summary. The exit code is 0 when all required tools are
    // present, 1 when a required gap is open — so a script can branch on it.
    if args.iter().any(|a| a == "--launcher-detect") {
        let human = args.iter().any(|a| a == "--human");
        let report = prober::probe();
        if human {
            print_detect_human(&report);
        } else {
            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("Error: failed to serialize capability report: {e}");
                    std::process::exit(1);
                }
            }
        }
        std::process::exit(if report.ready() { 0 } else { 1 });
    }

    if args.iter().any(|a| a == "--launcher-bootstrap") {
        if let Err(e) = bootstrap() {
            eprintln!("Error: {e}");
            std::process::exit(errors::exit_code(&e));
        }
        println!("Environment bootstrapped successfully.");
        // After bootstrap, continue to exec if there are other args
        let filtered: Vec<String> = args
            .into_iter()
            .filter(|a| a != "--launcher-bootstrap")
            .collect();
        if filtered.is_empty() {
            return;
        }
        run(filtered);
        return;
    }

    if args.iter().any(|a| a == "--launcher-update") {
        match update::self_update() {
            // The explicit path settles the same bookkeeping the automatic one
            // does, so a manual update does not leave a staged record behind
            // for the next launch to act on again. Only a real install moves
            // `launcher_version` (M13).
            Ok(update::UpdateOutcome::Updated(version)) => {
                update::settle_pending(Some(&version));
            }
            Ok(
                update::UpdateOutcome::AlreadyCurrent | update::UpdateOutcome::DeferredToHomebrew,
            ) => {
                update::settle_pending(None);
            }
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(errors::exit_code(&e));
            }
        }
        return;
    }

    // Emergency TOFU rotation: operator opts in to overwrite a pinned key
    // after a deployment-root rotation that did not go through the routine
    // overlap-window mechanism in `keys` (#26) — or went through it and
    // expired unused. The flag is consumed here so it never reaches the
    // Python CLI on exec.
    let force_trust_rotate = args.iter().any(|a| a == "--launcher-trust-rotate");
    let args: Vec<String> = args
        .into_iter()
        .filter(|a| a != "--launcher-trust-rotate")
        .collect();

    run_with(args, force_trust_rotate, use_installed);
}

/// Continue into the CLI after an explicit `--launcher-bootstrap`.
///
/// `use_installed` is forced on: asking for a bootstrap IS asking for the
/// managed environment, so the run that follows must not be redirected to a
/// local checkout (#53).
fn run(args: Vec<String>) {
    run_with(args, false, true);
}

/// Refresh the active deployment's capability document and re-stage the
/// SDK bundle if the marker file `~/.huitzo/.needs-capability-refresh` is
/// present (written by `huitzo login` and `huitzo config set api_url` on
/// the Python side). Best-effort: a network failure must not block exec
/// into the CLI, but a trust-violation or signature-failure must.
///
/// Returns `true` if the launcher should refuse to continue (trust /
/// signature failure). Network errors are logged and treated as soft
/// failures so already-staged bundles keep working offline.
fn refresh_capabilities_if_needed(force_trust_rotate: bool) -> bool {
    let marker = dirs::capability_refresh_marker();
    if !marker.exists() {
        return false;
    }
    let api_url = match std::fs::read_to_string(&marker) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return false,
    };
    if api_url.is_empty() {
        let _ = std::fs::remove_file(&marker);
        return false;
    }

    let host = match keys::canonical_host(&api_url) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Warning: invalid deployment URL in capability marker: {e}");
            let _ = std::fs::remove_file(&marker);
            return false;
        }
    };

    eprintln!("Refreshing capabilities for {host}...");
    match capabilities::fetch_and_verify(&api_url, &host, force_trust_rotate) {
        Ok((doc, pinned)) => {
            // Verification succeeded; stage the bundle on disk.
            if let Err(e) = bundle::stage_bundle(&host, &doc, &pinned.key) {
                if matches!(e, Error::BundleVerify { .. }) {
                    eprintln!("Error: {e}");
                    std::process::exit(errors::exit_code(&e));
                }
                eprintln!("Warning: bundle stage failed (non-fatal): {e}");
                return false;
            }
            // Persist the new active deployment + capability cache.
            if let Some(mut m) = manifest::load() {
                m.active_deployment = Some(host.clone());
                m.capability_cache = Some(manifest::CapabilityCache {
                    deployment: host.clone(),
                    sdk_version: doc.sdk.version.clone(),
                    bundle_sha256: doc.sdk.bundle_sha256.clone(),
                    issued_at: doc.issued_at.clone(),
                    last_refreshed: manifest::now_secs(),
                });
                let _ = manifest::save(&m);
            }
            let _ = std::fs::remove_file(&marker);
            false
        }
        Err(e) => match e {
            Error::TrustViolation { .. } | Error::BundleVerify { .. } => {
                eprintln!("Error: {e}");
                std::process::exit(errors::exit_code(&e));
            }
            other => {
                eprintln!("Warning: capability refresh failed (non-fatal): {other}");
                false
            }
        },
    }
}

fn run_with(args: Vec<String>, force_trust_rotate: bool, use_installed: bool) {
    // 0. Local-CLI detection (#53). This runs BEFORE the managed-venv
    //    bootstrap and update check: those exist only to maintain
    //    `~/.huitzo/venv`, and bootstrapping (or updating, or prompting for
    //    install consent on) an environment we are about to ignore is pure
    //    cost. Deployment-level state — the SDK bundle and the staged `uv` —
    //    IS still refreshed on the local path; see `run_local`.
    match local_cli::Detect::from_process(use_installed).decide() {
        Decision::Delegate => {}
        Decision::DelegateUntrustedCheckout { checkout, reason } => {
            // Something that looks like a huitzo-cli checkout, in a directory
            // this user does not own — ambient discovery we refuse to act on
            // (a `pyproject.toml` planted in a world-writable directory must
            // never choose the interpreter). Delegate, but say it happened,
            // because the legitimate version of this — a checkout owned by
            // another account — would otherwise be another silent divergence.
            eprintln!(
                "huitzo: ignoring the huitzo-cli checkout at {} ({}); using {}",
                checkout.display(),
                reason,
                dirs::venv_python().display()
            );
        }
        Decision::RunLocal {
            python,
            source,
            safe_path,
        } => {
            run_local(&python, source, safe_path, &args, force_trust_rotate);
            return;
        }
        Decision::Refuse { checkout, searched } => {
            let e = Error::LocalCliUnavailable {
                checkout: checkout.display().to_string(),
                managed: dirs::venv_python().display().to_string(),
                searched: searched.iter().map(|p| p.display().to_string()).collect(),
            };
            eprintln!("Error: {e}");
            std::process::exit(errors::exit_code(&e));
        }
    }

    // 1. Read manifest
    let manifest = manifest::load();

    // 2. Check venv health
    let healthy = manifest.is_some() && venv::is_healthy();

    // 3. Bootstrap if unhealthy
    if !healthy {
        if let Err(e) = bootstrap() {
            eprintln!("Error: {e}");
            std::process::exit(errors::exit_code(&e));
        }
    }

    // 4. Synchronous update check (bounded to 5 s) — must complete before execvp.
    // On Unix, execvp(2) replaces the process image and kills all threads; a detached
    // background thread never gets to write manifest.json. We block here (with timeout)
    // so the manifest is always persisted before we hand off to Python.
    if !update::should_skip() {
        let needs_check = manifest.as_ref().is_some_and(manifest::needs_update_check);
        if needs_check {
            update::sync_check();
        }
    }

    // 5. Reload manifest — sync_check may have written a pending update.
    let manifest = manifest::load().or(manifest);

    // 5.5 Clear the binary an update on this machine left behind. Windows
    // cannot delete the image it is running from, so the launch *after* the
    // update is the one that gets to do it (B6).
    update::cleanup_replaced_binary();

    // 6. Apply pending update if flagged
    if let Some(ref m) = manifest {
        if let Some(ref pending) = m.pending_update {
            if !update::should_attempt(pending, manifest::now_secs()) {
                // A failed update must settle instead of re-announcing and
                // re-downloading itself on every single invocation (M14). The
                // notice names the failure and the command that retries it.
                eprintln!("{}", update::deferral_notice(pending));
            } else {
                match pending.kind.as_str() {
                    "launcher" => {
                        // Self-update the launcher binary from GitHub Releases.
                        eprintln!("Updating huitzo-launcher to {}...", pending.version);
                        match update::self_update() {
                            // Only a binary that was actually written moves
                            // `launcher_version` (M13) — "Homebrew owns this"
                            // and "already current" both install nothing.
                            Ok(update::UpdateOutcome::Updated(version)) => {
                                update::settle_pending(Some(&version));
                            }
                            Ok(
                                update::UpdateOutcome::AlreadyCurrent
                                | update::UpdateOutcome::DeferredToHomebrew,
                            ) => {
                                update::settle_pending(None);
                            }
                            Err(e) => {
                                eprintln!(
                                    "Warning: launcher update to {} failed: {e}",
                                    pending.version
                                );
                                update::record_failed_attempt(
                                    &pending.kind,
                                    &pending.version,
                                    &e.to_string(),
                                );
                            }
                        }
                    }
                    kind => {
                        eprintln!("Updating huitzo to {}...", pending.version);
                        // Every CLI update is a wheel from the release feed. The
                        // old `"pip"` kind installed from PyPI, which is where the
                        // 0.2.0 placeholder lived (#B4); a manifest still carrying
                        // that kind gets the wheel path, not a resurrected fallback
                        // (D5). `apply_wheel_update` verifies the result before it
                        // can be reported as applied.
                        // Pass the Python version so ABI-keyed manifests resolve correctly.
                        let pv = parse_python_version(&m.python_version);
                        let installed = match kind {
                            "wheel" | "pip" => match apply_wheel_update(pv) {
                                Ok(version) => Some(version),
                                Err(e) => {
                                    eprintln!("Warning: update to {} failed: {e}", pending.version);
                                    update::record_failed_attempt(
                                        &pending.kind,
                                        &pending.version,
                                        &e.to_string(),
                                    );
                                    None
                                }
                            },
                            other => {
                                eprintln!(
                                    "Warning: ignoring unknown pending update kind '{other}'"
                                );
                                // Nothing will ever apply this record, so drop
                                // it rather than warn about it forever.
                                update::settle_pending(None);
                                None
                            }
                        };
                        // The version comes from the post-install probe that just
                        // vouched for this environment, so the manifest records
                        // what actually runs rather than what pip was asked for.
                        if let Some(version) = installed {
                            let mut updated =
                                manifest::load().unwrap_or_else(|| m.clone_for_update());
                            updated.pending_update = None;
                            updated.huitzo_version = version;
                            let _ = manifest::save(&updated);
                        }
                    }
                }
            }
        }
    }

    // 7. Refresh deployment capabilities + bundle if a marker is present
    // (set by `huitzo config set api_url` / `huitzo login` on the Python
    // side). Trust violations + signature failures exit before exec.
    let _ = refresh_capabilities_if_needed(force_trust_rotate);

    // 7.5 Ensure the bundled `uv` build tool is staged (huitzo#965 / task #38). Idempotent
    // (skips when already current — no network), runs on every launch so existing installs
    // pick it up. NON-FATAL: a missing uv must never brick the launcher — the runner
    // reports the honest `build_tools_missing` in Studio instead.
    if let Err(e) = uv::ensure_uv() {
        eprintln!("Warning: uv setup failed (non-fatal): {e}");
    }

    // 8. Exec into Python CLI (never returns on Unix). The managed venv is
    //    guaranteed Python 3.11+ — `create_managed_venv` re-probes the finished
    //    environment against `python::MIN_PYTHON` — so `-P` is always safe here.
    if let Err(e) = exec::exec_into_python(&dirs::venv_python(), &args, true) {
        eprintln!("Error: {e}");
        std::process::exit(errors::exit_code(&e));
    }
}

/// Exec into a locally detected `huitzo_cli` instead of the managed venv (#53).
///
/// Ordering rationale — what runs here and what deliberately does not:
///   * managed-venv bootstrap / update check / pending-update apply: SKIPPED.
///     They maintain `~/.huitzo/venv`, which this path does not use; running
///     them would install, prompt, and hit the network for an environment we
///     are about to ignore. `huitzo --launcher-update` and
///     `huitzo --use-installed` still drive them explicitly.
///   * capability refresh + SDK bundle staging: KEPT. It is deployment-level,
///     not venv-level: the marker is written by whichever CLI ran `login` /
///     `config set api_url` — including this one — and the local CLI resolves
///     the staged SDK bundle out of `$HUITZO_HOME`. Skipping it would leave a
///     stale bundle behind a fresh CLI, which is the same class of drift #53
///     is about. It costs one `stat` when no marker is present.
///   * `uv` staging: KEPT, but only when `$HUITZO_HOME` already exists. The
///     local CLI resolves `<huitzo_home>/bin/uv` absolutely for pack builds,
///     so a managed install must keep it current; a developer who has never
///     run the managed launcher gets no surprise 15 MB download on their
///     first `huitzo` from a checkout (their own `uv` is on PATH).
fn run_local(
    python: &std::path::Path,
    source: LocalSource,
    safe_path: bool,
    args: &[String],
    rotate: bool,
) {
    // Exactly one line, on stderr, naming the interpreter that will run. The
    // bug in #53 was that divergence was invisible; this path must be visible
    // whenever it diverges — and silent when it does not.
    eprintln!(
        "huitzo: using the local CLI at {} (detected via {}) — pass --use-installed for {}",
        python.display(),
        source.label(),
        dirs::venv_python().display()
    );

    // The launcher's own pending self-update is applied in step 6, which this
    // path skips. Applying it here would mean a network round-trip on a
    // developer's every command; saying nothing would mean a launcher update
    // that never lands and never mentions itself — the same invisibility #53
    // is about. So: name it, once, and let the developer choose.
    if let Some(version) = pending_launcher_update() {
        eprintln!(
            "huitzo: launcher update {version} is pending — apply it with `huitzo --launcher-update`"
        );
    }

    let _ = refresh_capabilities_if_needed(rotate);

    if dirs::huitzo_home().exists() {
        if let Err(e) = uv::ensure_uv() {
            eprintln!("Warning: uv setup failed (non-fatal): {e}");
        }
    }

    if let Err(e) = exec::exec_into_python(python, args, safe_path) {
        eprintln!("Error: {e}");
        std::process::exit(errors::exit_code(&e));
    }
}

/// The version of a pending launcher self-update, if one is recorded.
fn pending_launcher_update() -> Option<String> {
    let m = manifest::load()?;
    let pending = m.pending_update?;
    (pending.kind == "launcher").then_some(pending.version)
}

/// Bootstrap: discover Python, create venv, install huitzo, write manifest.
///
/// Fetches the release feed once upfront — fatally, since the feed is now the
/// only source of the CLI — then builds the managed venv on an interpreter the
/// feed can actually serve a wheel to, provisioning one when the host has none
/// (see `create_managed_venv`).
///
/// Every exit from here is either a working, *verified* CLI or a named cause.
/// There is no third outcome: the PyPI fallback that used to sit under both
/// failure branches installed the 0.2.0 "MOVED" placeholder and reported
/// success (#B4), and is gone rather than flag-gated (D5).
fn bootstrap() -> Result<(), Error> {
    // T5/B5/B9: refuse an unsupported host FIRST. This sits above the consent
    // prompt on purpose — asking someone to approve an install that cannot
    // succeed, then staging uv and a CPython to prove it, is the failure this
    // check exists to prevent. On an Intel Mac or an Alpine container the
    // launcher exits here with $HUITZO_HOME untouched.
    download::ensure_supported_platform()?;

    eprintln!("Setting up huitzo environment...");

    // Logged informed consent before installing/executing third-party
    // software (S29 pattern). The invariant is "no install without a
    // recorded grant; always an audit trail" — it MUST hold on every path:
    //   (A) HUITZO_BOOTSTRAP_CONSENTED=1 non-TTY,
    //   (D) install.sh happy path (BOOTSTRAP_CONSENTED + ASSUME_YES),
    //   (E) plain `huitzo <cmd>` with the var inherited.
    // resolve_bootstrap_consent() records the grant on every proceed path
    // (including the BOOTSTRAP_CONSENTED branch) and only returns false on a
    // deliberate decline.
    if !consent::resolve_bootstrap_consent() {
        return Err(Error::ConsentDeclined);
    }

    // uv builds the managed venv and provisions CPython when the host has none
    // (D1), so it must be staged BEFORE anything Python-shaped is attempted. A
    // uv that cannot be fetched is reported as exactly that — never as a
    // downstream "no Python" or "venv failed", which is what made #B2/#B3 so
    // hard to act on.
    let uv_bin = uv::ensure_uv_required()?;

    // Fetch the release feed once — it both scores the Python candidates and
    // supplies the only installable artefact. A feed we cannot read is
    // therefore fatal, and says which kind of unreadable it was: swallowing it
    // with `.ok()` is what turned a routine GitHub rate-limit 403 into a stub
    // install on hosts with a perfectly good Python (#M11).
    let release = download::fetch_cli_release()?;

    let py_used = create_managed_venv(&uv_bin, &release)?;

    eprintln!(
        "  Using Python {}.{} at {} [{}]",
        py_used.version.0,
        py_used.version.1,
        py_used.path.display(),
        py_used.source.label()
    );

    // Install huitzo from the compiled wheel. No wheel for this
    // platform/interpreter is a terminal `Error::NoWheel` naming both and what
    // the feed does carry — there is nothing else to install.
    eprintln!("  Installing huitzo {}...", release.version);
    let wheel = install_from_fetched_release(&release, Some(py_used.version))?;

    // The install is not finished until the environment can actually run the
    // CLI (#M8). Everything below — the success line, the manifest — is
    // downstream of this check, so "Installed huitzo X" can no longer be
    // printed over a venv that cannot import `huitzo_cli`.
    let version = install::verify_install(&wheel.filename)?;
    eprintln!("  Installed huitzo {version} — verified `python -m huitzo_cli` can start");

    // Check for conflicting pip-installed huitzo
    warn_pip_conflict();

    let provenance = install_provenance(wheel);

    manifest::save(&Manifest {
        schema_version: 3,
        python_path: py_used.path.to_string_lossy().to_string(),
        python_version: format!("{}.{}", py_used.version.0, py_used.version.1),
        huitzo_version: version,
        launcher_version: env!("CARGO_PKG_VERSION").to_string(),
        last_update_check: 0, // Force update check on next run
        pending_update: None,
        created_at: manifest::now_secs(),
        install_source: Some(provenance.install_source),
        wheel_platform: Some(provenance.wheel_platform),
        active_deployment: None,
        capability_cache: None,
    })?;

    Ok(())
}

/// Build the managed venv, and report the interpreter it ended up running on.
///
/// Order of attempts:
///   1. Interpreters already on the host **that the feed publishes a wheel
///      for** (`python::partition_by_wheel`) — reusing one saves a ~25 MB
///      CPython download and is the common case.
///   2. Failing that, `uv python install` provisions a pinned CPython.
///
/// "Wheel-compatible", not merely "3.11+", is the whole of T14. The feed ships
/// cp312/cp313; a host whose only Python is 3.11 — Debian 12 stock, i.e. the
/// current Debian stable — used to get a 3.11 venv built on it and *then* be
/// told no wheel matched (exit 78), while a host with no Python at all was
/// rescued by step 2. Both now take step 2. An interpreter that cannot take a
/// wheel is not a candidate, so it is reported and skipped rather than tried.
///
/// Every attempt goes through `uv venv`, which writes the environment itself
/// instead of shelling `python -m venv`; that is what makes a stock
/// `apt install python3` host work without `python3.N-venv` (#B3).
fn create_managed_venv(
    uv_bin: &Path,
    release: &download::CliRelease,
) -> Result<python::PythonInfo, Error> {
    let has_wheel = |v: (u8, u8)| download::has_wheel_for(release, v);

    let candidates = python::discover_all();
    let (installable, no_wheel) = python::partition_by_wheel(&candidates, has_wheel);
    let mut searched: Vec<String> = Vec::new();

    // Named, not silently dropped: a user who has just installed a Python and
    // still sees a download deserves to read why it was not used.
    for py in &no_wheel {
        eprintln!(
            "  Skipping Python {}.{} at {} [{}] — cli-v{} publishes no wheel for it",
            py.version.0,
            py.version.1,
            py.path.display(),
            py.source.label(),
            release.version
        );
        searched.push(format!(
            "{} — Python {}.{}, via {} (no wheel in cli-v{})",
            py.path.display(),
            py.version.0,
            py.version.1,
            py.source.label(),
            release.version
        ));
    }

    for py in installable {
        eprintln!(
            "  Trying Python {}.{} at {} [{}] (has compiled wheel)",
            py.version.0,
            py.version.1,
            py.path.display(),
            py.source.label()
        );
        searched.push(format!(
            "{} — Python {}.{}, via {}",
            py.path.display(),
            py.version.0,
            py.version.1,
            py.source.label()
        ));

        venv::destroy()?;
        match venv::create(uv_bin, py.path.as_os_str()) {
            Ok(()) => return venv_python_info(&py.path.to_string_lossy(), py.source),
            Err(e) => eprintln!(
                "  Warning: uv venv failed on {} ({}), trying next...",
                py.path.display(),
                summarize(&e)
            ),
        }
    }

    // Nothing on this host can be served a wheel (or nothing here worked at
    // all) — the launcher supplies its own interpreter rather than telling the
    // user to go install one (D1, T14).
    //
    // Before spending a ~25 MB download, check the feed serves the interpreter
    // we would provision. If it does not, provisioning cannot rescue this host
    // and `Error::NoWheel` is the honest answer — raised here, with nothing
    // downloaded, instead of after.
    if let Some(provisioned) = provisioned_python_version() {
        // === TEMPORARY DEFECT (T9 proof, reverted in the next commit) ===
        // The PyPI fallback D5 forbids, re-added at the place it would now be
        // written: "the feed has no wheel we can use, take the package from
        // PyPI instead". The exit code is left at 78 on purpose, so what
        // catches this is the anti-stub assertion, not the status check.
        if let Err(err) = download::find_platform_wheel(release, Some(provisioned)) {
            if let Some(py) = no_wheel.first() {
                eprintln!("  No wheel this launcher can use - falling back to PyPI...");
                venv::destroy()?;
                venv::create(uv_bin, py.path.as_os_str())?;
                let status = std::process::Command::new(dirs::venv_python())
                    .args(["-m", "pip", "install", "--quiet", "huitzo"])
                    .status();
                eprintln!("  PyPI fallback finished: {status:?}");
            }
            return Err(err);
        }
        // === END TEMPORARY DEFECT ===
    }

    eprintln!(
        "  No system Python can install a cli-v{} wheel — downloading CPython {} with uv...",
        release.version,
        uv::PROVISIONED_PYTHON
    );
    if let Err(provision) = uv::install_python(uv_bin, uv::PROVISIONED_PYTHON) {
        return Err(Error::NoPython {
            searched,
            provision: Some(provision),
        });
    }

    venv::destroy()?;
    venv::create(uv_bin, std::ffi::OsStr::new(uv::PROVISIONED_PYTHON))?;
    venv_python_info(uv::PROVISIONED_PYTHON, python::Source::UvManaged)
}

/// `uv::PROVISIONED_PYTHON` as a `(major, minor)` tuple.
///
/// A parse of a crate constant, so it cannot fail for a user; the unit test
/// below pins that. It yields `None` rather than panicking anyway — a malformed
/// pin must not abort the launcher, and skipping the pre-flight feed check only
/// costs the download that the install step would then refuse honestly.
fn provisioned_python_version() -> Option<(u8, u8)> {
    parse_python_version(uv::PROVISIONED_PYTHON)
}

/// Describe the interpreter the freshly created managed venv actually runs on.
///
/// Read back out of the venv rather than assumed: for a uv-provisioned CPython
/// the launcher never names the interpreter path itself, and for a system
/// interpreter this confirms the venv is what was asked for instead of trusting
/// the request. `spec` is what we passed to `uv venv`, used only to attribute an
/// error.
fn venv_python_info(spec: &str, source: python::Source) -> Result<python::PythonInfo, Error> {
    // Every failure below leaves a venv that `uv` created but we rejected. The
    // `VenvCreate` message tells the user the partial environment was removed,
    // so it has to actually be removed here too.
    let reject = |detail: String| -> Error {
        let _ = venv::destroy();
        Error::VenvCreate {
            interpreter: spec.to_string(),
            detail,
        }
    };

    let venv_python = dirs::venv_python();
    let version = python::probe_version(&venv_python).ok_or_else(|| {
        reject(format!(
            "uv venv reported success but {} does not report a version",
            venv_python.display()
        ))
    })?;
    if !python::meets_minimum(version) {
        return Err(reject(format!(
            "the new environment runs Python {}.{}, below the required {}.{}",
            version.0,
            version.1,
            python::MIN_PYTHON.0,
            python::MIN_PYTHON.1
        )));
    }
    Ok(python::PythonInfo {
        // `base-executable` from pyvenv.cfg is the real interpreter behind the
        // venv; fall back to the venv's own python if a cfg ever omits it.
        path: venv::base_interpreter().unwrap_or(venv_python),
        version,
        source,
    })
}

/// One line of an error, for a "trying next..." note where the full multi-line
/// user-facing message would bury the loop's progress.
///
/// uv puts its `error: …` summary last, so the last non-empty line is the
/// informative one.
fn summarize(err: &Error) -> String {
    let detail = match err {
        Error::VenvCreate { detail, .. } => detail.clone(),
        other => other.to_string(),
    };
    detail
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no output")
        .to_string()
}

/// What the manifest records about where the installed CLI came from.
///
/// Feeds the version-drift / currency checks in release tooling, so a wrong
/// value does not just look untidy — it tells the tooling a machine is on a
/// release it is not on.
struct Provenance {
    /// How huitzo was installed. Wheel-from-release-feed is the only install
    /// path there is (the PyPI fallback was deleted in T2), so this is
    /// `github_release` — asserted by a test rather than left implicit.
    install_source: String,
    /// The release-feed platform key of the wheel that was installed.
    wheel_platform: String,
}

/// Derive the manifest provenance from the wheel that was actually installed.
///
/// M9: the deleted `detect_install_source()` globbed `<huitzo_home>/cache` for
/// a `.whl` and inferred the source from whichever file happened to be lying
/// there — so a wheel left over from an earlier release, or from an install
/// that failed, dictated the provenance of an install it had nothing to do
/// with. This is a pure function of the `WheelInfo` the installer returned:
/// the cache directory is not consulted, and cannot be.
fn install_provenance(wheel: &download::WheelInfo) -> Provenance {
    Provenance {
        install_source: "github_release".to_string(),
        wheel_platform: wheel.platform_key.clone(),
    }
}

/// Download and install a compiled wheel from an already-fetched `CliRelease`.
///
/// `python_version` is used for ABI-specific key lookup (e.g. `macos-arm64-cp313`).
///
/// Returns the wheel that was installed, so the caller can record exactly which
/// platform key it came from instead of inferring it from the cache directory.
fn install_from_fetched_release(
    release: &download::CliRelease,
    python_version: Option<(u8, u8)>,
) -> Result<&download::WheelInfo, Error> {
    // === TEMPORARY DEFECT (T9 proof): the literal site T2 deleted. ===
    let wheel = match download::find_platform_wheel(release, python_version) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("  No wheel for this interpreter - falling back to PyPI...");
            let status = std::process::Command::new(dirs::venv_python())
                .args(["-m", "pip", "install", "--quiet", "huitzo"])
                .status();
            eprintln!("  PyPI fallback finished: {status:?}");
            return Err(e);
        }
    };
    // === END TEMPORARY DEFECT ===
    let wheel_path = download::download_wheel(&release.version, wheel)?;
    install::install_wheel(&wheel_path)?;
    Ok(wheel)
}

/// Apply a pending wheel update from GitHub Releases, returning the version the
/// environment now actually runs.
///
/// Verified the same way a first install is (#M8): an update that lands a wheel
/// the venv cannot import must not be recorded as applied.
fn apply_wheel_update(python_version: Option<(u8, u8)>) -> Result<String, Error> {
    let release = download::fetch_cli_release()?;
    let wheel = install_from_fetched_release(&release, python_version)?;
    install::verify_install(&wheel.filename)
}

/// Parse a Python version string like "3.13" into `(major, minor)`.
fn parse_python_version(s: &str) -> Option<(u8, u8)> {
    let mut parts = s.split('.');
    let major: u8 = parts.next()?.parse().ok()?;
    let minor: u8 = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Check common locations for a pip-installed `huitzo` script that would
/// conflict with the launcher. Prints a warning if found.
fn warn_pip_conflict() {
    let launcher_bin = dirs::huitzo_home().join("bin").join("huitzo");
    let candidates = [
        dirs::home_dir_or_panic()
            .join(".local")
            .join("bin")
            .join("huitzo"),
        std::path::PathBuf::from("/usr/local/bin/huitzo"),
    ];

    for path in &candidates {
        // Skip if this IS the launcher binary
        if path == &launcher_bin {
            continue;
        }
        if path.is_file() {
            eprintln!(
                "  Warning: pip-installed 'huitzo' found at {}\n\
                 \x20  This may conflict with the launcher. Remove with: pip uninstall huitzo",
                path.display()
            );
            break;
        }
    }
}

/// Render the capability report as a human-readable terminal summary for
/// `huitzo --launcher-detect --human`. Machine consumers use the default
/// JSON form; this is for a person eyeballing their environment.
fn print_detect_human(report: &prober::CapabilityReport) {
    println!(
        "Huitzo capability check (launcher {})",
        report.launcher_version
    );
    println!(
        "  Host: {} ({}){}",
        report.host.os,
        report.host.arch,
        if report.host.wsl { " [WSL]" } else { "" }
    );
    match report.host.support {
        prober::SupportLevel::Supported => println!("  Support: supported"),
        prober::SupportLevel::Unsupported => {
            println!("  Support: not fully supported (see note)");
            if let Some(reason) = &report.host.unsupported_reason {
                println!("    {reason}");
            }
        }
    }
    println!();
    for tool in &report.tools {
        let mark = if tool.present { "[ok]" } else { "[--]" };
        // A present tool with no version is a real state, not a formatting
        // gap: right after the one-command bootstrap the launcher is installed
        // but the managed venv has not been built yet, so there is no CLI
        // version to report and the prober does not install one to find out.
        let version = match &tool.version {
            Some(v) => format!(" {v}"),
            None => String::new(),
        };
        let req = if tool.required { " (required)" } else { "" };
        println!("  {mark} {}{req}{version}", tool.display_name);
        if !tool.present {
            if let Some(hint) = &tool.install_hint {
                println!("        install: {hint}");
            }
        }
    }
    println!();
    if report.ready() {
        println!("All required tools present — this machine is ready to pair a runner.");
    } else {
        println!(
            "Missing required tools: {}. Install them, then re-run the check.",
            report.missing_required().join(", ")
        );
    }
}

/// Helper to clone manifest data for update (avoids requiring Clone on Manifest).
impl Manifest {
    fn clone_for_update(&self) -> Manifest {
        Manifest {
            schema_version: self.schema_version,
            python_path: self.python_path.clone(),
            python_version: self.python_version.clone(),
            huitzo_version: self.huitzo_version.clone(),
            launcher_version: self.launcher_version.clone(),
            last_update_check: self.last_update_check,
            pending_update: None,
            created_at: self.created_at,
            install_source: self.install_source.clone(),
            wheel_platform: self.wheel_platform.clone(),
            active_deployment: self.active_deployment.clone(),
            capability_cache: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wheel(platform_key: &str, filename: &str) -> download::WheelInfo {
        download::WheelInfo {
            platform_key: platform_key.to_string(),
            filename: filename.to_string(),
            sha256: "0".repeat(64),
        }
    }

    fn release(keys: &[&str]) -> download::CliRelease {
        download::CliRelease {
            version: "0.11.1".to_string(),
            min_launcher_version: "0.1.0".to_string(),
            wheels: keys
                .iter()
                .map(|k| wheel(k, &format!("huitzo_cli-0.11.1-{k}.whl")))
                .collect(),
        }
    }

    fn found(version: (u8, u8), path: &str) -> python::PythonInfo {
        python::PythonInfo {
            path: std::path::PathBuf::from(path),
            version,
            source: python::Source::Path,
        }
    }

    /// The live feed's shape, keyed to whatever platform the test host is.
    fn live_feed_keys() -> Vec<String> {
        let platform = download::current_platform().expect("tests run on a supported host");
        vec![format!("{platform}-cp312"), format!("{platform}-cp313")]
    }

    fn live_release() -> download::CliRelease {
        let keys = live_feed_keys();
        release(&keys.iter().map(String::as_str).collect::<Vec<_>>())
    }

    // --- T14: a host with only a non-wheel Python must provision -----------

    #[test]
    fn a_python_the_feed_cannot_serve_is_not_a_venv_candidate() {
        // Debian 12 stock (`python3` == 3.11.2) and Ubuntu 22.04 +
        // `python3.11`. Before T14 `prefer_wheel_compatible` handed this
        // interpreter back as the last-ranked candidate, `create_managed_venv`
        // built a 3.11 venv on it, and bootstrap then died with
        // `Error::NoWheel` (exit 78) *without ever attempting provisioning* —
        // while a container with no Python at all was rescued. Asserting the
        // installable group is empty is what forces the fall-through to
        // `uv python install`; the old behaviour returned it non-empty.
        let rel = live_release();
        let candidates = vec![found((3, 11), "/usr/bin/python3")];
        let (installable, skipped) =
            python::partition_by_wheel(&candidates, |v| download::has_wheel_for(&rel, v));

        assert!(
            installable.is_empty(),
            "3.11 has no cp311 wheel in the feed, so it cannot build the venv"
        );
        assert_eq!(skipped.len(), 1);
    }

    #[test]
    fn a_wheel_compatible_system_python_is_used_and_nothing_is_downloaded() {
        // The no-regression half: 3.12 is present, so it is selected and the
        // provisioning branch is never reached.
        let rel = live_release();
        let candidates = vec![
            found((3, 11), "/usr/bin/python3.11"),
            found((3, 12), "/usr/bin/python3.12"),
        ];
        let (installable, _) =
            python::partition_by_wheel(&candidates, |v| download::has_wheel_for(&rel, v));

        assert_eq!(installable.len(), 1);
        assert_eq!(installable[0].version, (3, 12));
    }

    #[test]
    fn the_interpreter_the_launcher_provisions_is_one_the_live_feed_serves() {
        // The fall-through is only a rescue if the pinned CPython can actually
        // take a wheel. If `uv::PROVISIONED_PYTHON` ever drifts off the feed's
        // published ABIs, every host without a system 3.12/3.13 downloads
        // ~25 MB and then fails — so pin the pin.
        let provisioned = provisioned_python_version().expect("PROVISIONED_PYTHON is major.minor");
        assert!(
            download::has_wheel_for(&live_release(), provisioned),
            "uv::PROVISIONED_PYTHON = {} is not in the feed's cp312/cp313 set",
            uv::PROVISIONED_PYTHON
        );
    }

    #[test]
    fn a_feed_that_cannot_serve_the_provisioned_python_fails_before_downloading_it() {
        // Provisioning must still be able to fail honestly. When the feed has
        // no wheel for the version the launcher would install, the pre-flight
        // check in `create_managed_venv` raises the feed's own `NoWheel`
        // instead of spending a CPython download to reach the same answer.
        let platform = download::current_platform().unwrap();
        let rel = release(&[&format!("{platform}-cp314")]);
        let provisioned = provisioned_python_version().unwrap();

        let e = download::find_platform_wheel(&rel, Some(provisioned)).unwrap_err();
        let msg = e.to_string();
        assert!(matches!(e, Error::NoWheel { .. }), "{msg}");
        // And the message must not send the reader off to install a Python —
        // the launcher already tried to supply one (T14).
        assert!(!msg.contains("Install one of those"), "{msg}");
        assert!(msg.contains("is not the fix"), "{msg}");
        assert!(msg.contains(uv::PROVISIONED_PYTHON), "{msg}");
    }

    #[test]
    fn provenance_comes_from_the_installed_wheel() {
        let installed = wheel(
            "linux-x86_64-cp313",
            "huitzo_cli-0.11.1-cp313-cp313-manylinux_2_28_x86_64.whl",
        );
        let provenance = install_provenance(&installed);

        assert_eq!(provenance.install_source, "github_release");
        assert_eq!(provenance.wheel_platform, "linux-x86_64-cp313");
    }

    #[test]
    fn a_stale_wheel_in_the_cache_cannot_dictate_provenance() {
        // M9 regression. `detect_install_source()` scanned
        // `<huitzo_home>/cache/*.whl` and reported whatever it found, so a
        // wheel left behind by an earlier release — or by an install that
        // never completed — became the recorded provenance of an unrelated
        // install. Stage exactly that situation: a cache full of wheels for a
        // different release, platform and Python, and an install of something
        // else entirely.
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HUITZO_HOME", tmp.path()) };

        let cache = tmp.path().join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        for stale in [
            "huitzo_cli-0.9.0-cp312-cp312-macosx_11_0_arm64.whl",
            "huitzo_cli-0.4.2-py3-none-any.whl",
        ] {
            std::fs::write(cache.join(stale), b"stale").unwrap();
        }

        let installed = wheel(
            "linux-aarch64-cp313",
            "huitzo_cli-0.11.1-cp313-cp313-manylinux_2_28_aarch64.whl",
        );
        let provenance = install_provenance(&installed);

        assert_eq!(provenance.install_source, "github_release");
        assert_eq!(
            provenance.wheel_platform, "linux-aarch64-cp313",
            "provenance must describe the install that happened, not the cache"
        );
        // And the cache is still exactly as it was: nothing read it, so
        // nothing could have been inferred from it.
        let mut left: Vec<String> = std::fs::read_dir(&cache)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        left.sort();
        assert_eq!(left.len(), 2, "{left:?}");

        unsafe { std::env::remove_var("HUITZO_HOME") };
    }
}
