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
mod manifest;
mod prober;
mod python;
mod update;
mod uv;
mod uv_manifest;
mod venv;

use errors::Error;
use manifest::Manifest;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

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
        if let Err(e) = update::self_update() {
            eprintln!("Error: {e}");
            std::process::exit(errors::exit_code(&e));
        }
        return;
    }

    // Emergency TOFU rotation: operator opts in to overwrite a pinned key
    // after a deployment-root rotation outside the (deferred) overlap-
    // window mechanism. The flag is consumed here so it never reaches the
    // Python CLI on exec.
    let force_trust_rotate = args.iter().any(|a| a == "--launcher-trust-rotate");
    let args: Vec<String> = args
        .into_iter()
        .filter(|a| a != "--launcher-trust-rotate")
        .collect();

    run_with(args, force_trust_rotate);
}

fn run(args: Vec<String>) {
    run_with(args, false);
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

fn run_with(args: Vec<String>, force_trust_rotate: bool) {
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

    // 6. Apply pending update if flagged
    if let Some(ref m) = manifest {
        if let Some(ref pending) = m.pending_update {
            match pending.kind.as_str() {
                "launcher" => {
                    // Self-update the launcher binary from GitHub Releases.
                    eprintln!("Updating huitzo-launcher to {}...", pending.version);
                    let update_ok = update::self_update().is_ok();
                    if update_ok {
                        let mut updated = manifest::load().unwrap_or_else(|| m.clone_for_update());
                        updated.pending_update = None;
                        updated.launcher_version = pending.version.clone();
                        let _ = manifest::save(&updated);
                    }
                }
                kind => {
                    eprintln!("Updating huitzo to {}...", pending.version);
                    let update_ok = match kind {
                        "wheel" => {
                            // Download compiled wheel from GitHub Releases.
                            // Pass the Python version so ABI-keyed manifests resolve correctly.
                            let pv = parse_python_version(&m.python_version);
                            apply_wheel_update(pv).is_ok()
                        }
                        "pip" => {
                            // Legacy: install from PyPI (for manifests created before binary distribution)
                            let index_url = std::env::var("HUITZO_INDEX_URL").ok();
                            install::install_package("huitzo", index_url.as_deref()).is_ok()
                        }
                        _ => false,
                    };
                    if update_ok {
                        let mut updated = manifest::load().unwrap_or_else(|| m.clone_for_update());
                        updated.pending_update = None;
                        if let Ok(Some(v)) = install::get_installed_version("huitzo") {
                            updated.huitzo_version = v;
                        }
                        let _ = manifest::save(&updated);
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

    // 8. Exec into Python CLI (never returns on Unix)
    if let Err(e) = exec::exec_into_python(&dirs::venv_python(), &args) {
        eprintln!("Error: {e}");
        std::process::exit(errors::exit_code(&e));
    }
}

/// Bootstrap: discover Python, create venv, install huitzo, write manifest.
///
/// Fetches the release manifest once upfront, then iterates all discovered
/// Python 3.11+ interpreters in two passes:
///   Pass 1 — prefer a Python that has a compiled wheel in the manifest.
///   Pass 2 — if no wheel-compatible Python creates a venv successfully,
///             fall back to the first working Python (will install from PyPI).
///
/// This avoids committing to Python 3.14 (for example) when only cp312/cp313
/// wheels exist and Python 3.12 is also available.
fn bootstrap() -> Result<(), Error> {
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

    let candidates = python::discover_all()?;

    // Fetch the release manifest once — used to score Python candidates.
    // Network failure is non-fatal here; we degrade to PyPI fallback.
    let release = download::fetch_cli_release().ok();

    let py_used = select_python(&candidates, release.as_ref())?;

    eprintln!(
        "  Using Python {}.{} at {}",
        py_used.version.0,
        py_used.version.1,
        py_used.path.display()
    );

    // Install huitzo: try compiled wheel from the already-fetched release, fall back to PyPI
    eprintln!("  Installing huitzo...");
    let installed_from_wheel = if let Some(ref rel) = release {
        match install_from_fetched_release(rel, Some(py_used.version)) {
            Ok(()) => true,
            Err(wheel_err) => {
                eprintln!("  Compiled wheel unavailable ({wheel_err}), falling back to PyPI...");
                let index_url = std::env::var("HUITZO_INDEX_URL").ok();
                install::install_package("huitzo", index_url.as_deref())?;
                false
            }
        }
    } else {
        // Release fetch failed earlier — go straight to PyPI
        eprintln!("  Release manifest unavailable, falling back to PyPI...");
        let index_url = std::env::var("HUITZO_INDEX_URL").ok();
        install::install_package("huitzo", index_url.as_deref())?;
        false
    };
    let _ = installed_from_wheel; // used implicitly via detect_install_source()

    // Write manifest
    let version =
        install::get_installed_version("huitzo")?.unwrap_or_else(|| "unknown".to_string());
    eprintln!("  Installed huitzo {version}");

    // Check for conflicting pip-installed huitzo
    warn_pip_conflict();

    // Determine install source: GitHub Releases (wheel) vs PyPI fallback
    let (install_source, wheel_platform) = detect_install_source();

    manifest::save(&Manifest {
        schema_version: 3,
        python_path: py_used.path.to_string_lossy().to_string(),
        python_version: format!("{}.{}", py_used.version.0, py_used.version.1),
        huitzo_version: version,
        launcher_version: env!("CARGO_PKG_VERSION").to_string(),
        last_update_check: 0, // Force update check on next run
        pending_update: None,
        created_at: manifest::now_secs(),
        install_source: Some(install_source),
        wheel_platform,
        active_deployment: None,
        capability_cache: None,
    })?;

    Ok(())
}

/// Select the best Python interpreter from `candidates` for the managed venv.
///
/// Pass 1: prefer a Python that both creates a venv successfully AND has a
///         compiled wheel in `release` (if provided).
/// Pass 2: if pass 1 yields nothing, accept the first Python that creates a
///         venv — wheel-less fallback will use PyPI.
fn select_python<'a>(
    candidates: &'a [python::PythonInfo],
    release: Option<&download::CliRelease>,
) -> Result<&'a python::PythonInfo, Error> {
    // Pass 1: wheel-compatible Python preferred (skipped if no release manifest)
    if let Some(rel) = release {
        for py in candidates {
            if !download::has_wheel_for(rel, py.version) {
                continue;
            }
            if try_venv(py) {
                return Ok(py);
            }
        }
    }

    // Pass 2: any working Python (will fall back to PyPI)
    let mut last_err: Option<Error> = None;
    for py in candidates {
        eprintln!(
            "  Trying Python {}.{} at {}",
            py.version.0,
            py.version.1,
            py.path.display()
        );
        let venv_dir = dirs::venv_dir();
        if venv_dir.exists() {
            venv::destroy()?;
        }
        match venv::create(&py.path) {
            Ok(()) => return Ok(py),
            Err(e) => {
                eprintln!(
                    "  Warning: Python {}.{} failed to create venv, trying next...",
                    py.version.0, py.version.1
                );
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        Error::VenvCreate("All Python candidates failed to create a virtual environment".into())
    }))
}

/// Attempt to create the managed venv using `py`. Returns true on success.
///
/// Destroys any existing venv first, prints progress, and silently returns
/// false on failure (caller decides whether to warn or move on).
fn try_venv(py: &python::PythonInfo) -> bool {
    eprintln!(
        "  Trying Python {}.{} at {} (has compiled wheel)",
        py.version.0,
        py.version.1,
        py.path.display()
    );
    let venv_dir = dirs::venv_dir();
    if venv_dir.exists() && venv::destroy().is_err() {
        return false;
    }
    match venv::create(&py.path) {
        Ok(()) => true,
        Err(_) => {
            eprintln!(
                "  Warning: Python {}.{} failed to create venv, trying next...",
                py.version.0, py.version.1
            );
            false
        }
    }
}

/// Download and install a compiled wheel from an already-fetched `CliRelease`.
///
/// `python_version` is used for ABI-specific key lookup (e.g. `macos-arm64-cp313`).
fn install_from_fetched_release(
    release: &download::CliRelease,
    python_version: Option<(u8, u8)>,
) -> Result<(), Error> {
    let wheel = download::find_platform_wheel(release, python_version)?;
    let wheel_path = download::download_wheel(&release.version, wheel)?;
    install::install_wheel(&wheel_path)?;
    Ok(())
}

/// Apply a pending wheel update from GitHub Releases.
fn apply_wheel_update(python_version: Option<(u8, u8)>) -> Result<(), Error> {
    let release = download::fetch_cli_release()?;
    install_from_fetched_release(&release, python_version)
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

/// Detect how huitzo was installed based on the venv contents.
///
/// Returns `(install_source, wheel_platform)`.
fn detect_install_source() -> (String, Option<String>) {
    // If a compiled wheel exists in the cache dir, it came from GitHub Releases
    let cache = dirs::huitzo_home().join("cache");
    if cache.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&cache) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.ends_with(".whl") && name.contains("huitzo") {
                    // Extract platform tag from wheel filename
                    // Format: name-version-pyN-pyN-platform.whl
                    let platform = name
                        .rsplit('-')
                        .next()
                        .and_then(|s| s.strip_suffix(".whl"))
                        .map(|s| s.to_string());
                    return ("github_release".to_string(), platform);
                }
            }
        }
    }
    ("pypi".to_string(), None)
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
        let version = tool.version.as_deref().unwrap_or("");
        let req = if tool.required { " (required)" } else { "" };
        println!("  {mark} {}{req} {version}", tool.display_name);
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
