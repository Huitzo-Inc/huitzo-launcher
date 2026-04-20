mod dirs;
mod download;
mod errors;
mod exec;
mod install;
mod manifest;
mod python;
mod update;
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

    run(args);
}

fn run(args: Vec<String>) {
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
        let needs_check = manifest
            .as_ref()
            .is_some_and(manifest::needs_update_check);
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

    // 7. Exec into Python CLI (never returns on Unix)
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
        schema_version: 2,
        python_path: py_used.path.to_string_lossy().to_string(),
        python_version: format!("{}.{}", py_used.version.0, py_used.version.1),
        huitzo_version: version,
        launcher_version: env!("CARGO_PKG_VERSION").to_string(),
        last_update_check: 0, // Force update check on next run
        pending_update: None,
        created_at: manifest::now_secs(),
        install_source: Some(install_source),
        wheel_platform,
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
        }
    }
}
