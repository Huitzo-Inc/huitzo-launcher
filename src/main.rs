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

    // 4. Background update check (non-blocking)
    if let Some(ref m) = manifest {
        if !update::should_skip() && manifest::needs_update_check(m) {
            std::thread::spawn(|| {
                update::background_check();
            });
        }
    }

    // 5. Apply pending update if flagged
    if let Some(ref m) = manifest {
        if let Some(ref pending) = m.pending_update {
            eprintln!("Updating huitzo to {}...", pending.version);
            let update_ok = match pending.kind.as_str() {
                "wheel" => {
                    // Download compiled wheel from GitHub Releases
                    apply_wheel_update().is_ok()
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

    // 6. Exec into Python CLI (never returns on Unix)
    if let Err(e) = exec::exec_into_python(&dirs::venv_python(), &args) {
        eprintln!("Error: {e}");
        std::process::exit(errors::exit_code(&e));
    }
}

/// Bootstrap: discover Python, create venv, install huitzo, write manifest.
///
/// Iterates all discovered Python 3.11+ interpreters, trying each for venv
/// creation. This handles broken interpreters (e.g., RC builds with missing
/// ensurepip) by falling back to the next candidate.
fn bootstrap() -> Result<(), Error> {
    eprintln!("Setting up huitzo environment...");

    let candidates = python::discover_all()?;

    let mut last_err = None;
    let mut py_used = None;

    for py in &candidates {
        eprintln!(
            "  Trying Python {}.{} at {}",
            py.version.0,
            py.version.1,
            py.path.display()
        );

        // Destroy stale venv if it exists
        let venv_dir = dirs::venv_dir();
        if venv_dir.exists() {
            venv::destroy()?;
        }

        // Attempt venv creation
        match venv::create(&py.path) {
            Ok(()) => {
                py_used = Some(py);
                break;
            }
            Err(e) => {
                eprintln!(
                    "  Warning: Python {}.{} failed to create venv, trying next...",
                    py.version.0, py.version.1
                );
                last_err = Some(e);
            }
        }
    }

    let py = py_used.ok_or_else(|| {
        last_err.unwrap_or_else(|| {
            Error::VenvCreate("All Python candidates failed to create a virtual environment".into())
        })
    })?;

    eprintln!(
        "  Using Python {}.{} at {}",
        py.version.0,
        py.version.1,
        py.path.display()
    );

    // Install huitzo: try compiled wheel from GitHub Releases, fall back to PyPI
    eprintln!("  Installing huitzo...");
    if let Err(_wheel_err) = install_from_release() {
        // Fallback to PyPI for backwards compatibility
        eprintln!("  Compiled wheel unavailable, falling back to PyPI...");
        let index_url = std::env::var("HUITZO_INDEX_URL").ok();
        install::install_package("huitzo", index_url.as_deref())?;
    }

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
        python_path: py.path.to_string_lossy().to_string(),
        python_version: format!("{}.{}", py.version.0, py.version.1),
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

/// Download and install the latest compiled CLI wheel from GitHub Releases.
fn install_from_release() -> Result<(), Error> {
    let release = download::fetch_cli_release()?;
    let wheel = download::find_platform_wheel(&release)?;
    let wheel_path = download::download_wheel(&release.version, wheel)?;
    install::install_wheel(&wheel_path)?;
    Ok(())
}

/// Apply a pending wheel update from GitHub Releases.
fn apply_wheel_update() -> Result<(), Error> {
    install_from_release()
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
