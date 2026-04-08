mod dirs;
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
            let install_ok = match pending.kind.as_str() {
                "wheel" => {
                    if let Some(ref url) = pending.url {
                        eprintln!("Updating huitzo to {}...", pending.version);
                        install::install_package_from_url(url).is_ok()
                    } else {
                        false
                    }
                }
                // Legacy "pip" kind — kept for manifests written by older launcher versions
                "pip" => {
                    eprintln!("Updating huitzo to {}...", pending.version);
                    let index_url = std::env::var("HUITZO_INDEX_URL").ok();
                    install::install_package("huitzo", index_url.as_deref()).is_ok()
                }
                _ => false,
            };
            if install_ok {
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
fn bootstrap() -> Result<(), Error> {
    eprintln!("Setting up huitzo environment...");

    let py = python::discover()?;
    eprintln!(
        "  Found Python {}.{} at {}",
        py.version.0,
        py.version.1,
        py.path.display()
    );

    // Destroy stale venv if it exists
    let venv_dir = dirs::venv_dir();
    if venv_dir.exists() {
        venv::destroy()?;
    }

    // Create fresh venv
    eprintln!("  Creating virtual environment...");
    venv::create(&py.path)?;

    // Install huitzo from GitHub releases (compiled wheel for this platform)
    eprintln!("  Installing huitzo...");
    if let Some((_version, wheel_url)) = update::fetch_latest_cli_release() {
        install::install_package_from_url(&wheel_url)?;
    } else {
        // Fallback: install by package name (works if HUITZO_INDEX_URL is set)
        let index_url = std::env::var("HUITZO_INDEX_URL").ok();
        install::install_package("huitzo", index_url.as_deref())?;
    }

    // Write manifest
    let version =
        install::get_installed_version("huitzo")?.unwrap_or_else(|| "unknown".to_string());
    eprintln!("  Installed huitzo {version}");

    manifest::save(&Manifest {
        schema_version: 1,
        python_path: py.path.to_string_lossy().to_string(),
        python_version: format!("{}.{}", py.version.0, py.version.1),
        huitzo_version: version,
        launcher_version: env!("CARGO_PKG_VERSION").to_string(),
        last_update_check: 0, // Force update check on next run
        pending_update: None,
        created_at: manifest::now_secs(),
    })?;

    Ok(())
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
        }
    }
}
