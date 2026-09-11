// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

//! Integration tests for local-CLI detection (#53).
//!
//! The launcher used to exec its own `~/.huitzo/venv` unconditionally, which
//! silently hijacked `huitzo` invoked from a `huitzo-cli` source checkout —
//! nine days of stale-runner drift with no symptom. These tests pin the
//! decision table: delegate / run-local / refuse.
//!
//! Everything runs against a `tempfile` directory tree with an injected
//! environment. No test touches the machine's real `~/.huitzo`, and no test
//! needs a Python interpreter — an "interpreter" here is a regular file at the
//! platform's venv path, because detection never spawns one.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use huitzo_launcher::local_cli::{Decision, Detect, LocalSource, venv_python_path};

/// `HUITZO_LAUNCHER_FORCE` / `VIRTUAL_ENV` are process-global; serialize the
/// tests that mutate them (same pattern as `tests/common/mod.rs`). CI also
/// runs `cargo test -- --test-threads=1`.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// The `site-packages` directory for the platform's venv layout.
fn site_packages(venv_root: &Path) -> PathBuf {
    if cfg!(windows) {
        venv_root.join("Lib").join("site-packages")
    } else {
        venv_root
            .join("lib")
            .join("python3.13")
            .join("site-packages")
    }
}

/// Create a venv skeleton — executable interpreter, `pyvenv.cfg`, empty
/// `site-packages` — and return the interpreter path.
fn make_venv(venv_root: &Path) -> PathBuf {
    make_venv_with_cfg(venv_root, Some("version = 3.13.0"))
}

/// As [`make_venv`], with control over the `pyvenv.cfg` body (`None` writes
/// no `pyvenv.cfg` at all, as a non-venv prefix would have).
fn make_venv_with_cfg(venv_root: &Path, cfg: Option<&str>) -> PathBuf {
    let python = venv_python_path(venv_root);
    fs::create_dir_all(python.parent().unwrap()).unwrap();
    fs::write(&python, b"#!/bin/sh\nexit 0\n").unwrap();
    make_executable(&python);
    if let Some(cfg) = cfg {
        fs::write(
            venv_root.join("pyvenv.cfg"),
            format!("home = /usr/bin\n{cfg}\n"),
        )
        .unwrap();
    }
    fs::create_dir_all(site_packages(venv_root)).unwrap();
    python
}

/// Give `path` the executable bit (a no-op off Unix).
fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// The uid that owns `sample` — i.e. the uid running these tests. `None` off
/// Unix, which is exactly what `Detect::from_process` records there.
fn my_uid(sample: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(fs::metadata(sample).unwrap().uid())
    }
    #[cfg(not(unix))]
    {
        let _ = sample;
        None
    }
}

/// Install `huitzo_cli` into a venv the way a wheel install lays it out.
fn install_cli(venv_root: &Path) {
    let sp = site_packages(venv_root);
    fs::create_dir_all(sp.join("huitzo_cli")).unwrap();
    fs::create_dir_all(sp.join("huitzo_cli-1.7.0.dist-info")).unwrap();
}

/// Install `huitzo_cli` the way `uv sync` lays out an editable checkout: no
/// package directory, just the finder `.pth` plus the dist-info.
fn install_cli_editable(venv_root: &Path) {
    let sp = site_packages(venv_root);
    fs::write(sp.join("_huitzo_cli.pth"), b"/src/cli\n").unwrap();
    fs::create_dir_all(sp.join("huitzo_cli-1.7.0.dist-info")).unwrap();
}

/// Write a `huitzo-cli` source-checkout `pyproject.toml` into `dir`.
fn write_cli_pyproject(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("pyproject.toml"),
        b"[project]\nname = \"huitzo-cli\"\nversion = \"1.7.0\"\n",
    )
    .unwrap();
}

/// A `Detect` with the managed venv living outside the fixture tree, so a
/// test only exercises what it sets up.
fn detect_in(cwd: &Path, managed_root: &Path) -> Detect {
    Detect {
        force: false,
        virtual_env: None,
        uv_project_environment: None,
        cwd: Some(cwd.to_path_buf()),
        managed_python: venv_python_path(managed_root),
        launcher_exe: None,
        uid: my_uid(cwd),
    }
}

#[test]
fn plain_shell_outside_any_checkout_delegates() {
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let work = tmp.path().join("work");
    fs::create_dir_all(&work).unwrap();

    // No pyproject, no venv, no env vars: today's behaviour, unchanged.
    assert_eq!(detect_in(&work, &managed).decide(), Decision::Delegate);
}

#[test]
fn unrelated_project_with_an_unrelated_virtualenv_delegates() {
    // The over-refusal guard: a developer with some other project's venv
    // activated must keep working exactly as before.
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let project = tmp.path().join("other-project");
    fs::create_dir_all(&project).unwrap();
    fs::write(
        project.join("pyproject.toml"),
        b"[project]\nname = \"some-other-tool\"\ndependencies = [\"huitzo-cli\"]\n",
    )
    .unwrap();
    let venv = project.join(".venv");
    make_venv(&venv);

    let mut d = detect_in(&project, &managed);
    d.virtual_env = Some(venv);
    assert_eq!(d.decide(), Decision::Delegate);
}

#[test]
fn uv_run_from_the_cli_checkout_runs_the_local_interpreter() {
    // The exact shape of #53: `uv run huitzo …` in the cli checkout exports
    // VIRTUAL_ENV pointing at the checkout's synced environment.
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let checkout = tmp.path().join("cli");
    write_cli_pyproject(&checkout);
    let venv = checkout.join(".venv");
    let python = make_venv(&venv);
    install_cli_editable(&venv);

    let nested = checkout.join("src").join("huitzo_cli");
    fs::create_dir_all(&nested).unwrap();

    let mut d = detect_in(&nested, &managed);
    d.virtual_env = Some(venv);
    assert_eq!(
        d.decide(),
        Decision::RunLocal {
            python,
            source: LocalSource::ActiveVirtualEnv,
            safe_path: true,
        }
    );
}

#[test]
fn checkout_without_an_activated_env_uses_the_checkout_venv() {
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let checkout = tmp.path().join("cli");
    write_cli_pyproject(&checkout);
    let venv = checkout.join(".venv");
    let python = make_venv(&venv);
    install_cli(&venv);

    assert_eq!(
        detect_in(&checkout, &managed).decide(),
        Decision::RunLocal {
            python,
            source: LocalSource::CheckoutVenv,
            safe_path: true,
        }
    );
}

#[test]
fn uv_project_environment_is_resolved_against_the_checkout() {
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let checkout = tmp.path().join("cli");
    write_cli_pyproject(&checkout);
    let venv = checkout.join(".venv-dev");
    let python = make_venv(&venv);
    install_cli(&venv);

    let mut d = detect_in(&checkout, &managed);
    d.uv_project_environment = Some(PathBuf::from(".venv-dev"));
    assert_eq!(
        d.decide(),
        Decision::RunLocal {
            python,
            source: LocalSource::UvProjectEnvironment,
            safe_path: true,
        }
    );
}

#[test]
fn active_env_with_huitzo_cli_runs_local_even_without_a_checkout() {
    // `source .venv/bin/activate` in a scratch directory: the environment the
    // developer activated genuinely has huitzo_cli, so it wins.
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let work = tmp.path().join("scratch");
    fs::create_dir_all(&work).unwrap();
    let venv = tmp.path().join("somewhere").join(".venv");
    let python = make_venv(&venv);
    install_cli(&venv);

    let mut d = detect_in(&work, &managed);
    d.virtual_env = Some(venv);
    assert_eq!(
        d.decide(),
        Decision::RunLocal {
            python,
            source: LocalSource::ActiveVirtualEnv,
            safe_path: true,
        }
    );
}

#[test]
fn workspace_root_finds_the_member_checkout() {
    // A monorepo root that declares `cli` as a uv workspace member: the
    // checkout reported is the member directory, not the root.
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let root = tmp.path().join("monorepo");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("pyproject.toml"),
        b"[project]\nname = \"huitzo-monorepo\"\n\n[tool.uv.workspace]\nmembers = [\"cli\"]\n",
    )
    .unwrap();
    let member = root.join("cli");
    write_cli_pyproject(&member);
    let venv = member.join(".venv");
    let python = make_venv(&venv);
    install_cli(&venv);

    assert_eq!(
        detect_in(&root, &managed).decide(),
        Decision::RunLocal {
            python,
            source: LocalSource::CheckoutVenv,
            safe_path: true,
        }
    );
}

#[test]
fn checkout_with_no_environment_refuses_and_names_what_it_searched() {
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let checkout = tmp.path().join("cli");
    write_cli_pyproject(&checkout);

    match detect_in(&checkout, &managed).decide() {
        Decision::Refuse {
            checkout: c,
            searched,
        } => {
            assert_eq!(c, checkout);
            assert_eq!(searched, vec![checkout.join(".venv")]);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn checkout_whose_env_lacks_huitzo_cli_refuses_rather_than_delegating() {
    // The environment exists but was never synced. Delegating here is exactly
    // the silent-wrong-version bug; refuse and name both paths instead.
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let checkout = tmp.path().join("cli");
    write_cli_pyproject(&checkout);
    let venv = checkout.join(".venv");
    make_venv(&venv);

    assert!(matches!(
        detect_in(&checkout, &managed).decide(),
        Decision::Refuse { .. }
    ));
}

#[test]
fn force_delegates_from_inside_the_checkout_without_probing() {
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let checkout = tmp.path().join("cli");
    write_cli_pyproject(&checkout);
    let venv = checkout.join(".venv");
    make_venv(&venv);
    install_cli(&venv);

    let mut d = detect_in(&checkout, &managed);
    d.virtual_env = Some(venv);
    d.force = true;
    assert_eq!(d.decide(), Decision::Delegate);
}

#[test]
fn activating_the_managed_venv_delegates_silently() {
    // `source ~/.huitzo/venv/bin/activate`: the active environment IS the
    // managed one, so delegation runs exactly what is activated — and keeps
    // the bootstrap/update path that only the managed venv has.
    let tmp = tempfile::tempdir().unwrap();
    let managed_root = tmp.path().join("huitzo-home").join("venv");
    make_venv(&managed_root);
    install_cli(&managed_root);
    let checkout = tmp.path().join("cli");
    write_cli_pyproject(&checkout);

    let mut d = detect_in(&checkout, &managed_root);
    d.virtual_env = Some(managed_root);
    assert_eq!(d.decide(), Decision::Delegate);
}

#[cfg(unix)]
#[test]
fn an_interpreter_that_is_really_the_launcher_is_never_exec_d() {
    // Exec-recursion guard: a `python` that resolves to this launcher binary
    // would re-enter detection forever. It is rejected as a candidate, and
    // with no other candidate the checkout signal refuses.
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let launcher = tmp.path().join("huitzo");
    fs::write(&launcher, b"ELF\n").unwrap();
    // Executable, so the recursion guard — not the executable-bit check — is
    // what rejects it.
    make_executable(&launcher);

    let checkout = tmp.path().join("cli");
    write_cli_pyproject(&checkout);
    let venv = checkout.join(".venv");
    let python = venv_python_path(&venv);
    fs::create_dir_all(python.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&launcher, &python).unwrap();
    install_cli(&venv);

    let mut d = detect_in(&checkout, &managed);
    d.launcher_exe = Some(launcher);
    assert!(matches!(d.decide(), Decision::Refuse { .. }));
}

#[test]
fn from_process_honours_the_force_env_and_the_flag() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // SAFETY: env mutation is serialized by ENV_LOCK above and CI runs
    // `cargo test -- --test-threads=1`.
    unsafe { std::env::remove_var("HUITZO_LAUNCHER_FORCE") };
    assert!(!Detect::from_process(false).force);
    assert!(Detect::from_process(true).force, "--use-installed forces");

    unsafe { std::env::set_var("HUITZO_LAUNCHER_FORCE", "1") };
    assert!(Detect::from_process(false).force);

    // Explicitly falsy values are not a force.
    unsafe { std::env::set_var("HUITZO_LAUNCHER_FORCE", "0") };
    assert!(!Detect::from_process(false).force);
    unsafe { std::env::remove_var("HUITZO_LAUNCHER_FORCE") };
}

#[test]
fn a_broken_cwd_and_an_empty_environment_delegate() {
    // `Detect::default()` is the "we know nothing" case (e.g. `current_dir()`
    // failed): it must never refuse and never redirect.
    assert_eq!(Detect::default().decide(), Decision::Delegate);
}

#[cfg(unix)]
#[test]
fn a_checkout_owned_by_another_user_is_ignored() {
    // A `pyproject.toml` + `.venv` planted in a directory this user does not
    // own (the world-writable-/tmp shape) must NEVER choose the interpreter:
    // ambient discovery is not a grant. Delegate, and say so.
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let checkout = tmp.path().join("planted");
    write_cli_pyproject(&checkout);
    let venv = checkout.join(".venv");
    make_venv(&venv);
    install_cli(&venv);

    let mut d = detect_in(&checkout, &managed);
    d.uid = Some(my_uid(tmp.path()).unwrap() + 1); // "someone else" owns it
    match d.decide() {
        Decision::DelegateUntrustedCheckout {
            checkout: c,
            reason,
        } => {
            assert_eq!(c, checkout);
            // The uids are named so a container/NFS uid mapping is
            // distinguishable from a real intruder.
            assert!(reason.starts_with("owned by another user: directory uid "));
            assert!(reason.contains("this process uid "));
        }
        other => panic!("expected an untrusted-checkout delegation, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn a_world_writable_checkout_is_ignored() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let checkout = tmp.path().join("shared");
    write_cli_pyproject(&checkout);
    let venv = checkout.join(".venv");
    make_venv(&venv);
    install_cli(&venv);
    fs::set_permissions(&checkout, fs::Permissions::from_mode(0o777)).unwrap();

    match detect_in(&checkout, &managed).decide() {
        Decision::DelegateUntrustedCheckout { reason, .. } => {
            assert_eq!(reason, "world-writable");
        }
        other => panic!("expected an untrusted-checkout delegation, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn an_explicitly_activated_env_wins_even_from_an_untrusted_directory() {
    // The trust boundary: ambient discovery is distrusted, but VIRTUAL_ENV is
    // the user's own declaration and is still honoured.
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let checkout = tmp.path().join("planted");
    write_cli_pyproject(&checkout);
    let venv = tmp.path().join("mine").join(".venv");
    let python = make_venv(&venv);
    install_cli(&venv);

    let mut d = detect_in(&checkout, &managed);
    d.uid = Some(my_uid(tmp.path()).unwrap() + 1);
    d.virtual_env = Some(venv);
    assert_eq!(
        d.decide(),
        Decision::RunLocal {
            python,
            source: LocalSource::ActiveVirtualEnv,
            safe_path: true,
        }
    );
}

#[cfg(unix)]
#[test]
fn a_non_executable_interpreter_is_not_a_candidate() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let checkout = tmp.path().join("cli");
    write_cli_pyproject(&checkout);
    let venv = checkout.join(".venv");
    let python = make_venv(&venv);
    install_cli(&venv);
    fs::set_permissions(&python, fs::Permissions::from_mode(0o644)).unwrap();

    assert!(matches!(
        detect_in(&checkout, &managed).decide(),
        Decision::Refuse { .. }
    ));
}

#[test]
fn dash_p_is_withheld_from_an_interpreter_older_than_3_11() {
    // `-P` does not exist before Python 3.11; passing it is a hard startup
    // error, so the launcher only uses it when `pyvenv.cfg` proves 3.11+.
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let checkout = tmp.path().join("cli");
    write_cli_pyproject(&checkout);
    let venv = checkout.join(".venv");
    make_venv_with_cfg(&venv, Some("version = 3.10.14"));
    install_cli(&venv);

    match detect_in(&checkout, &managed).decide() {
        Decision::RunLocal { safe_path, .. } => assert!(!safe_path),
        other => panic!("expected a local run, got {other:?}"),
    }
}

#[test]
fn dash_p_is_withheld_when_the_version_is_unknown() {
    // No `pyvenv.cfg` (e.g. VIRTUAL_ENV pointing at a conda prefix): the
    // launcher cannot prove 3.11+, so it does not risk the flag.
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let work = tmp.path().join("scratch");
    fs::create_dir_all(&work).unwrap();
    let venv = tmp.path().join("conda-env");
    make_venv_with_cfg(&venv, None);
    install_cli(&venv);

    let mut d = detect_in(&work, &managed);
    d.virtual_env = Some(venv);
    match d.decide() {
        Decision::RunLocal { safe_path, .. } => assert!(!safe_path),
        other => panic!("expected a local run, got {other:?}"),
    }
}

#[test]
fn uv_writes_version_info_and_it_is_understood() {
    // The stdlib `venv` writes `version = …`; `uv` writes `version_info = …`.
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let checkout = tmp.path().join("cli");
    write_cli_pyproject(&checkout);
    let venv = checkout.join(".venv");
    make_venv_with_cfg(&venv, Some("version_info = 3.12.3"));
    install_cli(&venv);

    match detect_in(&checkout, &managed).decide() {
        Decision::RunLocal { safe_path, .. } => assert!(safe_path),
        other => panic!("expected a local run, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn a_world_writable_workspace_root_cannot_steer_selection() {
    use std::os::unix::fs::PermissionsExt;

    // The root's `members` list is what picks the member directory, so a root
    // anyone can write to must not be able to point the launcher at a member
    // — even a member that is legitimately owned by this user.
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed");
    let root = tmp.path().join("monorepo");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("pyproject.toml"),
        b"[project]\nname = \"huitzo-monorepo\"\n\n[tool.uv.workspace]\nmembers = [\"cli\"]\n",
    )
    .unwrap();
    let member = root.join("cli");
    write_cli_pyproject(&member);
    let venv = member.join(".venv");
    make_venv(&venv);
    install_cli(&venv);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();

    match detect_in(&root, &managed).decide() {
        Decision::DelegateUntrustedCheckout { checkout, reason } => {
            assert_eq!(checkout, root, "the ROOT is what is reported as untrusted");
            assert_eq!(reason, "world-writable");
        }
        other => panic!("expected the untrusted workspace root to be ignored, got {other:?}"),
    }
}
