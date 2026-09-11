// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

//! Local `huitzo_cli` detection — stop hijacking a source checkout (#53).
//!
//! The launcher is a compiled binary on `PATH`. When `uv run huitzo …` (or a
//! plain `huitzo …`) is issued from inside a `huitzo-cli` source checkout,
//! `uv` finds no project-level `huitzo` script, falls through to `PATH`, and
//! lands here — and the launcher then execs its own hardcoded
//! `~/.huitzo/venv`. The command succeeds, exits 0, and runs *entirely
//! different code* from the checkout the developer believes they are running.
//! On the staging host that went unnoticed for nine days.
//!
//! This module makes delegation a **decision** instead of an assumption. It is
//! a pure function over an injected environment ([`Detect`]) so it can be
//! unit-tested without spawning a process or touching the real `~/.huitzo`.
//!
//! # Cost
//!
//! Detection runs on EVERY `huitzo` invocation, so the common case (no local
//! checkout, no active venv) must be ~free. It is: a handful of `getenv`s plus
//! one `stat` of `pyproject.toml` per directory while walking up from the
//! invocation directory. **No process is ever spawned to probe an
//! interpreter** — "can this environment import `huitzo_cli`" is answered by
//! looking for the distribution's own markers in `site-packages`, which costs
//! one `stat` (installed) or one `read_dir` (editable install) and only runs
//! after a cheap signal has already fired.
//!
//! # Security
//!
//! The decision reads `VIRTUAL_ENV` / `UV_PROJECT_ENVIRONMENT` and files found
//! by walking up from the invocation directory, so it changes `huitzo` from a
//! binary with one fixed exec target into one whose target depends on where it
//! was run. The two kinds of signal are therefore NOT trusted equally:
//!
//! * **Explicit declaration** — `VIRTUAL_ENV`, `UV_PROJECT_ENVIRONMENT` — is
//!   taken at face value. An attacker who can write into that venv's
//!   `site-packages` already owns it: a `.pth` file there runs on *every*
//!   `python` invoked from that environment, so honouring the variable adds no
//!   reachable capability.
//! * **Ambient discovery** — a `pyproject.toml` found by walking up from the
//!   invocation directory — is trusted only when the checkout AND the `.venv`
//!   it selects are owned by the invoking user and not world-writable. This is
//!   what stops a `pyproject.toml` + `.venv` planted in a shared directory
//!   such as `/tmp` from choosing the interpreter for anyone who happens to
//!   `cd` there; it is the same failure git closed with `safe.directory`
//!   (CVE-2022-24765). A rejected checkout is ignored and announced, never
//!   acted on.
//!
//! On top of that, on every local path:
//!
//! 1. The interpreter path is **constructed by the launcher**
//!    (`<venv>/bin/python`); nothing read from a `pyproject.toml` ever names a
//!    binary to run.
//! 2. That path must resolve to a **regular, executable file** and must NOT
//!    resolve to the launcher binary itself (no exec recursion through a
//!    `huitzo` shim).
//! 3. The environment must actually carry a `huitzo_cli` distribution.
//! 4. The chosen interpreter is **printed to stderr** — the redirection is
//!    never silent, which is the whole point of #53.
//!
//! Two residual risks are accepted rather than closed:
//!
//! * The ownership test rejects world-writable directories but not
//!   *group*-writable ones. Distinguishing "a group that is just me" (the
//!   user-private-group layout several distributions default to, with
//!   `umask 002`) from "a group with other members" needs a group-membership
//!   lookup, and rejecting all group-writable directories would silently
//!   disable detection for those users — the very silence #53 is about. Git's
//!   own `safe.directory` check is ownership-only for the same reason.
//! * A repository the user has cloned *and owns*, whose `.venv` the user also
//!   owns, can direct their next `huitzo` invocation at its own interpreter.
//!   Ownership cannot distinguish "a checkout you trust" from "a checkout you
//!   cloned but should not" — nothing a filesystem check can see does. That
//!   is the trust model `uv run`, `tox` and `node_modules/.bin` already ask
//!   for, it requires running a huitzo command inside a tree the user chose
//!   to clone, and unlike those tools it announces itself.
//!
//! `HUITZO_LAUNCHER_FORCE=1` / `--use-installed` opt out entirely.

use std::path::{Path, PathBuf};

/// Environment variable that forces delegation to the managed venv.
pub const FORCE_ENV: &str = "HUITZO_LAUNCHER_FORCE";

/// Flag that forces delegation to the managed venv. Consumed in `main()` so
/// it never reaches the Python CLI on exec.
pub const USE_INSTALLED_FLAG: &str = "--use-installed";

/// Upper bound on the directory walk looking for a checkout root.
const MAX_WALK_DEPTH: usize = 64;

/// Upper bound on a `pyproject.toml` we are willing to read (1 MiB). A file
/// larger than this is not a project manifest we need to understand.
const MAX_PYPROJECT_BYTES: u64 = 1024 * 1024;

/// Where a detected local interpreter came from (for the stderr notice).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalSource {
    /// `VIRTUAL_ENV` is set (an activated venv, or a `uv run` child).
    ActiveVirtualEnv,
    /// `UV_PROJECT_ENVIRONMENT` names the project environment.
    UvProjectEnvironment,
    /// `<checkout>/.venv` inside a detected `huitzo-cli` source checkout.
    CheckoutVenv,
}

impl LocalSource {
    /// Short human label naming the signal that selected this interpreter.
    pub fn label(self) -> &'static str {
        match self {
            LocalSource::ActiveVirtualEnv => "VIRTUAL_ENV",
            LocalSource::UvProjectEnvironment => "UV_PROJECT_ENVIRONMENT",
            LocalSource::CheckoutVenv => "checkout .venv",
        }
    }
}

/// What the launcher should do with this invocation.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Use the managed `~/.huitzo/venv` — today's behaviour.
    Delegate,
    /// Exec the locally detected interpreter instead of the managed one.
    RunLocal {
        /// Interpreter to exec (`<venv>/bin/python`).
        python: PathBuf,
        /// Which signal selected it.
        source: LocalSource,
        /// Whether this interpreter accepts `-P` (Python 3.11+). Read from
        /// the venv's own `pyvenv.cfg`; `false` when the version cannot be
        /// established, because an unrecognised `-P` is a hard startup error.
        safe_path: bool,
    },
    /// A `huitzo-cli` checkout is in play but no local environment can run it.
    /// Refuse loudly rather than silently running different code.
    Refuse {
        /// The checkout root that was detected.
        checkout: PathBuf,
        /// Environment roots that were examined, in priority order.
        searched: Vec<PathBuf>,
    },
    /// A `huitzo-cli` checkout was found by walking up from the invocation
    /// directory, but it is not owned by this user — so it is NOT a signal
    /// this launcher will act on. Delegate (today's behaviour) and say why.
    DelegateUntrustedCheckout {
        /// The directory that looked like a checkout.
        checkout: PathBuf,
        /// Why it was not trusted, including the uids compared — a container
        /// or NFS uid mapping is a far likelier cause than a real intruder,
        /// and the numbers are what tell the two apart.
        reason: String,
    },
}

/// The injected environment the decision is made from.
///
/// Construct it with [`Detect::from_process`] in production; construct it
/// literally in tests — every field the decision reads lives here, so
/// [`Detect::decide`] never consults the ambient process environment.
#[derive(Debug, Clone, Default)]
pub struct Detect {
    /// `--use-installed` or `HUITZO_LAUNCHER_FORCE` — skip detection entirely.
    pub force: bool,
    /// `$VIRTUAL_ENV`, if set and non-empty.
    pub virtual_env: Option<PathBuf>,
    /// `$UV_PROJECT_ENVIRONMENT`, if set and non-empty.
    pub uv_project_environment: Option<PathBuf>,
    /// Directory the launcher was invoked from.
    pub cwd: Option<PathBuf>,
    /// The managed venv's interpreter (`~/.huitzo/venv/bin/python`).
    pub managed_python: PathBuf,
    /// This launcher binary, used as the exec-recursion guard.
    pub launcher_exe: Option<PathBuf>,
    /// The invoking user's effective uid, used to reject directories owned by
    /// someone else before they can select an interpreter. `None` disables
    /// the check (Windows, where ownership is an ACL question and non-WSL
    /// Windows is unsupported anyway).
    pub uid: Option<u32>,
}

impl Detect {
    /// Snapshot the real process environment. `force_flag` carries
    /// `--use-installed`, which `main()` has already consumed from argv.
    pub fn from_process(force_flag: bool) -> Self {
        Self {
            force: force_flag || env_is_truthy(FORCE_ENV),
            virtual_env: env_path("VIRTUAL_ENV"),
            uv_project_environment: env_path("UV_PROJECT_ENVIRONMENT"),
            cwd: std::env::current_dir().ok(),
            managed_python: crate::dirs::venv_python(),
            launcher_exe: std::env::current_exe().ok(),
            uid: current_uid(),
        }
    }

    /// Decide between the managed venv, a local interpreter, and refusal.
    ///
    /// The rule, in order:
    ///
    /// 1. `force` → [`Decision::Delegate`], no detection, no notice.
    /// 2. Otherwise, take the first candidate environment — `VIRTUAL_ENV`,
    ///    then `UV_PROJECT_ENVIRONMENT`, then `<checkout>/.venv` — that has a
    ///    usable interpreter AND a `huitzo_cli` distribution →
    ///    [`Decision::RunLocal`]. A candidate that *is* the managed venv means
    ///    the user activated the managed environment: delegate, silently.
    /// 3. Otherwise, if a `huitzo-cli` source checkout was detected above the
    ///    invocation directory → [`Decision::Refuse`]. This is the only
    ///    refusal case: a strong signal that the developer means the local
    ///    source, with no local environment able to run it.
    /// 4. Otherwise, if the only thing that looked like a checkout failed the
    ///    ownership test below → [`Decision::DelegateUntrustedCheckout`]:
    ///    delegate as before, and say once that it was ignored.
    /// 5. Otherwise → [`Decision::Delegate`]. An unrelated venv, an unrelated
    ///    project, or a plain shell keeps working exactly as before.
    ///
    /// Trust boundary: the two kinds of signal are NOT equally trusted.
    /// `VIRTUAL_ENV` / `UV_PROJECT_ENVIRONMENT` are the user's own explicit
    /// declaration, and an attacker who can write into that venv already owns
    /// every `python` run from it (a `.pth` there executes on startup), so
    /// they are taken at face value. A checkout found by walking up
    /// from the invocation directory is *ambient discovery* — the user may
    /// never have looked at that directory — so it and its `.venv` must be
    /// owned by the invoking user (see [`Detect::is_trusted_dir`]). That is
    /// what stops a `pyproject.toml` + `.venv` planted in a world-writable
    /// directory such as `/tmp` from choosing the interpreter, the same
    /// failure git closed with `safe.directory` (CVE-2022-24765).
    pub fn decide(&self) -> Decision {
        if self.force {
            return Decision::Delegate;
        }

        let (checkout, untrusted) = match self.cwd.as_deref() {
            Some(cwd) => match self.find_checkout(cwd) {
                Checkout::Trusted(dir) => (Some(dir), None),
                Checkout::Untrusted { dir, reason } => (None, Some((dir, reason))),
                Checkout::None => (None, None),
            },
            None => (None, None),
        };

        for (root, source) in self.candidate_envs(checkout.as_deref()) {
            let Some(python) = self.usable_interpreter(&root, source) else {
                continue;
            };
            if same_interpreter(&python, &self.managed_python) {
                // The managed environment is the active one. Delegating runs
                // exactly what is activated — and keeps bootstrap/update.
                return Decision::Delegate;
            }
            if has_huitzo_cli(&root) {
                return Decision::RunLocal {
                    python,
                    source,
                    safe_path: venv_supports_safe_path(&root),
                };
            }
        }

        match (checkout, untrusted) {
            (Some(checkout), _) => {
                let searched = self
                    .candidate_envs(Some(&checkout))
                    .into_iter()
                    .map(|(root, _)| root)
                    .collect();
                Decision::Refuse { checkout, searched }
            }
            (None, Some((checkout, reason))) => {
                Decision::DelegateUntrustedCheckout { checkout, reason }
            }
            (None, None) => Decision::Delegate,
        }
    }

    /// Walk up from `start` looking for the nearest `huitzo-cli` source
    /// checkout, classifying what it finds by ownership.
    ///
    /// Cost in the common case is one `stat` per ancestor directory; a
    /// `pyproject.toml` is only read when one exists, and ownership is only
    /// checked once a directory has already matched.
    ///
    /// Every directory whose `pyproject.toml` *steered* the outcome has to
    /// pass the ownership test, not just the one finally selected: for a
    /// workspace root the root names the member, so an untrusted root cannot
    /// be allowed to point at a member that happens to be trusted.
    fn find_checkout(&self, start: &Path) -> Checkout {
        for dir in start.ancestors().take(MAX_WALK_DEPTH) {
            let Some(text) = read_capped(&dir.join("pyproject.toml")) else {
                continue;
            };
            match classify_pyproject(&text) {
                PyprojectKind::IsHuitzoCli | PyprojectKind::DeclaresHuitzoCliSource => {
                    return self.classify_dir(dir.to_path_buf());
                }
                PyprojectKind::WorkspaceRoot(members) => {
                    for member in members {
                        let member_dir = dir.join(&member);
                        let Some(text) = read_capped(&member_dir.join("pyproject.toml")) else {
                            continue;
                        };
                        if !matches!(classify_pyproject(&text), PyprojectKind::IsHuitzoCli) {
                            continue;
                        }
                        // The root's `members` list is what selected this
                        // directory, so the root must be trusted before the
                        // member is even considered.
                        if let Some(reason) = self.is_trusted_dir(dir) {
                            return Checkout::Untrusted {
                                dir: dir.to_path_buf(),
                                reason,
                            };
                        }
                        return self.classify_dir(member_dir);
                    }
                }
                PyprojectKind::Other => {}
            }
        }
        Checkout::None
    }

    /// Classify an already-matched directory by ownership.
    fn classify_dir(&self, dir: PathBuf) -> Checkout {
        match self.is_trusted_dir(&dir) {
            None => Checkout::Trusted(dir),
            Some(reason) => Checkout::Untrusted { dir, reason },
        }
    }

    /// `None` when `path` is owned by the invoking user and not
    /// world-writable; otherwise the reason it is not trusted.
    ///
    /// Always `None` when `uid` is `None` (Windows): there is no portable
    /// owner comparison there, and native Windows is unsupported.
    fn is_trusted_dir(&self, path: &Path) -> Option<String> {
        let uid = self.uid?;
        let Some((owner, world_writable)) = dir_ownership(path) else {
            return Some("unreadable".to_string());
        };
        if owner != uid {
            return Some(format!(
                "owned by another user: directory uid {owner}, this process uid {uid}"
            ));
        }
        if world_writable {
            return Some("world-writable".to_string());
        }
        None
    }

    /// Candidate environment roots in priority order, de-duplicated.
    fn candidate_envs(&self, checkout: Option<&Path>) -> Vec<(PathBuf, LocalSource)> {
        let mut out: Vec<(PathBuf, LocalSource)> = Vec::with_capacity(3);
        let mut push = |root: PathBuf, source: LocalSource| {
            if !out.iter().any(|(existing, _)| *existing == root) {
                out.push((root, source));
            }
        };

        if let Some(venv) = &self.virtual_env {
            push(venv.clone(), LocalSource::ActiveVirtualEnv);
        }
        if let Some(uv_env) = &self.uv_project_environment {
            // uv resolves a relative UV_PROJECT_ENVIRONMENT against the
            // project root; fall back to the invocation directory.
            let base = checkout.or(self.cwd.as_deref());
            let resolved = match base {
                Some(base) if uv_env.is_relative() => base.join(uv_env),
                _ => uv_env.clone(),
            };
            push(resolved, LocalSource::UvProjectEnvironment);
        }
        if let Some(checkout) = checkout {
            push(checkout.join(".venv"), LocalSource::CheckoutVenv);
        }
        out
    }

    /// The interpreter inside `root`, if it exists and is safe to exec.
    ///
    /// Safe means: a regular, executable file after symlink resolution; not
    /// this launcher binary (a `huitzo` shim planted at `<venv>/bin/python`
    /// would otherwise exec back into the launcher and loop); and, for a
    /// candidate discovered by walking up from the invocation directory,
    /// owned by the invoking user.
    fn usable_interpreter(&self, root: &Path, source: LocalSource) -> Option<PathBuf> {
        // Ambient discovery is not trusted on ownership alone (see `decide`);
        // an explicitly exported VIRTUAL_ENV / UV_PROJECT_ENVIRONMENT is.
        if source == LocalSource::CheckoutVenv && self.is_trusted_dir(root).is_some() {
            return None;
        }
        let python = venv_python_path(root);
        // `metadata` follows symlinks — a venv interpreter is normally a
        // symlink to the base interpreter, which is fine; what matters is
        // that the target is a regular, executable file.
        if !std::fs::metadata(&python).is_ok_and(is_executable_file) {
            return None;
        }
        // Recursion guard. `canonicalize` must succeed — the metadata call
        // above already proved the path resolves — and a launcher path we
        // cannot canonicalize is compared literally rather than waved through.
        let Ok(resolved) = std::fs::canonicalize(&python) else {
            return None;
        };
        if let Some(launcher) = &self.launcher_exe {
            let launcher_resolved =
                std::fs::canonicalize(launcher).unwrap_or_else(|_| launcher.clone());
            if resolved == launcher_resolved || python == *launcher {
                return None;
            }
        }
        Some(python)
    }
}

/// The interpreter path inside a venv root, per platform layout.
pub fn venv_python_path(venv_root: &Path) -> PathBuf {
    if cfg!(windows) {
        venv_root.join("Scripts").join("python.exe")
    } else {
        venv_root.join("bin").join("python")
    }
}

/// True if both paths name the same file on disk.
///
/// Compares canonical paths when both resolve (so `/a/../a/bin/python` and a
/// symlinked interpreter compare equal), and falls back to a literal compare.
fn same_interpreter(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Read a file, refusing anything implausibly large for a project manifest.
fn read_capped(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_PYPROJECT_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// What a `pyproject.toml` says about `huitzo-cli`.
#[derive(Debug, PartialEq, Eq)]
enum PyprojectKind {
    /// `[project] name = "huitzo-cli"` — this IS the CLI source tree.
    IsHuitzoCli,
    /// `[tool.uv.sources] huitzo-cli = { workspace = true }` (or a path
    /// source) — this project resolves the CLI from local source.
    DeclaresHuitzoCliSource,
    /// `[tool.uv.workspace] members = [...]` — literal (non-glob) members,
    /// any of which may be the CLI.
    WorkspaceRoot(Vec<String>),
    /// Some other project.
    Other,
}

/// Classify a `pyproject.toml` without a TOML parser.
///
/// The launcher deliberately carries no TOML dependency (CLAUDE.md: no new
/// dependencies unless unavoidable), and the three facts needed here are all
/// simple `key = value` lines under a known section header. Anything this
/// scanner cannot understand falls through to [`PyprojectKind::Other`], whose
/// consequence is the pre-#53 behaviour.
fn classify_pyproject(text: &str) -> PyprojectKind {
    let mut section = String::new();
    let mut workspace_members: Vec<String> = Vec::new();
    let mut in_members = false;

    for raw in text.lines() {
        let line = strip_comment(raw);
        if line.is_empty() {
            continue;
        }

        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = header.trim().trim_matches('"').to_string();
            in_members = false;
            continue;
        }

        match section.as_str() {
            "project" => {
                if let Some(value) = key_value(line, "name") {
                    if normalize_dist(&unquote(value)) == "huitzo_cli" {
                        return PyprojectKind::IsHuitzoCli;
                    }
                }
            }
            "tool.uv.sources" => {
                if let Some((key, value)) = split_key_value(line) {
                    if normalize_dist(&unquote(key)) == "huitzo_cli"
                        && (value.contains("workspace") || value.contains("path"))
                    {
                        return PyprojectKind::DeclaresHuitzoCliSource;
                    }
                }
            }
            "tool.uv.workspace" => {
                // `members = ["cli", "packages/foo"]`, possibly multi-line.
                let payload = match key_value(line, "members") {
                    Some(value) => {
                        in_members = !value.contains(']');
                        value
                    }
                    None if in_members => {
                        in_members = !line.contains(']');
                        line
                    }
                    None => continue,
                };
                for entry in payload.split(',') {
                    let entry = unquote(entry.trim().trim_matches(['[', ']']).trim());
                    // Globs are not resolved: matching them would mean a
                    // directory scan on every launch for a signal the
                    // literal-member and `[tool.uv.sources]` rules already
                    // cover in practice.
                    if !entry.is_empty() && !entry.contains(['*', '?']) {
                        workspace_members.push(entry);
                    }
                }
            }
            _ => {}
        }
    }

    if workspace_members.is_empty() {
        PyprojectKind::Other
    } else {
        PyprojectKind::WorkspaceRoot(workspace_members)
    }
}

/// Drop a trailing `#` comment (naive: a `#` inside a quoted value ends the
/// line early, which can only lose a signal, never invent one) and trim.
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => line[..idx].trim(),
        None => line.trim(),
    }
}

/// `key = value` split on the first `=`.
fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    Some((key.trim(), value.trim()))
}

/// The value of `line` when it assigns `key`.
fn key_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let (found, value) = split_key_value(line)?;
    (found.trim_matches('"') == key).then_some(value)
}

/// Strip one layer of matching quotes.
fn unquote(value: &str) -> String {
    value
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .to_string()
}

/// PEP 503-ish normalization: lowercase, `-`/`.` → `_`.
fn normalize_dist(name: &str) -> String {
    name.trim().to_lowercase().replace(['-', '.'], "_")
}

/// Classification of the nearest matching directory found by walking up from
/// the invocation directory.
#[derive(Debug, PartialEq, Eq)]
enum Checkout {
    /// A `huitzo-cli` checkout owned by the invoking user.
    Trusted(PathBuf),
    /// Something that looks like a `huitzo-cli` checkout but is not ours.
    Untrusted { dir: PathBuf, reason: String },
    /// No checkout above the invocation directory.
    None,
}

/// `(owner_uid, world_writable)` for a directory, or `None` if it cannot be
/// stat'd. Windows has no portable owner uid, so ownership is not checked
/// there (see [`Detect::is_trusted_dir`]).
#[cfg(unix)]
fn dir_ownership(path: &Path) -> Option<(u32, bool)> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path).ok()?;
    Some((md.uid(), md.mode() & 0o002 != 0))
}

#[cfg(not(unix))]
fn dir_ownership(_path: &Path) -> Option<(u32, bool)> {
    None
}

/// The invoking user's effective uid, or `None` where ownership is not a
/// portable concept (Windows).
#[cfg(unix)]
fn current_uid() -> Option<u32> {
    Some(nix::unistd::Uid::effective().as_raw())
}

#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

/// True if `md` is a regular file that is executable by somebody.
#[cfg(unix)]
fn is_executable_file(md: std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    md.is_file() && md.mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable_file(md: std::fs::Metadata) -> bool {
    md.is_file()
}

/// True if the venv at `root` runs Python 3.11+, which is when `-P` exists.
///
/// Read from the venv's own `pyvenv.cfg` (`version` as written by the stdlib
/// `venv`, `version_info` as written by `uv`) — one small file read, no
/// process spawn. Unknown means `false`: the managed venv is guaranteed 3.11+
/// by `python::discover_all`, but a locally detected interpreter is not ours,
/// and passing `-P` to Python 3.10 is a hard startup error ("Unknown option:
/// -P") that would break the very workflow this module exists to fix.
fn venv_supports_safe_path(venv_root: &Path) -> bool {
    let Some(text) = read_capped(&venv_root.join("pyvenv.cfg")) else {
        return false;
    };
    for line in text.lines() {
        let Some((key, value)) = split_key_value(line) else {
            continue;
        };
        if key != "version" && key != "version_info" {
            continue;
        }
        let mut parts = value.trim().split('.');
        let (Some(Ok(major)), Some(Ok(minor))) = (
            parts.next().map(str::parse::<u32>),
            parts.next().map(str::parse::<u32>),
        ) else {
            continue;
        };
        return (major, minor) >= (3, 11);
    }
    false
}

/// True if the venv at `root` carries a `huitzo_cli` distribution.
///
/// Answered from the filesystem — never by spawning the interpreter, which
/// would cost 50-150 ms on a tool whose design premise is zero runtime
/// overhead. Covers a regular install (`site-packages/huitzo_cli/`), a wheel
/// install (`huitzo_cli-<ver>.dist-info/`) and an editable install (the
/// `.pth` / `__editable__…` finder uv writes for `uv sync` of the checkout).
fn has_huitzo_cli(venv_root: &Path) -> bool {
    for site_packages in site_packages_dirs(venv_root) {
        // Fast path: the imported package directory itself.
        if site_packages.join("huitzo_cli").is_dir() {
            return true;
        }
        let Ok(entries) = std::fs::read_dir(&site_packages) else {
            continue;
        };
        for entry in entries.flatten() {
            if is_huitzo_cli_marker(&entry.file_name().to_string_lossy()) {
                return true;
            }
        }
    }
    false
}

/// Candidate `site-packages` directories inside a venv root.
fn site_packages_dirs(venv_root: &Path) -> Vec<PathBuf> {
    if cfg!(windows) {
        return vec![venv_root.join("Lib").join("site-packages")];
    }
    let mut out = Vec::new();
    for lib in ["lib", "lib64"] {
        let Ok(entries) = std::fs::read_dir(venv_root.join(lib)) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with("python") {
                out.push(entry.path().join("site-packages"));
            }
        }
    }
    out
}

/// True if a `site-packages` entry name belongs to the `huitzo_cli`
/// distribution: the package dir, its `.dist-info`, or an editable-install
/// marker (`_huitzo_cli.pth`, `__editable___huitzo_cli_…_finder.py`).
fn is_huitzo_cli_marker(name: &str) -> bool {
    let base = name
        .trim_start_matches("__editable__")
        .trim_start_matches(['_', '.']);
    // Normalization has already folded `-` and `.` into `_`, so the version
    // suffix of a `.dist-info`, a `.pth` and an editable finder all reduce to
    // the same `huitzo_cli_…` shape.
    let base = normalize_dist(base);
    base == "huitzo_cli" || base.starts_with("huitzo_cli_")
}

/// True if `var` is set to something other than empty / `0` / `false`.
fn env_is_truthy(var: &str) -> bool {
    std::env::var(var).is_ok_and(|v| !v.is_empty() && v != "0" && v.to_lowercase() != "false")
}

/// `var` as a path, if set and non-empty.
fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_the_cli_source_tree() {
        let text = r#"
            [project]
            name = "huitzo-cli"
            version = "1.7.0"
        "#;
        assert_eq!(classify_pyproject(text), PyprojectKind::IsHuitzoCli);
    }

    #[test]
    fn classifies_a_workspace_source_declaration() {
        let text = r#"
            [project]
            name = "huitzo-monorepo"

            [tool.uv.sources]
            huitzo-cli = { workspace = true }
        "#;
        assert_eq!(
            classify_pyproject(text),
            PyprojectKind::DeclaresHuitzoCliSource
        );
    }

    #[test]
    fn collects_literal_workspace_members_and_skips_globs() {
        let text = r#"
            [tool.uv.workspace]
            members = ["cli", "packages/*"]
        "#;
        assert_eq!(
            classify_pyproject(text),
            PyprojectKind::WorkspaceRoot(vec!["cli".to_string()])
        );
    }

    #[test]
    fn unrelated_project_is_other() {
        let text = r#"
            [project]
            name = "some-other-tool"
            dependencies = ["huitzo-cli"]
        "#;
        assert_eq!(classify_pyproject(text), PyprojectKind::Other);
    }

    #[test]
    fn recognizes_install_layout_markers() {
        assert!(is_huitzo_cli_marker("huitzo_cli"));
        assert!(is_huitzo_cli_marker("huitzo_cli-1.7.0.dist-info"));
        assert!(is_huitzo_cli_marker("_huitzo_cli.pth"));
        assert!(is_huitzo_cli_marker(
            "__editable___huitzo_cli_1_7_0_finder.py"
        ));
        assert!(!is_huitzo_cli_marker("huitzo"));
        assert!(!is_huitzo_cli_marker("huitzo_sdk"));
        assert!(!is_huitzo_cli_marker("requests"));
    }
}
