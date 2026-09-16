// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

use crate::dirs;
use crate::errors::{Error, FeedError};
use crate::update::select_newest_release;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::PathBuf;

/// GitHub Releases API URL for CLI distribution (hosted on the public launcher repo).
/// CLI releases are tagged `cli-v*` to distinguish from launcher releases (`v*`).
const CLI_RELEASES_URL: &str = "https://api.github.com/repos/Huitzo-Inc/huitzo-launcher/releases";

/// Information about a CLI release, parsed from cli-release.json.
#[derive(Debug)]
pub struct CliRelease {
    pub version: String,
    /// Minimum launcher version this release may be installed by; enforced in
    /// [`fetch_cli_release`] via [`crate::update::enforce_min_launcher_version`].
    pub min_launcher_version: String,
    pub wheels: Vec<WheelInfo>,
}

/// A platform-specific wheel in a release.
#[derive(Debug)]
pub struct WheelInfo {
    pub platform_key: String,
    pub filename: String,
    pub sha256: String,
}

/// Why this host cannot install the Huitzo CLI.
///
/// Each variant is a founder decision plus a fact about the published feed,
/// not a guess: the CLI ships **only** as a compiled wheel, so a host with no
/// wheel has nothing to install and no fallback to degrade into (D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedReason {
    /// D2 — Intel macOS. `cli-release.json` carries `macos-arm64-cp312` and
    /// `macos-arm64-cp313` and no `macos-x86_64` key at any Python version.
    IntelMac,
    /// D8 — musl/Alpine. `cli-v0.11.1` publishes 8 wheels, every Linux one
    /// `manylinux2014`/`manylinux_2_17`/`manylinux_2_28`; zero `musllinux`.
    /// pip on a musl host computes `musllinux_*` tags and rejects all of them.
    Musl,
    /// m11 — Windows on ARM. No launcher asset and no pinned `uv` asset is
    /// published for `aarch64-pc-windows-*`, so the bootstrap cannot even
    /// stage itself, let alone find a wheel.
    WindowsArm,
    /// M3 — anything else. Previously these fell through a catch-all `else`
    /// and asked the feed for `linux-x86_64`.
    Unknown,
}

/// The platform keys the release feed is built around, for error messages.
pub const SUPPORTED_KEYS: &str =
    "macos-arm64, linux-x86_64 (glibc), linux-aarch64 (glibc), windows-x86_64";

/// Returns the base platform key for the current OS/architecture, or the
/// reason this host has no key at all.
///
/// Must match the prefix used in cli-release.json:
/// linux-x86_64, linux-aarch64, macos-arm64, windows-x86_64
///
/// There is deliberately no fallback key (M3): a host we do not recognise gets
/// an error naming what was detected, never a guess that sends a Windows-on-ARM
/// machine to fetch a Linux wheel.
pub fn current_platform() -> Result<&'static str, Error> {
    // `std::env::consts::OS`/`ARCH` are compile-time target facts, which is
    // exactly right for OS and architecture — a binary cannot run on a
    // different one. libc is NOT such a fact: this launcher is built for
    // `x86_64-unknown-linux-musl` specifically so one binary runs everywhere,
    // so `cfg!(target_env = "musl")` is true on Debian and Alpine alike and
    // describes the launcher, not the host. Hence the runtime probe (B9).
    resolve_platform(std::env::consts::OS, std::env::consts::ARCH, host_is_musl)
}

/// Refuse, loudly and early, if this host has no wheel — before consent is
/// asked, before `uv` is staged, before a venv exists.
///
/// The bootstrap path calls this first so an unsupported machine ends with an
/// explanation and an empty `$HUITZO_HOME`, rather than downloading a toolchain
/// to discover the same thing three steps later (B5, B9).
pub fn ensure_supported_platform() -> Result<(), Error> {
    current_platform().map(|_| ())
}

/// The OS/arch/libc → platform-key mapping, with the libc probe injected.
///
/// Separated from [`current_platform`] so every branch — including the ones
/// this machine can never take, such as Intel macOS — is reachable from a test
/// without a Mac, an Alpine box or a Windows-on-ARM laptop.
///
/// `is_musl` is a closure, not a `bool`, so the filesystem probe never runs on
/// a platform where the answer cannot matter (it is a match guard, hence `Fn`).
fn resolve_platform(
    os: &str,
    arch: &str,
    is_musl: impl Fn() -> bool,
) -> Result<&'static str, Error> {
    let refuse = |reason| {
        Err(Error::UnsupportedPlatform {
            os: os.to_string(),
            arch: arch.to_string(),
            reason,
        })
    };

    match (os, arch) {
        // Linux is the only platform where libc is a question, and it is
        // asked before the key is handed out — a musl host that resolved
        // `linux-x86_64` would go on to install a manylinux wheel pip cannot
        // accept, which is precisely #B9.
        ("linux", "x86_64" | "aarch64") if is_musl() => refuse(UnsupportedReason::Musl),
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("linux", "aarch64") => Ok("linux-aarch64"),
        ("macos", "aarch64") => Ok("macos-arm64"),
        ("macos", "x86_64") => refuse(UnsupportedReason::IntelMac),
        ("windows", "x86_64") => Ok("windows-x86_64"),
        ("windows", "aarch64") => refuse(UnsupportedReason::WindowsArm),
        _ => refuse(UnsupportedReason::Unknown),
    }
}

/// Does the *host* run musl libc rather than glibc?
///
/// Positive evidence only, and evidence that survives a cross-libc developer
/// machine:
///
/// * `/etc/alpine-release` — Alpine is musl by construction. Even with
///   `gcompat` installed the interpreter still tags itself `musllinux_*`, so
///   pip rejects the manylinux wheels regardless; Alpine is out either way.
/// * a `ld-musl-*.so.1` loader in `/lib` **and no glibc loader anywhere**.
///   The second half matters: `apt install musl` on Debian drops
///   `/lib/ld-musl-x86_64.so.1` onto a perfectly supported glibc host, and
///   refusing to install there would be a worse bug than the one being fixed.
///
/// Deliberately not the inverse ("no glibc found ⇒ musl"): a distro that keeps
/// its loader somewhere unusual (NixOS puts it under `/nix/store`) would be
/// refused for no reason. A missed musl host still fails safely, but later and
/// less legibly, and `Error::NoWheel` is no longer what catches it: the platform
/// key is `linux-x86_64` on musl and glibc alike, so since T14 a musl host with
/// a 3.12/3.13 interpreter reads as wheel-compatible and one without provisions
/// a managed CPython instead of being refused. Both then fail downstream — pip
/// rejecting a manylinux wheel (`Error::PipInstall`), or `uv python install`
/// having no build for the host (`Error::NoPython`). Nothing is installed and no
/// path reports success, but the message blames pip or uv rather than the libc,
/// which is why the positive check above has to do the work.
fn host_is_musl() -> bool {
    if std::path::Path::new("/etc/alpine-release").exists() {
        return true;
    }
    has_musl_loader() && !has_glibc_loader()
}

/// musl's loader is always `/lib/ld-musl-$ARCH.so.1`. Scanning the directory
/// rather than building the name keeps this correct on architectures the
/// launcher is not itself built for.
fn has_musl_loader() -> bool {
    let Ok(entries) = std::fs::read_dir("/lib") else {
        return false;
    };
    entries.flatten().any(|e| {
        let name = e.file_name();
        let name = name.to_string_lossy();
        name.starts_with("ld-musl-") && name.ends_with(".so.1")
    })
}

/// glibc's loader and runtime, across the layouts in use: multiarch (Debian,
/// Ubuntu), `/lib64` (RHEL, Fedora, SUSE) and merged-`/usr` symlinks.
fn has_glibc_loader() -> bool {
    [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/aarch64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/lib/libc.so.6",
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/ld-linux-aarch64.so.1",
    ]
    .iter()
    .any(|p| std::path::Path::new(p).exists())
}

// --- HTTP transport: timeouts, proxy and trust anchors (M12, m15) -----------
//
// Every request the launcher makes on the install or update path is built
// here, so "does this request have a timeout?" has one answer instead of one
// per call site. Before this, only `fetch_feed` was bounded: the ~50 MB wheel
// download and the whole of `update.rs` had no timeout at all and a blackholed
// connection hung `huitzo` forever.

/// Cap on DNS + TCP + any proxy CONNECT + the TLS handshake.
///
/// Sized for a slow corporate proxy chain, not for a healthy connection: 15 s
/// is well past the ~1-3 s a real handshake takes even through a MITM proxy,
/// and is what bounds the "socket accepts and never speaks" case, where the
/// TCP connect succeeds and the TLS handshake is what hangs.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Cap on waiting for response *headers* after the request is sent.
///
/// This is server think-time, not transfer time — GitHub answers in
/// milliseconds, so 30 s only ever fires on something that is not answering.
const RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Cap on a whole feed request: connect, headers and a small JSON body.
///
/// The release list and `cli-release.json` are tens of kilobytes; nothing
/// legitimate on this path takes 30 s.
const FEED_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Cap on a whole artefact download: connect, headers and the body.
///
/// The largest artefact on the install path is the CLI wheel at roughly 50 MB
/// (the launcher binary and the `uv` archive are smaller). 15 minutes is a
/// floor of about 57 kB/s sustained — below a bad hotel link or a throttled
/// mobile tether, so a genuinely slow but working connection still finishes —
/// while still being a bound, which is the whole point: `ureq` applies no
/// timeout by default, so the old code's only "bound" was TCP keepalive.
///
/// This is a total budget, not an idle one: `ureq` 3 has no configurable
/// stall timeout, so a transfer that trickles for 15 minutes is cut off. That
/// is the conservative direction — a hung install that never returns is worse
/// than one that fails with a message naming the budget it blew.
const DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);

/// Env var naming a PEM file of trust anchors to use *instead of* the CA list
/// compiled into the launcher.
///
/// Same semantics as `CURL_CA_BUNDLE` / `REQUESTS_CA_BUNDLE`: it replaces the
/// default set rather than adding to it, so on a machine that must reach both
/// the corporate proxy and the public internet, point it at the system bundle
/// (which already contains the public roots plus the corporate one), e.g.
/// `/etc/ssl/certs/ca-certificates.crt`.
pub const CA_BUNDLE_ENV: &str = "HUITZO_CA_BUNDLE";

/// Proxy env vars, in the order `ureq` itself tries them.
const PROXY_ENV: &[&str] = &[
    "ALL_PROXY",
    "all_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
];

/// How long a family of requests is allowed to take, and what to call it in
/// an error message.
#[derive(Clone, Copy)]
pub(crate) struct Budget {
    what: &'static str,
    global: std::time::Duration,
}

impl Budget {
    /// The cap on the whole call, for messages that quote it back.
    pub(crate) fn global_secs(&self) -> u64 {
        self.global.as_secs()
    }
}

/// Small JSON over HTTPS: the release list, `cli-release.json`, a checksum.
pub(crate) const FEED_BUDGET: Budget = Budget {
    what: "release feed request",
    global: FEED_TIMEOUT,
};

/// A whole artefact: a wheel, a launcher binary, a `uv` archive.
pub(crate) const DOWNLOAD_BUDGET: Budget = Budget {
    what: "download",
    global: DOWNLOAD_TIMEOUT,
};

/// The first proxy env var that carries a value, and that value.
fn proxy_env_value() -> Option<(&'static str, String)> {
    PROXY_ENV.iter().find_map(|name| {
        let value = std::env::var(name).ok()?;
        let value = value.trim().to_string();
        (!value.is_empty()).then_some((*name, value))
    })
}

/// Hide any `user:password@` in a proxy URL before it reaches stderr.
fn redact_userinfo(proxy: &str) -> String {
    match proxy.rsplit_once('@') {
        Some((before, host)) => {
            let scheme = before.split_once("://").map(|(s, _)| s);
            match scheme {
                Some(scheme) => format!("{scheme}://***@{host}"),
                None => format!("***@{host}"),
            }
        }
        None => proxy.to_string(),
    }
}

/// The proxy to route through, from the environment.
///
/// `ureq` reads these variables itself when its `Config` is defaulted, but
/// doing it here is deliberate, and not only so the setting can be *named* in
/// an error: `ureq` answers "could not parse that" and "no proxy is
/// configured" with the same `None`, and a launcher that quietly connects
/// direct because `HTTPS_PROXY` had a typo in it is indistinguishable, from
/// the user's side, from one that ignores the proxy on purpose. So an
/// unusable value is an error here, not a shrug.
fn proxy_from_env() -> Result<Option<ureq::Proxy>, Error> {
    // Handles every form in the wild: `http://host:port`, `https://`,
    // `socks5://`, credentials, and the scheme-less `host:port` — `ureq`
    // parses that last one as a URI authority.
    if let Some(proxy) = ureq::Proxy::try_from_env() {
        return Ok(Some(proxy));
    }
    match proxy_env_value() {
        // Nothing configured: connect direct, which is the overwhelming case.
        None => Ok(None),
        // Something *is* configured and none of it parsed.
        Some((var, value)) => Err(Error::ProxyConfig {
            var: var.to_string(),
            value: redact_userinfo(&value),
        }),
    }
}

/// The trust anchors to verify servers against.
///
/// `None` means "the CA list compiled into the launcher". `Err` means the user
/// named a bundle that yielded no certificate — see [`Error::CaBundle`] for why
/// that is terminal rather than a fall back.
fn root_certs_from_env() -> Result<Option<ureq::tls::RootCerts>, Error> {
    let Some(path) = std::env::var(CA_BUNDLE_ENV)
        .ok()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
    else {
        return Ok(None);
    };

    let bad = |detail: String| Error::CaBundle {
        path: path.clone(),
        detail,
    };

    let pem = std::fs::read(&path).map_err(|e| bad(e.to_string()))?;
    let certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(&pem)
        .filter_map(|item| match item {
            // A bundle that also carries a key is normal; take the certs and
            // ignore the rest rather than refusing the file.
            Ok(ureq::tls::PemItem::Certificate(cert)) => Some(cert),
            _ => None,
        })
        .collect();

    if certs.is_empty() {
        return Err(bad(
            "the file parsed but contains no CERTIFICATE section".to_string()
        ));
    }
    Ok(Some(ureq::tls::RootCerts::from(certs)))
}

/// Build the agent every request on the install/update path goes through.
///
/// Rebuilt per call rather than cached in a `OnceLock`: the launcher makes a
/// handful of requests per run, to a handful of hosts, so there is no pool to
/// preserve, and re-reading the environment keeps the proxy and CA settings
/// honest instead of frozen at whichever request happened to come first.
pub(crate) fn http_agent(budget: Budget) -> Result<ureq::Agent, Error> {
    let mut config = ureq::Agent::config_builder()
        .http_status_as_error(false) // callers classify the status themselves
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_recv_response(Some(RESPONSE_TIMEOUT))
        .timeout_global(Some(budget.global))
        .proxy(proxy_from_env()?);

    if let Some(roots) = root_certs_from_env()? {
        config = config.tls_config(ureq::tls::TlsConfig::builder().root_certs(roots).build());
    }

    Ok(config.build().into())
}

/// Is this failure the TLS handshake rather than the network under it?
///
/// `ureq::Error` is `#[non_exhaustive]` and routes rustls failures through a
/// feature-gated variant, so this asks the question two ways: the variants
/// that are unconditionally TLS, then the rendered text for the rest.
fn is_tls_failure(e: &ureq::Error) -> bool {
    if matches!(e, ureq::Error::Tls(_) | ureq::Error::TlsRequired) {
        return true;
    }
    let rendered = e.to_string().to_ascii_lowercase();
    ["rustls:", "native-tls:", "certificate", "handshake"]
        .iter()
        .any(|needle| rendered.contains(needle))
}

/// The proxy and CA settings in effect, as the user would have to type them.
fn transport_settings() -> String {
    let proxy = match proxy_env_value() {
        Some((name, value)) => format!("{name}={}", redact_userinfo(&value)),
        None => "none set (ALL_PROXY / HTTPS_PROXY / HTTP_PROXY)".to_string(),
    };
    let ca = match std::env::var(CA_BUNDLE_ENV) {
        Ok(path) if !path.trim().is_empty() => format!("{CA_BUNDLE_ENV}={}", path.trim()),
        _ => format!("{CA_BUNDLE_ENV} not set"),
    };
    format!(
        "\x20     proxy:     {proxy}\n\
         \x20     CA bundle: {ca}"
    )
}

/// Classify a `ureq` failure into the launcher's vocabulary, naming the
/// settings that decide whether the request could have worked.
///
/// The TLS case is the one worth spelling out: the launcher verifies against
/// the CA list compiled into it, *not* the machine's certificate store, so a
/// TLS-intercepting corporate proxy fails here no matter how thoroughly the
/// admin installed its root system-wide. Without this message the next person
/// is guessing.
pub(crate) fn transport_failure(e: &ureq::Error, budget: Budget) -> FeedError {
    let settings = transport_settings();

    if is_tls_failure(e) {
        return FeedError::Tls(format!(
            "{e}\n\
             \x20   The launcher verifies TLS against the CA list compiled into it, not this\n\
             \x20   machine's certificate store, so a TLS-intercepting proxy is rejected until\n\
             \x20   it is told which CA signed what it is presenting.\n\
             {settings}\n\
             \x20   Fix it by exporting the intercepting CA (PEM, may hold a chain):\n\
             \x20     export {CA_BUNDLE_ENV}=/etc/ssl/certs/ca-certificates.crt\n\
             \x20   See docs/SUPPORT_MATRIX.md, \"Behind a TLS-intercepting proxy\"."
        ));
    }

    if let ureq::Error::Timeout(which) = e {
        let budget_secs = budget.global.as_secs();
        return FeedError::Unreachable(format!(
            "the {} timed out ({which})\n\
             \x20   Budgets: connect {}s, response headers {}s, whole request {budget_secs}s.\n\
             {settings}",
            budget.what,
            CONNECT_TIMEOUT.as_secs(),
            RESPONSE_TIMEOUT.as_secs(),
        ));
    }

    FeedError::Unreachable(format!("{e}\n{settings}"))
}

/// A GitHub token to raise the 60-req/hour unauthenticated allowance, if the
/// environment offers one AND the feed is actually GitHub.
///
/// The host check is not cosmetic: `HUITZO_RELEASE_URL` can point anywhere, and
/// attaching the user's token to an arbitrary host would hand it to whoever set
/// that variable.
fn github_token_for(url: &str) -> Option<String> {
    let host = url::Url::parse(url).ok()?.host_str()?.to_ascii_lowercase();
    if host != "api.github.com" {
        return None;
    }
    ["GITHUB_TOKEN", "GH_TOKEN"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .find(|v| !v.trim().is_empty())
}

/// GET `url` and return its body, classifying every failure as a [`FeedError`].
///
/// The classification is the point (M11): "GitHub is rate-limiting this IP",
/// "there is no network" and "that URL served something else" are three
/// different problems with three different remedies, and the old code turned
/// all of them into `Option::None` and then into a silent PyPI stub install.
fn fetch_feed(url: &str) -> Result<String, Error> {
    let unavailable = |cause: FeedError| Error::FeedUnavailable {
        url: url.to_string(),
        cause,
    };

    let mut request = http_agent(FEED_BUDGET)?
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "huitzo-launcher");
    if let Some(token) = github_token_for(url) {
        request = request.header("Authorization", format!("Bearer {token}"));
    }

    let mut response = request
        .call()
        .map_err(|e| unavailable(transport_failure(&e, FEED_BUDGET)))?;

    let status = response.status().as_u16();
    if status != 200 {
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        return Err(unavailable(if status == 403 || status == 429 {
            FeedError::Forbidden {
                status,
                remaining: header("x-ratelimit-remaining").and_then(|v| v.parse().ok()),
                retry_after: header("x-ratelimit-reset")
                    .and_then(|v| v.parse().ok())
                    .and_then(describe_reset),
            }
        } else {
            FeedError::Status(status)
        }));
    }

    response
        .body_mut()
        .read_to_string()
        .map_err(|e| unavailable(FeedError::Unreachable(format!("truncated response: {e}"))))
}

/// Render GitHub's `x-ratelimit-reset` (a Unix timestamp) as a wait the user
/// can act on. `None` when the clock says the reset is already behind us —
/// "resets in 0 minutes" would be noise, not information.
fn describe_reset(reset_epoch: u64) -> Option<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let seconds = reset_epoch.checked_sub(now)?;
    Some(match seconds {
        0 => return None,
        1..=90 => format!("in {seconds}s"),
        _ => format!("in {}min", seconds.div_ceil(60)),
    })
}

/// Fetch the latest CLI release manifest (cli-release.json) from GitHub Releases.
///
/// If `HUITZO_RELEASE_URL` is set, uses that as the base URL instead.
///
/// Every failure is an [`Error::FeedUnavailable`] naming which kind it was; a
/// caller that cannot read the feed has no wheel to install and no business
/// guessing (D5).
pub fn fetch_cli_release() -> Result<CliRelease, Error> {
    let releases_url =
        std::env::var("HUITZO_RELEASE_URL").unwrap_or_else(|_| CLI_RELEASES_URL.to_string());

    let malformed = |detail: String| Error::FeedUnavailable {
        url: releases_url.clone(),
        cause: FeedError::Malformed(detail),
    };

    let body_str = fetch_feed(&releases_url)?;

    let releases: serde_json::Value = serde_json::from_str(&body_str)
        .map_err(|e| malformed(format!("release list is not JSON: {e}")))?;

    if !releases.is_array() {
        return Err(malformed("release list is not a JSON array".to_string()));
    }

    // Find the latest CLI release (tagged cli-v*) by version, not by position:
    // every cli-v* release shares one `created_at`, so the API's order among
    // them is arbitrary (#48).
    let release = find_latest_cli_release(&releases)
        .ok_or_else(|| malformed("no cli-v* release in the release list".to_string()))?;

    // Find cli-release.json asset
    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| malformed("newest cli-v* release lists no assets".to_string()))?;

    let manifest_url = assets
        .iter()
        .find(|a| a["name"].as_str() == Some("cli-release.json"))
        .and_then(|a| a["browser_download_url"].as_str())
        .ok_or_else(|| malformed("cli-release.json is not among the release assets".to_string()))?;

    // Download and parse cli-release.json
    let manifest_str = fetch_feed(manifest_url)?;

    let manifest: serde_json::Value = serde_json::from_str(&manifest_str)
        .map_err(|e| malformed(format!("cli-release.json is not JSON: {e}")))?;

    let release = parse_manifest(&manifest).map_err(malformed)?;

    // M10: the floor the feed publishes is enforced here, at the one point
    // every install, bootstrap and update path passes through. The comparison
    // itself lives with the rest of the version logic in `update`.
    crate::update::enforce_min_launcher_version(&release)?;

    Ok(release)
}

/// Turn a parsed `cli-release.json` body into a [`CliRelease`].
///
/// Split out from the fetch so the shape contract is testable without a server.
fn parse_manifest(manifest: &serde_json::Value) -> Result<CliRelease, String> {
    let version = manifest["version"]
        .as_str()
        .ok_or("cli-release.json has no `version`")?
        .to_string();

    // Parsed here, enforced by the caller: `parse_manifest` is the shape
    // contract and stays testable without a launcher-version dependency.
    // An older feed with no floor is not an error — it predates the field.
    let min_launcher_version = manifest["min_launcher_version"]
        .as_str()
        .unwrap_or("0.1.0")
        .to_string();

    let wheels_obj = manifest["wheels"]
        .as_object()
        .ok_or("cli-release.json has no `wheels` object")?;

    let mut wheels = Vec::new();
    for (key, val) in wheels_obj {
        let filename = val["filename"].as_str().unwrap_or("").to_string();
        let sha256 = val["sha256"].as_str().unwrap_or("").to_string();
        wheels.push(WheelInfo {
            platform_key: key.clone(),
            filename,
            sha256,
        });
    }

    Ok(CliRelease {
        version,
        min_launcher_version,
        wheels,
    })
}

/// Returns true if a compiled wheel exists for the given Python version on the current platform.
///
/// Used during Python selection in bootstrap to prefer interpreters that have a compiled wheel.
pub fn has_wheel_for(release: &CliRelease, python_version: (u8, u8)) -> bool {
    find_platform_wheel(release, Some(python_version)).is_ok()
}

/// Find the best matching wheel for the current platform and Python version.
///
/// Lookup order:
/// 1. `{platform}-cp{major}{minor}` — exact interpreter ABI match (e.g. `macos-arm64-cp313`)
/// 2. `{platform}` — version-agnostic fallback for older manifests or universal wheels
///
/// This allows cli-release.json to carry wheels for multiple Python versions
/// while remaining backwards compatible with launchers that only emit
/// platform-only keys.
///
/// Pass `python_version` as `Some((major, minor))` when the interpreter version is known.
/// Pass `None` only as a last resort.
pub fn find_platform_wheel(
    release: &CliRelease,
    python_version: Option<(u8, u8)>,
) -> Result<&WheelInfo, Error> {
    // An unsupported host never reaches a wheel lookup on the bootstrap path
    // (`ensure_supported_platform` refuses first), but this is the function
    // that decides what gets installed, so it re-asks rather than assuming a
    // key exists.
    let platform = current_platform()?;

    // 1. Try Python-version-specific key (e.g. "macos-arm64-cp313")
    if let Some((major, minor)) = python_version {
        let abi_key = format!("{platform}-cp{major}{minor}");
        if let Some(wheel) = release.wheels.iter().find(|w| w.platform_key == abi_key) {
            return Ok(wheel);
        }
    }

    // 2. Fall back to platform-only key for backwards compatibility
    release
        .wheels
        .iter()
        .find(|w| w.platform_key == platform)
        .ok_or_else(|| {
            let mut available: Vec<String> = release
                .wheels
                .iter()
                .map(|w| w.platform_key.clone())
                .collect();
            // Map order is arbitrary; the user is reading this list to compare
            // it against their own platform, so sort it.
            available.sort();
            Error::NoWheel {
                platform: platform.to_string(),
                // Passed through, never defaulted. `None` is reachable with the
                // error kept: `--update` calls this with whatever
                // `parse_python_version` made of the manifest's
                // `python_version`, and a corrupt value there yields `None`.
                // Flattening it to `(0, 0)` rendered "Interpreter: Python 0.0",
                // a version that has never existed (R61).
                python_version,
                feed_version: release.version.clone(),
                available,
            }
        })
}

/// Stream the response body of `url` to `dest`, computing SHA-256 on the way,
/// and verify it matches `expected_sha256` (hex, lowercase).
///
/// On mismatch the file is deleted and a `BundleVerify` error is returned so
/// callers downstream of the launcher's trust boundary can distinguish a
/// checksum failure from a generic network failure. Use this for any
/// signature-anchored artefact (capability bundles, wheels). `dest`'s parent
/// directory is created if missing.
pub fn stream_to_file_with_hash(
    url: &str,
    dest: &std::path::Path,
    expected_sha256: &str,
) -> Result<(), Error> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::PipInstall(format!("Failed to create dest dir: {e}")))?;
    }

    let mut response = http_agent(DOWNLOAD_BUDGET)?
        .get(url)
        .header("User-Agent", "huitzo-launcher")
        .call()
        .map_err(|e| {
            Error::Network(format!(
                "Failed to fetch {url}: {}",
                transport_failure(&e, DOWNLOAD_BUDGET)
            ))
        })?;

    let mut file = std::fs::File::create(dest)
        .map_err(|e| Error::PipInstall(format!("Failed to create {}: {e}", dest.display())))?;

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    let mut written: u64 = 0;
    let mut reader = response.body_mut().as_reader();

    loop {
        // The global budget covers the body too, so a transfer that stalls
        // mid-stream surfaces here rather than hanging: name the budget so the
        // message is about the bound, not about an anonymous "interrupted".
        let n = reader.read(&mut buf).map_err(|e| {
            let _ = std::fs::remove_file(dest);
            Error::Network(format!(
                "Download of {url} interrupted after {} bytes: {e}\n\
                 \x20 The whole download must finish within {}s.",
                written,
                DOWNLOAD_BUDGET.global_secs()
            ))
        })?;
        if n == 0 {
            break;
        }
        written += n as u64;
        hasher.update(&buf[..n]);
        std::io::Write::write_all(&mut file, &buf[..n])
            .map_err(|e| Error::PipInstall(format!("Failed to write file: {e}")))?;
    }

    let computed: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if !computed.eq_ignore_ascii_case(expected_sha256) {
        let _ = std::fs::remove_file(dest);
        return Err(Error::BundleVerify {
            reason: format!(
                "checksum mismatch for {}\n  expected: {}\n  got:      {}",
                dest.display(),
                expected_sha256,
                computed
            ),
        });
    }

    Ok(())
}

/// Download a wheel file from a GitHub Release, verify its SHA-256 checksum,
/// and save it to the cache directory.
///
/// The wheel URL is constructed from the release tag and filename.
pub fn download_wheel(release_version: &str, wheel: &WheelInfo) -> Result<PathBuf, Error> {
    let cache_dir = dirs::huitzo_home().join("cache");
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| Error::PipInstall(format!("Failed to create cache dir: {e}")))?;

    let dest = cache_dir.join(&wheel.filename);

    // Construct download URL from the GitHub release (hosted on public launcher repo)
    let url = format!(
        "https://github.com/Huitzo-Inc/huitzo-launcher/releases/download/cli-v{}/{}",
        release_version, wheel.filename
    );

    // Allow override for testing
    let url = if let Ok(base) = std::env::var("HUITZO_RELEASE_DOWNLOAD_URL") {
        format!("{}/{}", base.trim_end_matches('/'), wheel.filename)
    } else {
        url
    };

    eprintln!("  Downloading {}...", wheel.filename);

    // Reuse the shared streaming helper; remap BundleVerify → PipInstall here
    // so the wheel-install code path keeps its existing error contract.
    if let Err(e) = stream_to_file_with_hash(&url, &dest, &wheel.sha256) {
        return match e {
            Error::BundleVerify { reason } => Err(Error::PipInstall(format!(
                "Wheel checksum mismatch: {reason}"
            ))),
            other => Err(other),
        };
    }

    eprintln!("  Checksum verified.");
    Ok(dest)
}

/// Map a CLI tag (`cli-v0.10.1`) to the version it carries (`0.10.1`).
///
/// Returns `None` for launcher tags (`v*`) and anything else.
fn cli_tag_version(tag: &str) -> Option<&str> {
    tag.strip_prefix("cli-v")
}

/// Find the newest CLI release (`cli-v*` tag) in a releases JSON array.
///
/// Ordering, draft exclusion and prerelease handling all live in
/// [`select_newest_release`] so the launcher and the CLI agree on what
/// "newest" means.
fn find_latest_cli_release(releases: &serde_json::Value) -> Option<&serde_json::Value> {
    select_newest_release(releases, cli_tag_version)
}

/// Get the latest CLI version from GitHub Releases without downloading the wheel.
///
/// Used by the background update checker.
pub fn check_cli_release_version() -> Option<String> {
    let release = fetch_cli_release().ok()?;
    Some(release.version)
}

#[cfg(test)]
mod tests {
    use super::*;

    use httpmock::prelude::*;

    /// `HUITZO_RELEASE_URL` is process-global. CI runs `--test-threads=1`, but
    /// a bare `cargo test` does not, so serialize the tests that set it.
    static FEED_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Point `fetch_cli_release` at `url` and return the error it produces.
    /// The guard is held for the whole call so no other test sees the variable.
    fn feed_failure(url: &str) -> Error {
        let _guard = FEED_ENV.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("HUITZO_RELEASE_URL", url) };
        let result = fetch_cli_release();
        unsafe { std::env::remove_var("HUITZO_RELEASE_URL") };
        match result {
            Err(e) => e,
            Ok(r) => panic!("expected a feed failure, got release {}", r.version),
        }
    }

    fn feed_cause(url: &str) -> FeedError {
        match feed_failure(url) {
            Error::FeedUnavailable { cause, .. } => cause,
            other => panic!("expected FeedUnavailable, got: {other}"),
        }
    }

    /// The platform key for the machine running the suite. CI and every
    /// developer host is a supported platform, so a failure here is a real
    /// regression in the mapping and not a skip condition.
    fn this_platform() -> &'static str {
        current_platform().expect("the test host must resolve to a supported platform")
    }

    fn make_release(keys: &[&str]) -> CliRelease {
        CliRelease {
            version: "0.2.3".to_string(),
            min_launcher_version: "0.1.0".to_string(),
            wheels: keys
                .iter()
                .map(|k| WheelInfo {
                    platform_key: k.to_string(),
                    filename: format!("huitzo-0.2.3-{k}.whl"),
                    sha256: "abc".to_string(),
                })
                .collect(),
        }
    }

    // --- B5 / B9 / M3 / m11: the platform mapping refuses, never guesses ---

    /// Resolve a forced OS/arch/libc triple. This is criterion 3's
    /// "test exercising the mapping with a forced platform value": every
    /// branch below runs on this Linux CI host, including the Mac and Windows
    /// ones, because `resolve_platform` takes the triple as arguments.
    fn resolve(os: &str, arch: &str, musl: bool) -> Result<&'static str, Error> {
        resolve_platform(os, arch, || musl)
    }

    fn refusal(os: &str, arch: &str, musl: bool) -> (UnsupportedReason, String) {
        match resolve(os, arch, musl) {
            Err(Error::UnsupportedPlatform { reason, os, arch }) => {
                let rendered = Error::UnsupportedPlatform {
                    reason,
                    os: os.clone(),
                    arch: arch.clone(),
                }
                .to_string();
                // Captured by default; `cargo test -- --nocapture` shows each
                // refusal exactly as a user on that host would read it.
                println!("--- {os}/{arch} (musl={musl}) ---\n{rendered}\n");
                (reason, rendered)
            }
            Err(other) => panic!("expected UnsupportedPlatform, got: {other}"),
            Ok(key) => panic!("expected a refusal for {os}/{arch}, got key {key}"),
        }
    }

    #[test]
    fn current_platform_returns_valid_key() {
        let platform = this_platform();
        let valid = [
            "linux-x86_64",
            "linux-aarch64",
            "macos-arm64",
            "windows-x86_64",
        ];
        assert!(
            valid.contains(&platform),
            "Unknown platform key: {platform}"
        );
        // `macos-x86_64` is not in that list and must never be produced again:
        // no release carries the key, so it could only ever be a 404 (B5).
        assert_ne!(platform, "macos-x86_64");
    }

    #[test]
    fn supported_hosts_map_to_the_feed_keys() {
        assert_eq!(resolve("linux", "x86_64", false).unwrap(), "linux-x86_64");
        assert_eq!(resolve("linux", "aarch64", false).unwrap(), "linux-aarch64");
        assert_eq!(resolve("macos", "aarch64", false).unwrap(), "macos-arm64");
        assert_eq!(
            resolve("windows", "x86_64", false).unwrap(),
            "windows-x86_64"
        );
    }

    #[test]
    fn intel_macos_is_refused_by_name_not_handed_a_wheel() {
        let (reason, msg) = refusal("macos", "x86_64", false);
        assert_eq!(reason, UnsupportedReason::IntelMac);
        assert!(msg.contains("Apple Silicon"), "{msg}");
        assert!(msg.contains("Intel"), "{msg}");
        assert!(msg.contains("x86_64"), "{msg}");
        assert!(msg.contains("Nothing was installed"), "{msg}");
        // The bug was that it resolved a key at all.
        assert!(!msg.contains("macos-arm64-cp"), "{msg}");
    }

    #[test]
    fn a_musl_host_is_refused_with_glibc_required_and_a_named_alternative() {
        for arch in ["x86_64", "aarch64"] {
            let (reason, msg) = refusal("linux", arch, true);
            assert_eq!(reason, UnsupportedReason::Musl);
            assert!(msg.contains("musl"), "{msg}");
            assert!(msg.contains("glibc"), "{msg}");
            // D8 requires naming a glibc alternative, not just the diagnosis.
            assert!(msg.contains("debian-slim"), "{msg}");
            assert!(msg.contains("ubuntu"), "{msg}");
            assert!(msg.contains("WSL2"), "{msg}");
            assert!(msg.contains(arch), "{msg}");
        }
        // The same arch on glibc is supported — the refusal is about libc, not
        // about Linux, so a test that passed with the libc probe deleted would
        // fail right here.
        assert!(resolve("linux", "x86_64", false).is_ok());
        assert!(resolve("linux", "aarch64", false).is_ok());
    }

    #[test]
    fn windows_on_arm_is_refused_by_name() {
        let (reason, msg) = refusal("windows", "aarch64", false);
        assert_eq!(reason, UnsupportedReason::WindowsArm);
        assert!(msg.contains("Windows on ARM"), "{msg}");
        assert!(msg.contains("aarch64"), "{msg}");
    }

    #[test]
    fn an_unknown_host_errors_instead_of_claiming_linux_x86_64() {
        // M3: every one of these used to fall through the catch-all `else`
        // and ask the feed for a Linux wheel.
        for (os, arch) in [
            ("freebsd", "x86_64"),
            ("linux", "riscv64"),
            ("linux", "s390x"),
            ("macos", "powerpc64"),
            ("solaris", "sparc64"),
            ("haiku", "x86"),
        ] {
            let (reason, msg) = refusal(os, arch, false);
            assert_eq!(reason, UnsupportedReason::Unknown, "{os}/{arch}");
            assert!(msg.contains(os), "{msg}");
            assert!(msg.contains(arch), "{msg}");
            // The whole point of M3: no guessed key anywhere in the output.
            assert!(
                !msg.contains("linux-x86_64,") && !msg.contains("Detected: linux-x86_64"),
                "unknown host must not be handed a key: {msg}"
            );
        }
    }

    #[test]
    fn the_advertised_key_list_is_exactly_what_the_mapping_can_produce() {
        // `SUPPORTED_KEYS` is printed to a user who has just been refused. If
        // it drifted from the `Ok` arms it would send someone to a platform
        // the launcher would then also refuse.
        let produced: Vec<&str> = [
            ("macos", "aarch64"),
            ("linux", "x86_64"),
            ("linux", "aarch64"),
            ("windows", "x86_64"),
        ]
        .iter()
        .map(|(os, arch)| resolve(os, arch, false).unwrap())
        .collect();
        for key in &produced {
            assert!(
                SUPPORTED_KEYS.contains(key),
                "{key} is produced but not advertised: {SUPPORTED_KEYS}"
            );
        }
        // …and nothing is advertised that cannot be produced.
        for advertised in SUPPORTED_KEYS.split(", ") {
            let key = advertised.split_whitespace().next().unwrap();
            assert!(
                produced.contains(&key),
                "{key} is advertised but no host maps to it"
            );
        }
    }

    #[test]
    fn the_refusal_exit_code_is_config_not_a_retryable_outage() {
        let e = Error::UnsupportedPlatform {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            reason: UnsupportedReason::Musl,
        };
        assert_eq!(crate::errors::exit_code(&e), 78, "EX_CONFIG");
    }

    #[test]
    fn the_libc_probe_agrees_with_this_host() {
        // The launcher is built for x86_64-unknown-linux-musl, so
        // `cfg!(target_env = "musl")` is true in this very binary. The probe
        // must disagree with it on a glibc host — that inversion IS B9.
        if cfg!(target_os = "linux") {
            assert!(
                !host_is_musl() || std::path::Path::new("/etc/alpine-release").exists(),
                "glibc host classified as musl"
            );
        }
    }

    #[test]
    fn find_platform_wheel_prefers_abi_key() {
        let platform = this_platform();
        let abi_key = format!("{platform}-cp313");
        let release = make_release(&[&abi_key, platform]);

        let wheel = find_platform_wheel(&release, Some((3, 13))).unwrap();
        assert_eq!(
            wheel.platform_key, abi_key,
            "Should prefer ABI-specific key"
        );
    }

    #[test]
    fn find_platform_wheel_falls_back_to_platform_key() {
        let platform = this_platform();
        let release = make_release(&[platform]);

        let wheel = find_platform_wheel(&release, Some((3, 13))).unwrap();
        assert_eq!(wheel.platform_key, platform);
    }

    #[test]
    fn find_platform_wheel_abi_only_manifest() {
        let platform = this_platform();
        let abi_key = format!("{platform}-cp311");
        let release = make_release(&[&abi_key]);

        let wheel = find_platform_wheel(&release, Some((3, 11))).unwrap();
        assert_eq!(wheel.platform_key, abi_key);
    }

    #[test]
    fn find_platform_wheel_abi_mismatch_falls_back() {
        let platform = this_platform();
        let abi_key = format!("{platform}-cp311");
        let release = make_release(&[&abi_key, platform]);

        let wheel = find_platform_wheel(&release, Some((3, 13))).unwrap();
        assert_eq!(
            wheel.platform_key, platform,
            "cp313 miss → fall back to base key"
        );
    }

    #[test]
    fn find_platform_wheel_no_python_version_uses_platform_key() {
        let platform = this_platform();
        let release = make_release(&[platform]);

        let wheel = find_platform_wheel(&release, None).unwrap();
        assert_eq!(wheel.platform_key, platform);
    }

    #[test]
    fn find_platform_wheel_returns_error_when_no_match() {
        let release = make_release(&["linux-x86_64-cp310"]);
        let platform = this_platform();
        let abi_key = format!("{platform}-cp310");
        if release
            .wheels
            .iter()
            .all(|w| w.platform_key != platform && w.platform_key != abi_key)
        {
            assert!(find_platform_wheel(&release, Some((3, 13))).is_err());
        }
    }

    // --- #48: the newest cli-v* release, not the first one -----------------

    /// The real `/releases` page from #48: `cli-v0.9.0` sits at index 0,
    /// `cli-v0.10.1` at index 4, every entry shares one `created_at`, and all
    /// of them are prereleases.
    fn issue_48_releases() -> serde_json::Value {
        serde_json::from_str(
            r#"[
                {"tag_name": "cli-v0.9.0",  "created_at": "2026-07-20T04:26:37Z", "draft": false, "prerelease": true},
                {"tag_name": "cli-v0.8.0",  "created_at": "2026-07-20T04:26:37Z", "draft": false, "prerelease": true},
                {"tag_name": "v0.3.2",      "created_at": "2026-07-25T04:26:37Z", "draft": false, "prerelease": false},
                {"tag_name": "cli-v0.7.0",  "created_at": "2026-07-20T04:26:37Z", "draft": false, "prerelease": true},
                {"tag_name": "cli-v0.10.1", "created_at": "2026-07-20T04:26:37Z", "draft": false, "prerelease": true},
                {"tag_name": "cli-v0.10.0", "created_at": "2026-07-20T04:26:37Z", "draft": false, "prerelease": true}
            ]"#,
        )
        .unwrap()
    }

    #[test]
    fn find_latest_cli_release_picks_newest_not_first() {
        let releases = issue_48_releases();
        let release = find_latest_cli_release(&releases).unwrap();
        assert_eq!(release["tag_name"].as_str(), Some("cli-v0.10.1"));
    }

    #[test]
    fn find_latest_cli_release_keeps_prereleases() {
        // Every cli-v* release is published as a prerelease. Filtering them
        // would leave the launcher with no CLI release at all.
        let releases: serde_json::Value = serde_json::from_str(
            r#"[{"tag_name": "cli-v0.10.1", "draft": false, "prerelease": true}]"#,
        )
        .unwrap();
        assert_eq!(
            find_latest_cli_release(&releases).map(|r| r["tag_name"].as_str().unwrap()),
            Some("cli-v0.10.1")
        );
    }

    #[test]
    fn find_latest_cli_release_excludes_drafts() {
        let releases: serde_json::Value = serde_json::from_str(
            r#"[
                {"tag_name": "cli-v0.11.0", "draft": true,  "prerelease": true},
                {"tag_name": "cli-v0.10.1", "draft": false, "prerelease": true}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            find_latest_cli_release(&releases).map(|r| r["tag_name"].as_str().unwrap()),
            Some("cli-v0.10.1")
        );
    }

    #[test]
    fn find_latest_cli_release_ignores_launcher_tags() {
        let releases: serde_json::Value =
            serde_json::from_str(r#"[{"tag_name": "v9.9.9"}, {"tag_name": "cli-v0.10.1"}]"#)
                .unwrap();
        assert_eq!(
            find_latest_cli_release(&releases).map(|r| r["tag_name"].as_str().unwrap()),
            Some("cli-v0.10.1")
        );
    }

    #[test]
    fn find_latest_cli_release_skips_malformed_tags() {
        let releases: serde_json::Value = serde_json::from_str(
            r#"[
                {"tag_name": "cli-vfoo"},
                {"tag_name": "cli-v"},
                {"tag_name": "cli-v0.10.1"}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            find_latest_cli_release(&releases).map(|r| r["tag_name"].as_str().unwrap()),
            Some("cli-v0.10.1")
        );

        let all_bad: serde_json::Value =
            serde_json::from_str(r#"[{"tag_name": "cli-vfoo"}, {"tag_name": "cli-v"}]"#).unwrap();
        assert!(
            find_latest_cli_release(&all_bad).is_none(),
            "an unorderable tag must not be returned as latest"
        );
    }

    #[test]
    fn find_latest_cli_release_skips_versions_it_cannot_order() {
        // `0.11.0-rc1` truncates to [0, 11] under the lenient comparison rule,
        // which would beat 0.10.1. Selection skips it instead.
        let releases: serde_json::Value = serde_json::from_str(
            r#"[
                {"tag_name": "cli-v0.11.0-rc1"},
                {"tag_name": "cli-v0.10.1"}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            find_latest_cli_release(&releases).map(|r| r["tag_name"].as_str().unwrap()),
            Some("cli-v0.10.1")
        );
    }

    #[test]
    fn find_latest_cli_release_none_when_no_cli_tags() {
        let releases: serde_json::Value =
            serde_json::from_str(r#"[{"tag_name": "v0.3.2"}]"#).unwrap();
        assert!(find_latest_cli_release(&releases).is_none());
    }

    // --- manifest shape ---------------------------------------------------

    #[test]
    fn a_parsed_manifest_carries_min_launcher_version_for_t3() {
        // Not enforced here — T3 owns the gate — but it must survive parsing,
        // or T3 has nothing to enforce against without a second fetch.
        let m: serde_json::Value = serde_json::from_str(
            r#"{"version": "0.11.1", "min_launcher_version": "0.4.0",
                "wheels": {"linux-x86_64-cp313": {"filename": "w.whl", "sha256": "ab"}}}"#,
        )
        .unwrap();
        let release = parse_manifest(&m).unwrap();
        assert_eq!(release.version, "0.11.1");
        assert_eq!(release.min_launcher_version, "0.4.0");
        assert_eq!(release.wheels.len(), 1);

        // An older feed with no floor parses rather than failing the install.
        let no_floor: serde_json::Value =
            serde_json::from_str(r#"{"version": "0.9.0", "wheels": {}}"#).unwrap();
        assert_eq!(
            parse_manifest(&no_floor).unwrap().min_launcher_version,
            "0.1.0"
        );
    }

    #[test]
    fn a_manifest_without_version_or_wheels_is_rejected() {
        let no_version: serde_json::Value = serde_json::from_str(r#"{"wheels": {}}"#).unwrap();
        assert!(parse_manifest(&no_version).unwrap_err().contains("version"));
        let no_wheels: serde_json::Value = serde_json::from_str(r#"{"version": "0.1.0"}"#).unwrap();
        assert!(parse_manifest(&no_wheels).unwrap_err().contains("wheels"));
    }

    // --- M11: a feed that will not answer is never an install -------------

    #[test]
    fn a_rate_limited_feed_says_rate_limited_and_names_the_reset() {
        let server = MockServer::start();
        let reset = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 12 * 60;
        server.mock(|when, then| {
            when.method(GET).path("/releases");
            then.status(403)
                .header("x-ratelimit-remaining", "0")
                .header("x-ratelimit-reset", reset.to_string())
                .body("{\"message\":\"API rate limit exceeded\"}");
        });

        let cause = feed_cause(&server.url("/releases"));
        assert!(
            matches!(
                cause,
                FeedError::Forbidden {
                    status: 403,
                    remaining: Some(0),
                    ..
                }
            ),
            "403 + x-ratelimit-remaining: 0 must be classified as rate limited"
        );
        let msg = cause.to_string();
        assert!(msg.contains("rate limit"), "{msg}");
        assert!(msg.contains("in 12min"), "{msg}");
        assert!(msg.contains("GITHUB_TOKEN"), "{msg}");
    }

    #[test]
    fn a_bare_403_is_still_reported_as_a_rate_limit_not_as_a_missing_wheel() {
        // An endpoint that refuses without GitHub's headers — the shape the
        // acceptance run uses. It must NOT be confused with "no wheel here".
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/releases");
            then.status(403).body("forbidden");
        });

        let e = feed_failure(&server.url("/releases"));
        assert!(matches!(
            e,
            Error::FeedUnavailable {
                cause: FeedError::Forbidden {
                    status: 403,
                    remaining: None,
                    ..
                },
                ..
            }
        ));
        let msg = e.to_string();
        assert!(msg.contains("403"), "{msg}");
        assert!(msg.contains("rate limit"), "{msg}");
        assert!(msg.contains("nothing was installed"), "{msg}");
        assert!(!msg.contains("PyPI"), "no fallback may be offered: {msg}");
    }

    #[test]
    fn a_server_error_is_a_status_not_a_rate_limit() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/releases");
            then.status(503).body("upstream down");
        });
        assert!(matches!(
            feed_cause(&server.url("/releases")),
            FeedError::Status(503)
        ));
    }

    #[test]
    fn a_feed_that_answers_with_html_is_malformed_not_unreachable() {
        // The #B1 failure mode applied to the feed: a 200 that is not JSON.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/releases");
            then.status(200).body("<!doctype html><html></html>");
        });
        let cause = feed_cause(&server.url("/releases"));
        assert!(matches!(cause, FeedError::Malformed(_)), "{cause}");
        assert!(cause.to_string().contains("not a Huitzo release feed"));
    }

    #[test]
    fn a_feed_with_no_cli_release_is_malformed_not_an_empty_success() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/releases");
            then.status(200).body(r#"[{"tag_name": "v0.3.3"}]"#);
        });
        let cause = feed_cause(&server.url("/releases"));
        assert!(cause.to_string().contains("cli-v*"), "{cause}");
    }

    #[test]
    fn a_host_that_refuses_the_connection_is_unreachable() {
        // Port 1 on loopback: nothing listens, so the connection is refused
        // immediately rather than hanging on the 30 s timeout.
        let cause = feed_cause("http://127.0.0.1:1/releases");
        assert!(matches!(cause, FeedError::Unreachable(_)), "{cause}");
        let msg = cause.to_string();
        assert!(msg.contains("never completed"), "{msg}");
        assert!(msg.contains("proxy"), "{msg}");
    }

    // --- token handling ---------------------------------------------------

    #[test]
    fn a_github_token_is_never_sent_to_a_non_github_feed() {
        let _guard = FEED_ENV.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("GITHUB_TOKEN", "ghp_secret") };
        assert_eq!(
            github_token_for("https://api.github.com/repos/x/y/releases").as_deref(),
            Some("ghp_secret")
        );
        // HUITZO_RELEASE_URL can point anywhere; the token must not follow it.
        assert_eq!(github_token_for("https://evil.example/releases"), None);
        assert_eq!(github_token_for("http://127.0.0.1:8080/releases"), None);
        unsafe { std::env::remove_var("GITHUB_TOKEN") };
        assert_eq!(
            github_token_for("https://api.github.com/repos/x/y/releases"),
            None
        );
    }

    #[test]
    fn a_reset_in_the_past_is_not_rendered_as_a_wait() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(describe_reset(now - 5), None);
        assert_eq!(describe_reset(now + 30).as_deref(), Some("in 30s"));
        // 91 s rounds up to the next whole minute rather than down to 1.
        assert_eq!(describe_reset(now + 91).as_deref(), Some("in 2min"));
    }

    // --- B4: wheel-missing is its own, fully-populated error ---------------

    #[test]
    fn a_missing_wheel_names_the_platform_the_interpreter_and_the_feed() {
        // A feed that carries this platform, but only for other Pythons —
        // exactly the Python-3.11-only host in #B4.
        let platform = this_platform();
        let release = make_release(&[
            &format!("{platform}-cp313"),
            &format!("{platform}-cp312"),
            "windows-x86_64-cp312",
        ]);

        let e = find_platform_wheel(&release, Some((3, 11))).unwrap_err();
        let Error::NoWheel {
            platform: got_platform,
            python_version,
            feed_version,
            available,
        } = &e
        else {
            panic!("expected NoWheel, got: {e}");
        };
        assert_eq!(got_platform, platform);
        assert_eq!(*python_version, Some((3, 11)));
        assert_eq!(feed_version, "0.2.3");
        // Sorted, so a user can scan it against their own key.
        let mut sorted = available.clone();
        sorted.sort();
        assert_eq!(available, &sorted);

        let msg = e.to_string();
        assert!(msg.contains("Python 3.11"), "{msg}");
        assert!(msg.contains(&format!("{platform}-cp312")), "{msg}");
        assert!(msg.contains("cli-v0.2.3"), "{msg}");
        // The actionable half: this platform IS built, just not for 3.11.
        assert!(msg.contains("3.12"), "{msg}");
        assert!(msg.contains("3.13"), "{msg}");
        assert!(!msg.contains("PyPI"), "no fallback may be offered: {msg}");
    }

    #[test]
    fn a_platform_with_no_wheels_at_all_says_so_rather_than_blaming_the_python() {
        // A *supported* platform the feed has dropped a build for at every
        // interpreter version. (Intel macOS no longer reaches this message —
        // `Error::UnsupportedPlatform` refuses it first — so what is left here
        // is a feed regression, and it must not read as "install a different
        // Python".)
        let release = make_release(&["some-other-platform-cp312"]);
        let msg = find_platform_wheel(&release, Some((3, 13)))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("at any"), "{msg}");
        assert!(
            !msg.contains("Install one of those"),
            "must not suggest another Python when no build exists: {msg}"
        );
    }

    // --- R61: the message may not invent an interpreter --------------------

    #[test]
    fn an_unknown_interpreter_is_named_unknown_and_never_python_0_0() {
        // The state `--update` reaches when the local manifest's
        // `python_version` is corrupt: `parse_python_version` yields `None`,
        // `apply_wheel_update` passes it straight through, and this is the
        // error the user sees. It used to read "Interpreter: Python 0.0".
        let release = make_release(&["some-other-platform-cp312"]);
        let e = find_platform_wheel(&release, None).unwrap_err();

        let Error::NoWheel { python_version, .. } = &e else {
            panic!("expected NoWheel, got: {e}");
        };
        assert_eq!(*python_version, None, "the None must survive to the error");

        let msg = e.to_string();
        assert!(!msg.contains("Python 0.0"), "{msg}");
        assert!(
            !msg.contains("0.0"),
            "no invented version may appear: {msg}"
        );
        assert!(msg.contains("Interpreter:   unknown"), "{msg}");
        // The rest of the message still has to be useful.
        assert!(
            msg.contains(&format!("Platform key:  {}", this_platform())),
            "{msg}"
        );
        assert!(msg.contains("cli-v0.2.3"), "{msg}");
    }

    #[test]
    fn a_known_interpreter_is_still_named_exactly() {
        // The other half of the same change: `Some` must not be lost while
        // making `None` honest.
        let release = make_release(&["some-other-platform-cp312"]);
        let msg = find_platform_wheel(&release, Some((3, 13)))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("Interpreter:   Python 3.13"), "{msg}");
        assert!(!msg.contains("unknown"), "{msg}");
    }

    // --- M12: no request on the install/update path is unbounded ----------

    /// Vars the transport reads. Process-global, so every test that touches
    /// them takes the same lock the feed tests use.
    const TRANSPORT_VARS: &[&str] = &[
        "ALL_PROXY",
        "all_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "NO_PROXY",
        "no_proxy",
        CA_BUNDLE_ENV,
    ];

    /// Run `f` with exactly `vars` set and every other transport variable
    /// cleared, so an inherited `HTTPS_PROXY` on a developer machine cannot
    /// change what a test observes.
    fn with_transport_env<T>(vars: &[(&str, &str)], f: impl FnOnce() -> T) -> T {
        let _guard = FEED_ENV.lock().unwrap_or_else(|e| e.into_inner());
        let saved: Vec<(&str, Option<String>)> = TRANSPORT_VARS
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect();
        for (k, _) in &saved {
            unsafe { std::env::remove_var(k) };
        }
        for (k, v) in vars {
            unsafe { std::env::set_var(k, v) };
        }
        let out = f();
        for (k, _) in vars {
            unsafe { std::env::remove_var(k) };
        }
        for (k, v) in saved {
            if let Some(v) = v {
                unsafe { std::env::set_var(k, v) };
            }
        }
        out
    }

    /// A socket that completes the TCP handshake and then says nothing, ever.
    /// Returns its address; the listener thread outlives the test on purpose.
    fn blackhole() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        std::thread::spawn(move || {
            // Hold every accepted connection open without writing a byte.
            let mut held = Vec::new();
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => held.push(s),
                    Err(_) => break,
                }
            }
        });
        addr
    }

    #[test]
    fn every_request_family_carries_a_connect_and_a_global_timeout() {
        // The wiring, not the numbers: dropping any of these builder calls
        // restores the unbounded request M12 is about.
        for budget in [FEED_BUDGET, DOWNLOAD_BUDGET] {
            let agent = with_transport_env(&[], || http_agent(budget)).expect("agent");
            let timeouts = agent.config().timeouts();
            assert_eq!(timeouts.connect, Some(CONNECT_TIMEOUT), "{}", budget.what);
            assert_eq!(
                timeouts.recv_response,
                Some(RESPONSE_TIMEOUT),
                "{}",
                budget.what
            );
            assert_eq!(timeouts.global, Some(budget.global), "{}", budget.what);
        }
        // The wheel is the big artefact: its budget must be the generous one.
        assert!(DOWNLOAD_BUDGET.global > FEED_BUDGET.global);
        // …and generous enough for a ~50 MB wheel on a genuinely slow link.
        assert!(50 * 1024 * 1024 / DOWNLOAD_BUDGET.global_secs() < 64 * 1024);
    }

    #[test]
    fn a_blackholed_host_fails_on_the_budget_instead_of_hanging() {
        // Same plumbing as a real download, with the budget compressed so the
        // suite does not wait 15 minutes to prove there is one.
        let budget = Budget {
            what: "test download",
            global: std::time::Duration::from_millis(750),
        };
        let url = format!("http://{}/wheel.whl", blackhole());

        let started = std::time::Instant::now();
        let err = with_transport_env(&[], || {
            http_agent(budget)
                .expect("agent")
                .get(&url)
                .call()
                .expect_err("a blackholed host must not succeed")
        });
        let elapsed = started.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "took {elapsed:?} — the budget did not apply"
        );
        let cause = transport_failure(&err, budget).to_string();
        assert!(cause.contains("timed out"), "{cause}");
        assert!(cause.contains("test download"), "{cause}");
    }

    // --- m15: proxy and custom CA ------------------------------------------

    #[test]
    fn the_proxy_environment_is_read_and_routed_through() {
        let proxy = with_transport_env(&[("HTTPS_PROXY", "http://proxy.corp:8080")], || {
            http_agent(FEED_BUDGET)
                .expect("agent")
                .config()
                .proxy()
                .cloned()
        })
        .expect("HTTPS_PROXY must reach the agent, not just parse");
        assert_eq!(proxy.host(), "proxy.corp");
        assert_eq!(proxy.port(), 8080);
    }

    #[test]
    fn every_spelling_a_corporate_setup_hands_out_is_honoured() {
        // The forms that turn up in a corporate profile. Each must produce a
        // proxy, not a silent direct connection.
        for (value, host, port) in [
            ("http://proxy.corp:8080", "proxy.corp", 8080),
            ("https://proxy.corp:8443", "proxy.corp", 8443),
            // Scheme-less `host:port` — parsed as a URI authority.
            ("proxy.corp:8080", "proxy.corp", 8080),
            ("alice:hunter2@proxy.corp:8080", "proxy.corp", 8080),
        ] {
            let proxy = with_transport_env(&[("HTTPS_PROXY", value)], proxy_from_env)
                .unwrap_or_else(|e| panic!("{value}: {e}"))
                .unwrap_or_else(|| panic!("{value}: went direct"));
            assert_eq!(proxy.host(), host, "{value}");
            assert_eq!(proxy.port(), port, "{value}");
        }
    }

    #[test]
    fn a_proxy_variable_that_cannot_be_parsed_is_refused_not_ignored() {
        // `ureq` answers "unparseable" and "not configured" with the same
        // `None`. Treating the first as the second connects direct on a
        // machine whose only route out is the proxy — and says nothing.
        let err = with_transport_env(&[("HTTPS_PROXY", "proxy.corp:8080/")], || {
            http_agent(FEED_BUDGET).expect_err("an unusable proxy must be refused")
        });
        assert!(matches!(err, Error::ProxyConfig { .. }), "{err}");
        let msg = err.to_string();
        assert!(msg.contains("HTTPS_PROXY=proxy.corp:8080/"), "{msg}");
        assert!(msg.contains("Nothing was installed"), "{msg}");
        assert_eq!(crate::errors::exit_code(&err), 78);
    }

    #[test]
    fn an_unparseable_proxy_password_is_not_echoed_into_the_refusal() {
        let err = with_transport_env(&[("HTTPS_PROXY", "alice:hunter2@proxy.corp:8080/")], || {
            http_agent(FEED_BUDGET).expect_err("must be refused")
        });
        let msg = err.to_string();
        assert!(!msg.contains("hunter2"), "{msg}");
        assert!(msg.contains("***@proxy.corp:8080/"), "{msg}");
    }

    #[test]
    fn no_proxy_carves_out_direct_routes() {
        let proxy = with_transport_env(
            &[
                ("HTTPS_PROXY", "http://proxy.corp:8080"),
                ("NO_PROXY", "localhost,.internal.corp"),
            ],
            proxy_from_env,
        )
        .expect("a valid proxy")
        .expect("proxy");
        let bypass = |host: &str| {
            proxy.is_no_proxy(
                &format!("https://{host}/x")
                    .parse::<ureq::http::Uri>()
                    .unwrap(),
            )
        };
        assert!(bypass("localhost"));
        assert!(bypass("git.internal.corp"));
        assert!(!bypass("api.github.com"));
    }

    #[test]
    fn no_proxy_variable_at_all_means_a_direct_connection() {
        let proxy = with_transport_env(&[], proxy_from_env).expect("not an error");
        assert!(proxy.is_none(), "{proxy:?}");
        // …and an empty value is "not configured", not "unusable".
        let proxy = with_transport_env(&[("HTTPS_PROXY", "")], proxy_from_env)
            .expect("an empty value is not an error");
        assert!(proxy.is_none(), "{proxy:?}");
    }

    #[test]
    fn a_proxy_password_is_not_echoed_into_an_error_message() {
        assert_eq!(
            redact_userinfo("http://alice:hunter2@proxy.corp:8080"),
            "http://***@proxy.corp:8080"
        );
        assert_eq!(
            redact_userinfo("http://proxy.corp:8080"),
            "http://proxy.corp:8080"
        );
    }

    #[test]
    fn a_ca_bundle_replaces_the_bundled_roots() {
        // Two anchors in one file: a bundle is a chain, not a single cert.
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle = dir.path().join("corp.pem");
        std::fs::write(&bundle, two_pem_certificates()).expect("write");

        let roots = with_transport_env(
            &[(CA_BUNDLE_ENV, bundle.to_str().expect("utf-8 path"))],
            || root_certs_from_env().expect("a valid bundle must load"),
        )
        .expect("a bundle was configured, so roots must be Specific");
        match roots {
            ureq::tls::RootCerts::Specific(certs) => assert_eq!(certs.len(), 2),
            other => panic!("expected Specific roots, got {other:?}"),
        }
    }

    #[test]
    fn an_unusable_ca_bundle_is_terminal_rather_than_a_silent_fallback() {
        let dir = tempfile::tempdir().expect("tempdir");

        // A file that is not PEM at all.
        let junk = dir.path().join("not-a-cert.pem");
        std::fs::write(&junk, b"this is not a certificate\n").expect("write");
        let err = with_transport_env(
            &[(CA_BUNDLE_ENV, junk.to_str().expect("utf-8 path"))],
            || http_agent(FEED_BUDGET).expect_err("must refuse"),
        );
        assert!(matches!(err, Error::CaBundle { .. }), "{err}");
        let msg = err.to_string();
        assert!(msg.contains("HUITZO_CA_BUNDLE"), "{msg}");
        assert!(msg.contains("Nothing was installed"), "{msg}");
        // EX_CONFIG: the machine is misconfigured, this is not a retryable blip.
        assert_eq!(crate::errors::exit_code(&err), 78);

        // A path that does not exist.
        let missing = dir.path().join("absent.pem");
        let err = with_transport_env(
            &[(CA_BUNDLE_ENV, missing.to_str().expect("utf-8 path"))],
            || http_agent(FEED_BUDGET).expect_err("must refuse"),
        );
        assert!(matches!(err, Error::CaBundle { .. }), "{err}");
    }

    #[test]
    fn an_empty_ca_bundle_variable_means_the_bundled_roots() {
        // Unset and set-to-empty must behave the same; an empty string is how
        // a shell profile spells "not configured".
        for value in ["", "   "] {
            let roots = with_transport_env(&[(CA_BUNDLE_ENV, value)], || {
                root_certs_from_env().expect("empty is not an error")
            });
            assert!(roots.is_none(), "{value:?}");
        }
    }

    #[test]
    fn a_tls_failure_names_the_proxy_and_the_ca_setting() {
        let err = ureq::Error::Tls("invalid peer certificate: UnknownIssuer");
        let cause = with_transport_env(
            &[
                ("HTTPS_PROXY", "http://alice:hunter2@proxy.corp:8080"),
                (CA_BUNDLE_ENV, "/etc/corp/root.pem"),
            ],
            || transport_failure(&err, FEED_BUDGET),
        );

        assert!(matches!(cause, FeedError::Tls(_)), "{cause}");
        let msg = cause.to_string();
        assert!(msg.contains("TLS handshake failed"), "{msg}");
        // The two settings that decide whether this could ever have worked.
        assert!(
            msg.contains("HTTPS_PROXY=http://***@proxy.corp:8080"),
            "{msg}"
        );
        assert!(msg.contains("HUITZO_CA_BUNDLE=/etc/corp/root.pem"), "{msg}");
        // Credentials from the proxy URL must not be in it.
        assert!(!msg.contains("hunter2"), "{msg}");
        // And the remedy, not just the diagnosis.
        assert!(msg.contains("export HUITZO_CA_BUNDLE="), "{msg}");
    }

    #[test]
    fn a_tls_failure_with_nothing_configured_says_so_instead_of_staying_silent() {
        let err = ureq::Error::Tls("invalid peer certificate: UnknownIssuer");
        let msg = with_transport_env(&[], || transport_failure(&err, FEED_BUDGET)).to_string();
        assert!(msg.contains("none set"), "{msg}");
        assert!(msg.contains("HUITZO_CA_BUNDLE not set"), "{msg}");
    }

    #[test]
    fn a_plain_connection_failure_is_not_reported_as_a_tls_problem() {
        // Port 1 on loopback: refused immediately, nothing to do with TLS.
        // `fetch_feed` directly rather than `feed_cause`, which takes the same
        // lock `with_transport_env` is already holding.
        let cause = with_transport_env(&[], || match fetch_feed("http://127.0.0.1:1/releases") {
            Err(Error::FeedUnavailable { cause, .. }) => cause,
            other => panic!("expected FeedUnavailable, got {other:?}"),
        });
        assert!(matches!(cause, FeedError::Unreachable(_)), "{cause}");
        assert!(
            !cause.to_string().contains("TLS handshake failed"),
            "{cause}"
        );
    }

    /// Two self-signed certificates in one PEM file. Generated once and pasted
    /// in rather than built at test time: the launcher has no certificate
    /// *authoring* dependency and must not grow one to test that it can read
    /// a bundle.
    fn two_pem_certificates() -> String {
        format!("{TEST_CERT_A}\n{TEST_CERT_B}\n")
    }

    /// A throwaway self-signed root, valid to 2126. Never trusted by anything;
    /// it exists only so `root_certs_from_env` has real DER to parse.
    const TEST_CERT_A: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDLzCCAhegAwIBAgIUO6Wxt6UfRlwaiFJTVO4n0rVRnQMwDQYJKoZIhvcNAQEL\n\
BQAwJjEkMCIGA1UEAwwbSHVpdHpvIExhdW5jaGVyIFRlc3QgUm9vdCBBMCAXDTI2\n\
MDkxNjAzMDQ1OFoYDzIxMjYwODIzMDMwNDU4WjAmMSQwIgYDVQQDDBtIdWl0em8g\n\
TGF1bmNoZXIgVGVzdCBSb290IEEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n\
AoIBAQC7UmGS2vD0PW+SpakCP4mdvow7b963zwKGleh06doAeFRPQCihGyobil20\n\
P0sB/0UiHJwfJWtpbbyHX09C6QmyWJyuJeoLCmEosy/QRa/4W1qM64pchSMT3cXs\n\
jDzUOe/KnfXFa2TKqEms0bTxcu09kl56eaBPRzEbrg+vg7R7u5mLGLA2e+2xxr62\n\
E9iNyXe56MhmDyifp45/SLEIitTEUWSA3BaQJc3aDKRZdSnovregzc/J62ZIiIIH\n\
wgROliCZKmSwja6/mNIjS3MriqkoIlRjdujYXY0YXJ3FxrWFg2dwmcq8glPch5o9\n\
XxO9EKaeP+nUCpU+KIomHc2D29adAgMBAAGjUzBRMB0GA1UdDgQWBBRjD2hFZ0d6\n\
E/Q3/M6+At90j0G2oTAfBgNVHSMEGDAWgBRjD2hFZ0d6E/Q3/M6+At90j0G2oTAP\n\
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCCeoHW0tQRysZFreQd\n\
+38IAmVNrnLqTvjjv3B35JeIabFHuugh20s4bGTJE8eouRDYcGU6riqBt60BSlR0\n\
HnBKrOOKfrTQHo0lISysNQMrgr18tQCQE6MtSZcuLLHvcX/ZUwz2lvJ9Ffwveudt\n\
BKYczKBEhJ8xtMVfos6kBuTOuPU2GU4Kob96AFaBEpXlT22coxELqN5QcfEm7y3e\n\
QWHqMD+c44tyWTnQUTAYxnh1HdAZLEZ4a4eYZLu/EM7XpzkiS/oeQE9LH2V3PaO4\n\
8R/z0YXhiXWr6XI6bpJtsg+OFadVoRm2nbinFbV9VNie1Mt6MX9gFfr5QFba1iiK\n\
1Sb+\n\
-----END CERTIFICATE-----";

    /// A second throwaway root, so the bundle under test is a chain and not
    /// a single certificate.
    const TEST_CERT_B: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDLzCCAhegAwIBAgIUbDDLKOwgpdlMuPgGmBA7mW0vnN0wDQYJKoZIhvcNAQEL\n\
BQAwJjEkMCIGA1UEAwwbSHVpdHpvIExhdW5jaGVyIFRlc3QgUm9vdCBCMCAXDTI2\n\
MDkxNjAzMDQ1OFoYDzIxMjYwODIzMDMwNDU4WjAmMSQwIgYDVQQDDBtIdWl0em8g\n\
TGF1bmNoZXIgVGVzdCBSb290IEIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n\
AoIBAQCz7M7FAjlhODBfPuhNG0TZukZVWTP5p0j4wCZbfRjEyv1ypc8+bOz4wuNs\n\
rsk3mfmtDa5ErEbDmQxDbSvW5OiAvSxR4No/zDSn8ZmQUVwCNpvBVnEfZviMEpgD\n\
i6d1wIgF+fBKfD31lh2aa5DVHlH+Qjc0WBXvP3BzPUwpfo/tBEVS8l58PZmucRX8\n\
FhfJV0I5i+9mRzwaeIiIZaLJ5oBV+6YoKz/H3yjIEOqxfMkNxmC/23EdwbhpzT9B\n\
ryQpSL/L2MuT8LoJ5Trrn4TxpRVVeN3AKelv7RrKY4LtTMFdSdwTRLDmz1jL7KT1\n\
AcOnvodz2D84/2oQbJ5VUC+I5zHnAgMBAAGjUzBRMB0GA1UdDgQWBBTKvgOf5RIb\n\
SCqjzCfmrtS1Q+3j1jAfBgNVHSMEGDAWgBTKvgOf5RIbSCqjzCfmrtS1Q+3j1jAP\n\
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAyEmYUaPPxA40oLy1x\n\
1pW0P42PrxBxZljiphv90IDtw3xq5/OvfGRBP97dY/T8ravwBXwOd9CpmFbx5/vo\n\
oU4iy45XhzsYr/CzW5x90NyGhZSjVgbwS84hxUf0wBjykFV6T922fpT+JQ4AG4wV\n\
UCPUdGPPX/wQOpCE75zKjhxDQ7XKAaqn6guMTH5uMxnGMOvzXU5BhChOj2cqVLLF\n\
EHYOMakPijZ7TOf2Mcnm0f6/9NdmRc+Mp+w+OqnKpZs1+N3FOu+iTPg7vYg2w/Gs\n\
a0ZtUE7ExlbkzgBNxK28NdSYYhsZj5H4YCzMBxo6dFFcrL0Khul+oIVLnY3IDrxq\n\
hXTV\n\
-----END CERTIFICATE-----";
}
