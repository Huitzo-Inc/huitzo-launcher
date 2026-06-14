//! Pinned `uv` release manifest — the compiled-in trust anchor for bundling uv.
//!
//! The Studio runner builds packs with `uv` (the gates run `uv run`; the build runs
//! `uv build`). A launcher-only, non-technical user has no `uv` on their machine, so
//! the launcher BUNDLES a pinned, sha256-verified `uv` (huitzo#965 / task #38).
//!
//! TRUST MODEL: the per-platform archive sha256 is a CONSTANT baked into this launcher
//! binary at compile time. It is the trust anchor — a network MITM cannot substitute a
//! different `uv`, because the downloaded archive is verified against this constant
//! BEFORE it is ever extracted or executed (`download::stream_to_file_with_hash`). The
//! pinned version is bumped only by editing this file and cutting a new launcher
//! release (the same auditable path as any other pinned dependency).
//!
//! The asset is chosen by the launcher's OWN compile-time target triple (a musl
//! launcher fetches a musl uv, etc.) via `#[cfg]`-selected functions, so exactly one
//! `uv_asset_for_host` compiles per build (no unreachable branches, no unused consts).
//! An unsupported platform returns `None` — uv bundling is skipped and the CLI reports
//! the honest `build_tools_missing` instead.

/// The pinned uv release version. Bump in lock-step with a launcher release; the gates
/// were certified against this version (huitzo#965).
pub const PINNED_UV_VERSION: &str = "0.8.17";

/// One platform's pinned uv release archive (the GitHub asset + its sha256 trust anchor).
pub struct UvAsset {
    /// The GitHub release asset filename (the archive that contains the `uv` binary).
    pub filename: &'static str,
    /// The lowercase-hex sha256 of the ARCHIVE — verified before extraction.
    pub sha256: &'static str,
    /// True when the archive is a `.zip` (Windows); false for the `.tar.gz` (Unix).
    pub is_zip: bool,
}

impl UvAsset {
    const fn targz(filename: &'static str, sha256: &'static str) -> Self {
        Self {
            filename,
            sha256,
            is_zip: false,
        }
    }

    #[cfg(windows)]
    const fn zip(filename: &'static str, sha256: &'static str) -> Self {
        Self {
            filename,
            sha256,
            is_zip: true,
        }
    }
}

/// Resolve the pinned uv asset for THIS launcher build's target, or `None` if the
/// platform is unsupported (uv bundling is skipped; the CLI degrades honestly).
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub fn uv_asset_for_host() -> Option<UvAsset> {
    Some(UvAsset::targz(
        "uv-x86_64-unknown-linux-gnu.tar.gz",
        "920cbcaad514cc185634f6f0dcd71df5e8f4ee4456d440a22e0f8c0f142a8203",
    ))
}

#[cfg(all(target_os = "linux", target_arch = "aarch64", target_env = "gnu"))]
pub fn uv_asset_for_host() -> Option<UvAsset> {
    Some(UvAsset::targz(
        "uv-aarch64-unknown-linux-gnu.tar.gz",
        "9a20d65b110770bbaa2ee89ed76eb963d8c6a480b9ebef584ea9df2ae85b4f0f",
    ))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "musl"))]
pub fn uv_asset_for_host() -> Option<UvAsset> {
    Some(UvAsset::targz(
        "uv-x86_64-unknown-linux-musl.tar.gz",
        "4057052999a210fe78d93599d2165da9e24c8bbb23370cdd26b66a98ab479203",
    ))
}

#[cfg(all(target_os = "linux", target_arch = "aarch64", target_env = "musl"))]
pub fn uv_asset_for_host() -> Option<UvAsset> {
    Some(UvAsset::targz(
        "uv-aarch64-unknown-linux-musl.tar.gz",
        "bd141b7e263935d14f5725f2a5c1c942fd89642e37683cb904f1984ce7e365f4",
    ))
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub fn uv_asset_for_host() -> Option<UvAsset> {
    Some(UvAsset::targz(
        "uv-x86_64-apple-darwin.tar.gz",
        "31ed353cfd8e6c962e7c60617bd8a9d6b97b704c1ecb5b5eceaff8c6121b54ac",
    ))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn uv_asset_for_host() -> Option<UvAsset> {
    Some(UvAsset::targz(
        "uv-aarch64-apple-darwin.tar.gz",
        "e4d4859d7726298daa4c12e114f269ff282b2cfc2b415dc0b2ca44ae2dbd358e",
    ))
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub fn uv_asset_for_host() -> Option<UvAsset> {
    Some(UvAsset::zip(
        "uv-x86_64-pc-windows-msvc.zip",
        "0d051779fbcb173b183efeae1c3e96148764fd82709bbbf0966df3efe48b67c5",
    ))
}

/// Fallback for any platform without a pinned uv asset — uv bundling is skipped.
#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "linux", target_arch = "aarch64", target_env = "gnu"),
    all(target_os = "linux", target_arch = "x86_64", target_env = "musl"),
    all(target_os = "linux", target_arch = "aarch64", target_env = "musl"),
    all(target_os = "macos", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "windows", target_arch = "x86_64"),
)))]
pub fn uv_asset_for_host() -> Option<UvAsset> {
    None
}

/// The download URL for a uv release `filename` (Astral's GitHub release).
///
/// Overridable via `HUITZO_UV_DOWNLOAD_URL` (base URL) for tests / mirrors — the
/// sha256 trust anchor still gates whatever bytes come back, so a hostile mirror
/// cannot substitute a different binary.
pub fn uv_download_url(filename: &str) -> String {
    if let Ok(base) = std::env::var("HUITZO_UV_DOWNLOAD_URL") {
        format!("{}/{}", base.trim_end_matches('/'), filename)
    } else {
        format!(
            "https://github.com/astral-sh/uv/releases/download/{}/{}",
            PINNED_UV_VERSION, filename
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_asset_is_pinned_and_well_formed() {
        // The dev/CI host is a supported platform, so an asset must resolve.
        let asset = uv_asset_for_host().expect("a supported host must have a pinned uv asset");
        assert!(asset.filename.starts_with("uv-"));
        // The sha256 is a 64-char lowercase hex string (the trust anchor's shape).
        assert_eq!(asset.sha256.len(), 64, "sha256 must be 64 hex chars");
        assert!(asset.sha256.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn download_url_ends_with_the_asset_filename() {
        // True for BOTH the default Astral URL and an override base — env-independent
        // (edition-2024 env mutation is unsafe + racy under parallel tests).
        let url = uv_download_url("uv-x86_64-unknown-linux-gnu.tar.gz");
        assert!(url.ends_with("/uv-x86_64-unknown-linux-gnu.tar.gz"));
    }

    #[test]
    fn pinned_version_is_a_nonempty_version() {
        assert!(!PINNED_UV_VERSION.is_empty());
        assert!(PINNED_UV_VERSION.chars().next().unwrap().is_ascii_digit());
    }
}
