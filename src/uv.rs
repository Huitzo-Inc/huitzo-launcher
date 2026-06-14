//! Bundle the pinned `uv` build tool for the Studio runner (huitzo#965 / task #38).
//!
//! A launcher-only, non-technical user has no `uv`. The runner needs it to build a pack
//! (the VALIDATE-stage gates run `uv run`; the BUILD stage runs `uv build`). This module
//! stages a pinned, sha256-verified `uv` at `<huitzo_home>/bin/uv` and is idempotent
//! across launches.
//!
//! SECURITY (Security-PRIMARY review surface): the archive is verified against the
//! compiled-in sha256 (`uv_manifest`, the trust anchor) BEFORE it is extracted or made
//! executable. A checksum mismatch fails closed (the archive is removed, nothing is
//! staged). Only the entry named exactly `uv` (`uv.exe` on Windows) is extracted, and
//! its bytes are streamed to a launcher-controlled destination path — the archive's own
//! internal paths never decide where anything lands (no path traversal).
//!
//! NON-FATAL: a failure here never bricks the launcher. The caller logs a warning and
//! continues; a runner without uv reports the honest `build_tools_missing` in Studio.

use std::fs::File;
use std::path::Path;

use crate::dirs;
use crate::download;
use crate::errors::Error;
use crate::uv_manifest::{PINNED_UV_VERSION, uv_asset_for_host, uv_download_url};

/// Ensure the pinned `uv` is staged at `<huitzo_home>/bin/uv` (idempotent).
///
/// Returns `Ok(())` without doing anything when uv is already current OR the platform is
/// unsupported (no pinned asset). Otherwise downloads + verifies + extracts + stages it.
pub fn ensure_uv() -> Result<(), Error> {
    let asset = match uv_asset_for_host() {
        Some(asset) => asset,
        // Unsupported platform: skip silently — the CLI reports build_tools_missing.
        None => return Ok(()),
    };

    let dest = dirs::uv_bin();
    if staged_uv_is_current(&dest) {
        return Ok(());
    }

    eprintln!("  Setting up uv {PINNED_UV_VERSION} (Studio build tool)...");
    let archive = dirs::huitzo_home().join("cache").join(asset.filename);

    // 1. Download + VERIFY the archive against the compiled-in sha256 (trust anchor).
    //    On mismatch this fails closed and removes the file.
    download::stream_to_file_with_hash(&uv_download_url(asset.filename), &archive, asset.sha256)?;

    // 2. Extract + publish the `uv` binary ATOMICALLY (extract to a temp path → chmod →
    //    rename into place). The rename REPLACES any pre-existing file or symlink at
    //    `dest` rather than writing THROUGH it, so a planted symlink can't redirect the
    //    write, and `dest` is never observed as a truncated binary (the publish is
    //    all-or-nothing). On any failure nothing is staged.
    let staged = stage_uv_atomically(&archive, asset.is_zip, &dest);
    // The verified archive is a cache artifact; remove it regardless of outcome.
    let _ = std::fs::remove_file(&archive);
    staged?;

    // 3. Stamp the staged version so the next launch short-circuits (idempotency).
    let _ = std::fs::write(dirs::uv_version_stamp(), PINNED_UV_VERSION);
    eprintln!("  uv {PINNED_UV_VERSION} ready.");
    Ok(())
}

/// True iff a staged uv is a REGULAR FILE (not a symlink) AND its version stamp matches.
///
/// The symlink check (`symlink_metadata`, which does NOT follow links) means the fast
/// path never trusts a symlink swapped in at `dest` — a non-regular `dest` forces a
/// re-stage, which atomically replaces it. (The residual at-rest risk — an attacker who
/// can write BOTH a malicious real `bin/uv` AND a matching stamp — is equivalent to
/// tampering with the launcher binary itself, which lives in the SAME `$HUITZO_HOME/bin`;
/// `$HUITZO_HOME` integrity is a threat-model assumption, not something a launcher can
/// out-verify of its own managed tree.)
fn staged_uv_is_current(dest: &Path) -> bool {
    match std::fs::symlink_metadata(dest) {
        Ok(md) if md.file_type().is_file() => {}
        _ => return false,
    }
    match std::fs::read_to_string(dirs::uv_version_stamp()) {
        Ok(stamp) => stamp.trim() == PINNED_UV_VERSION,
        Err(_) => false,
    }
}

/// Extract the `uv` binary, make it executable, and publish it to `dest` ATOMICALLY.
///
/// Extracts to a unique temp path in the SAME directory (so the final `rename` is atomic
/// — same filesystem), chmods the temp, then renames it over `dest`. The temp is removed
/// on any failure. The unique name + same-dir guarantee a planted symlink at `dest` is
/// replaced (not followed) and `dest` never appears half-written.
fn stage_uv_atomically(archive: &Path, is_zip: bool, dest: &Path) -> Result<(), Error> {
    let parent = dest.parent().ok_or_else(|| Error::BundleVerify {
        reason: "uv dest has no parent dir".to_string(),
    })?;
    std::fs::create_dir_all(parent).map_err(|e| Error::BundleVerify {
        reason: format!("failed to create uv bin dir: {e}"),
    })?;
    // A unique, same-dir temp name (PID-scoped — not random, so resume-safe).
    let tmp = parent.join(format!(".uv.staging.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp); // never write through a stale temp / symlink.

    let result = (|| {
        extract_uv(archive, is_zip, &tmp)?;
        make_executable(&tmp)?;
        std::fs::rename(&tmp, dest).map_err(|e| Error::BundleVerify {
            reason: format!("failed to publish uv binary: {e}"),
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Extract the `uv` binary from a verified archive into `dest`.
fn extract_uv(archive: &Path, is_zip: bool, dest: &Path) -> Result<(), Error> {
    if is_zip {
        extract_uv_from_zip(archive, dest)
    } else {
        extract_uv_from_targz(archive, dest)
    }
}

/// Stream the archive entry named exactly `uv` from a `.tar.gz` into `dest`.
fn extract_uv_from_targz(archive: &Path, dest: &Path) -> Result<(), Error> {
    let file = File::open(archive).map_err(|e| Error::BundleVerify {
        reason: format!("failed to open uv archive: {e}"),
    })?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut tar = tar::Archive::new(decoder);
    let entries = tar.entries().map_err(|e| Error::BundleVerify {
        reason: format!("uv tar read failed: {e}"),
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|e| Error::BundleVerify {
            reason: format!("uv tar entry read failed: {e}"),
        })?;
        let path = entry.path().map_err(|e| Error::BundleVerify {
            reason: format!("uv tar entry has invalid path: {e}"),
        })?;
        // Match the binary by its FILE NAME only — its archive directory never decides
        // the destination (we stream the bytes to our own `dest`, no path traversal).
        if path.file_name() == Some(std::ffi::OsStr::new("uv")) {
            return write_entry(&mut entry, dest);
        }
    }
    Err(Error::BundleVerify {
        reason: "uv binary not found in archive".to_string(),
    })
}

/// Stream the `uv.exe` entry from a `.zip` into `dest` (Windows).
#[cfg(windows)]
fn extract_uv_from_zip(archive: &Path, dest: &Path) -> Result<(), Error> {
    let file = File::open(archive).map_err(|e| Error::BundleVerify {
        reason: format!("failed to open uv archive: {e}"),
    })?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| Error::BundleVerify {
        reason: format!("uv zip read failed: {e}"),
    })?;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| Error::BundleVerify {
            reason: format!("uv zip entry read failed: {e}"),
        })?;
        if entry.name().rsplit(['/', '\\']).next() == Some("uv.exe") {
            return write_entry(&mut entry, dest);
        }
    }
    Err(Error::BundleVerify {
        reason: "uv.exe not found in archive".to_string(),
    })
}

/// Non-Windows stub: a `.zip` uv archive is never selected off Windows, so this is
/// unreachable at runtime — it exists only so `extract_uv` compiles on every platform.
#[cfg(not(windows))]
fn extract_uv_from_zip(_archive: &Path, _dest: &Path) -> Result<(), Error> {
    Err(Error::BundleVerify {
        reason: "zip uv archive on a non-Windows host (unexpected)".to_string(),
    })
}

/// Stream a reader's bytes into `dest`, truncating any prior file.
fn write_entry<R: std::io::Read>(reader: &mut R, dest: &Path) -> Result<(), Error> {
    let mut out = File::create(dest).map_err(|e| Error::BundleVerify {
        reason: format!("failed to create uv binary: {e}"),
    })?;
    std::io::copy(reader, &mut out).map_err(|e| Error::BundleVerify {
        reason: format!("failed to write uv binary: {e}"),
    })?;
    Ok(())
}

/// Mark `dest` user/group/other-executable (0755). No-op on non-Unix.
#[cfg(unix)]
fn make_executable(dest: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(dest)
        .map_err(|e| Error::BundleVerify {
            reason: format!("failed to stat staged uv: {e}"),
        })?
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(dest, perms).map_err(|e| Error::BundleVerify {
        reason: format!("failed to chmod staged uv: {e}"),
    })
}

#[cfg(not(unix))]
fn make_executable(_dest: &Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A `.tar.gz` whose `uv-fake/uv` entry holds known bytes — extraction streams that
    /// entry's CONTENT to dest, ignoring the archive's internal directory.
    fn make_targz_with_uv(body: &[u8]) -> Vec<u8> {
        let mut tar_builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, "uv-fake/uv", body)
            .unwrap();
        // Also a sibling entry that must be ignored (only `uv` is extracted).
        let mut h2 = tar::Header::new_gnu();
        let uvx = b"not-the-uv-binary";
        h2.set_size(uvx.len() as u64);
        h2.set_mode(0o755);
        h2.set_cksum();
        tar_builder
            .append_data(&mut h2, "uv-fake/uvx", &uvx[..])
            .unwrap();
        let tar_bytes = tar_builder.into_inner().unwrap();

        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn staging_streams_only_the_uv_entry_into_place() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("uv.tar.gz");
        std::fs::write(&archive, make_targz_with_uv(b"REAL-UV-BINARY")).unwrap();
        let dest = tmp.path().join("bin").join("uv"); // parent does not exist yet.

        stage_uv_atomically(&archive, false, &dest).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"REAL-UV-BINARY");
        // No staging temp left behind in the bin dir.
        let leftovers: Vec<_> = std::fs::read_dir(dest.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".uv.staging"))
            .collect();
        assert!(leftovers.is_empty(), "staging temp not cleaned up");
    }

    #[test]
    fn staging_without_uv_entry_fails_closed_and_leaves_no_dest() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("empty.tar.gz");
        // A gzip-tar with NO `uv` entry.
        let tar_builder = tar::Builder::new(Vec::new());
        let tar_bytes = tar_builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar_bytes).unwrap();
        std::fs::write(&archive, gz.finish().unwrap()).unwrap();
        let dest = tmp.path().join("bin").join("uv");

        let err = stage_uv_atomically(&archive, false, &dest).unwrap_err();
        assert!(matches!(err, Error::BundleVerify { .. }));
        assert!(!dest.exists());
    }

    #[cfg(unix)]
    #[test]
    fn staging_replaces_a_planted_symlink_instead_of_writing_through_it() {
        // Security: a planted symlink at `dest` must be REPLACED by the atomic rename,
        // never followed (which would corrupt the symlink's target).
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("uv.tar.gz");
        std::fs::write(&archive, make_targz_with_uv(b"REAL-UV-BINARY")).unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let dest = bin.join("uv");
        // A victim file the symlink points at — it must remain untouched.
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, b"DO-NOT-OVERWRITE").unwrap();
        std::os::unix::fs::symlink(&victim, &dest).unwrap();

        stage_uv_atomically(&archive, false, &dest).unwrap();

        // dest is now a REGULAR FILE with the real uv bytes (the symlink was replaced)...
        assert!(
            std::fs::symlink_metadata(&dest)
                .unwrap()
                .file_type()
                .is_file()
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"REAL-UV-BINARY");
        // ...and the symlink's former target was NOT written through.
        assert_eq!(std::fs::read(&victim).unwrap(), b"DO-NOT-OVERWRITE");
    }

    #[cfg(unix)]
    #[test]
    fn make_executable_sets_the_exec_bit() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("uv");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        make_executable(&f).unwrap();
        let mode = std::fs::metadata(&f).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111, "all exec bits set");
    }

    /// REAL end-to-end against Astral's pinned release (network). `#[ignore]`d so CI's
    /// default `cargo test` skips it; run with `cargo test -- --ignored ensure_uv_stages`.
    /// Proves download → sha256-verify → extract → chmod → run → idempotent re-run.
    #[test]
    #[ignore = "network: downloads the real pinned uv from Astral"]
    fn ensure_uv_stages_a_runnable_real_binary() {
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: an ignored test, run alone; no other thread reads HUITZO_HOME here.
        unsafe { std::env::set_var("HUITZO_HOME", tmp.path()) };

        ensure_uv().expect("ensure_uv should stage the pinned uv");
        let uv = dirs::uv_bin();
        assert!(uv.exists(), "uv staged at {}", uv.display());

        let out = std::process::Command::new(&uv)
            .arg("--version")
            .output()
            .expect("staged uv should run");
        assert!(out.status.success());
        let ver = String::from_utf8_lossy(&out.stdout);
        assert!(ver.contains(PINNED_UV_VERSION), "version was {ver:?}");

        // Idempotent: the second call short-circuits and leaves uv in place.
        ensure_uv().expect("idempotent re-run");
        assert!(uv.exists());

        unsafe { std::env::remove_var("HUITZO_HOME") };
    }
}
