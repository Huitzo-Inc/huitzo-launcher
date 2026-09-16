# Copyright (c) 2026 Huitzo Inc. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

# Huitzo CLI Installer -- Windows (PowerShell 5.1+)
# Usage: iwr -useb https://raw.githubusercontent.com/Huitzo-Inc/huitzo-launcher/main/install.ps1 | iex
#
# IMPORTANT: Native Windows (non-WSL) is NOT yet officially supported for the
# Huitzo Studio runner. The OFFICIAL one-command bootstrap targets macOS,
# Linux, and WSL2 via install.sh. This script remains for advanced users who
# want the launcher binary on native Windows, but you should prefer WSL2:
#   wsl --install -d Ubuntu
#   # then, inside Ubuntu:
#   curl -sSf https://raw.githubusercontent.com/Huitzo-Inc/huitzo-launcher/main/install.sh | sh
# See docs/SUPPORT_MATRIX.md for the honest support matrix and rationale.
#
# THIS FILE IS ASCII-ONLY, ON PURPOSE. The default Windows PowerShell 5.1
# console is code page 437: the em dash and check mark this script used to print
# came out as "?", so the success banner literally read "??? Huitzo CLI installed
# successfully!". Use "--" and "[OK]" instead. The file also carries no BOM, so
# `iwr -useb ... | iex` gets a clean string. Keep both properties when editing.
#
# Environment variables:
#   HUITZO_HOME            - override install root (default: $env:USERPROFILE\.huitzo)
#   HUITZO_NO_MODIFY_PATH  - set to 1 to skip PATH modification
#   HUITZO_ASSUME_YES      - set to 1 to grant install consent non-interactively

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = "Stop"

$REPO  = "Huitzo-Inc/huitzo-launcher"
$ASSET = "huitzo-x86_64-pc-windows-msvc.exe"

# Captured before defaulting: an alternate install root means a sandboxed or
# side-by-side install, which has no business inspecting or mutating the
# machine-wide Python environment.
$HuitzoHomeIsOverride = [bool]$env:HUITZO_HOME

$HuitzoHome = if ($env:HUITZO_HOME) { $env:HUITZO_HOME } else { Join-Path $env:USERPROFILE ".huitzo" }
$InstallDir = Join-Path $HuitzoHome "bin"
$BinaryPath = Join-Path $InstallDir "huitzo.exe"
$VenvDir    = Join-Path $HuitzoHome "venv"
$CacheDir   = Join-Path $HuitzoHome "cache"

function Write-Step { param($msg) Write-Host "  $msg" -ForegroundColor Cyan }
function Write-Ok   { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "  [!]  $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "Error: $msg" -ForegroundColor Red; exit 1 }

# Pick the newest LAUNCHER release from a /releases listing.
#
# /releases/latest returns the most recently *published* release, and this repo
# publishes CLI releases (tag "cli-v*") into the same repository. That only
# happens to work today because CLI releases are flagged prerelease; the day one
# ships as a full release, every Windows install would try to download launcher
# assets from a CLI tag. install.sh has always filtered on the tag name, so this
# does the same: the first tag shaped like v<digit>, which excludes "cli-v*".
function Select-LauncherRelease {
    param($Releases)
    foreach ($release in @($Releases)) {
        if ([string]$release.tag_name -match '^v[0-9]') {
            return $release
        }
    }
    return $null
}

# Prepend $Dir to the *user* PATH without damaging it.
#
# [Environment]::SetEnvironmentVariable("PATH", ..., "User") writes
# HKCU\Environment\Path back as REG_SZ even when it is REG_EXPAND_SZ, which
# freezes entries like %JAVA_HOME%\bin at whatever they expand to today. So we
# write through the registry, preserve the existing value kind, and read the
# current value UNEXPANDED so no %VAR% is ever baked in. When the entry is
# already present we do not write at all.
function Add-ToUserPath {
    param([string]$Dir)

    # The binary is already installed by the time we get here, so a PATH problem
    # is a warning with a manual fallback, never a failed install.
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Environment", $true)
    if (-not $key) {
        Write-Warn "Could not open HKCU\Environment for writing - PATH left unchanged."
        Write-Warn "Add this to your PATH manually: $Dir"
        return
    }
    try {
        $hasPath = @($key.GetValueNames()) -contains "Path"
        $raw  = ""
        $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
        if ($hasPath) {
            $raw  = [string]$key.GetValue("Path", "", [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $kind = $key.GetValueKind("Path")
        }

        if ($kind -ne [Microsoft.Win32.RegistryValueKind]::ExpandString -and
            $kind -ne [Microsoft.Win32.RegistryValueKind]::String) {
            # Anything else (REG_MULTI_SZ, REG_BINARY, ...) is not something we
            # can round-trip safely. Refuse rather than rewrite it.
            Write-Warn "User PATH has unexpected registry type '$kind' - not modifying it."
            Write-Warn "Add this to your PATH manually: $Dir"
            return
        }

        $wanted = $Dir.TrimEnd('\')
        foreach ($segment in ($raw -split ';')) {
            if ($segment.Trim().TrimEnd('\') -eq $wanted) {
                Write-Ok "$Dir is already on your user PATH (left untouched)"
                return
            }
        }

        $newPath = if ($raw -eq "") { $Dir } else { "$Dir;$raw" }
        $key.SetValue("Path", $newPath, $kind)
        Write-Ok "Added $Dir to your user PATH (permanent, kind preserved: $kind)"
        Write-Warn "Restart your terminal for the PATH change to take effect in new sessions."
    } finally {
        $key.Dispose()
    }

    # SetEnvironmentVariable broadcasts WM_SETTINGCHANGE for us; a raw registry
    # write does not, so processes that inherit their environment from Explorer
    # would not see the new PATH until the next sign-in. Best effort only: the
    # stored value is already correct if this fails.
    try {
        if (-not ("Huitzo.NativeMethods" -as [type])) {
            Add-Type -Namespace Huitzo -Name NativeMethods -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
public static extern System.IntPtr SendMessageTimeout(System.IntPtr hWnd, uint Msg, System.UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out System.UIntPtr lpdwResult);
'@
        }
        $result = [System.UIntPtr]::Zero
        [void][Huitzo.NativeMethods]::SendMessageTimeout(
            [System.IntPtr]0xffff, 0x1A, [System.UIntPtr]::Zero, "Environment", 0x0002, 5000, [ref]$result)
    } catch {
        Write-Warn "Could not broadcast the environment change; sign out and back in if new windows do not see it."
    }
}

Write-Host ""
Write-Host "==> Installing Huitzo CLI" -ForegroundColor White

# --- Honest support matrix: CLI runs natively; Studio runner requires WSL2 ---
Write-Step "Native Windows: the Huitzo CLI installs and runs here."
Write-Step "The Studio runner requires WSL2 (Ubuntu) -- if you plan to pair a"
Write-Step "local runner, use WSL2 + install.sh. See docs/SUPPORT_MATRIX.md."

# --- Logged informed consent before any third-party install/exec (S29) ---
Write-Host ""
Write-Host "  Huitzo is about to download and install the Huitzo launcher + CLI." -ForegroundColor White
Write-Host "  This installs/executes third-party software. Nothing is uploaded." -ForegroundColor White
if ($env:HUITZO_ASSUME_YES -eq "1") {
    Write-Step "HUITZO_ASSUME_YES=1 - proceeding with recorded consent."
} else {
    $answer = Read-Host "  Proceed? [y/N]"
    if ($answer -notmatch '^(y|yes)$') {
        Write-Host "  Declined. Nothing was installed." -ForegroundColor Yellow
        exit 1
    }
}
# Signal that up-front consent was already obtained. On this path the
# launcher records the GRANT to its local, metadata-only consent ledger
# (~/.huitzo/consent.jsonl) on first run - no install without an audit trail.
# We do NOT blanket-set HUITZO_ASSUME_YES: this consent covers only the
# bootstrap install, and the BOOTSTRAP_CONSENTED path proceeds + records on
# its own without needing the non-interactive override.
$env:HUITZO_BOOTSTRAP_CONSENTED = "1"

# 1. Fetch latest launcher release
Write-Step "Fetching latest release..."
try {
    $releases = Invoke-RestMethod "https://api.github.com/repos/$REPO/releases?per_page=20" -UseBasicParsing
} catch {
    Write-Fail "Could not reach GitHub API: $_"
}

$release = Select-LauncherRelease $releases
if (-not $release) {
    Write-Fail "No launcher release found. Check: https://github.com/$REPO/releases"
}

$assetInfo   = $release.assets | Where-Object { $_.name -eq $ASSET } | Select-Object -First 1
$sha256Info  = $release.assets | Where-Object { $_.name -eq "$ASSET.sha256" } | Select-Object -First 1

if (-not $assetInfo) {
    Write-Fail "Asset '$ASSET' not found in release $($release.tag_name). Check: https://github.com/$REPO/releases"
}
Write-Step "Version: $($release.tag_name)"

# 2. Clean old venv and cache (force fresh CLI install)
if (Test-Path $VenvDir) {
    Write-Step "Removing old launcher venv at $VenvDir..."
    Remove-Item -Recurse -Force $VenvDir
    Write-Ok "Old venv removed"
}
if (Test-Path $CacheDir) {
    Write-Step "Clearing wheel cache at $CacheDir..."
    Remove-Item -Recurse -Force $CacheDir
    Write-Ok "Cache cleared"
}

# 3. REPORT a conflicting pip-installed huitzo.
#
# We do not uninstall it: the user's global Python is not ours to mutate during a
# bootstrap. The probe also runs natively instead of through `cmd /c` - cmd.exe
# cannot have a UNC working directory, so the old five-candidate loop printed
# five "CMD.EXE ... UNC paths are not supported" warnings mid-install whenever
# the installer was started from a UNC/WSL path.
if (-not $HuitzoHomeIsOverride) {
    $pipProbes = @(
        @{ Exe = "pip";     Args = @() },
        @{ Exe = "pip3";    Args = @() },
        @{ Exe = "py";      Args = @("-m", "pip") },
        @{ Exe = "python";  Args = @("-m", "pip") },
        @{ Exe = "python3"; Args = @("-m", "pip") }
    )
    # A native command writing to stderr throws under "Stop"; this probe is
    # advisory, so it must never abort the install.
    $previousEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        foreach ($probe in $pipProbes) {
            $cmd = Get-Command $probe.Exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $cmd) { continue }

            $global:LASTEXITCODE = 0
            $output = $null
            try {
                $output = & $cmd.Source @($probe.Args + @("show", "huitzo")) 2>&1
            } catch {
                continue
            }

            if ($LASTEXITCODE -eq 0 -and $output) {
                $invocation = (@($probe.Exe) + $probe.Args) -join ' '
                Write-Warn "A pip-installed 'huitzo' exists in $($cmd.Source)'s environment."
                Write-Warn "It may shadow $BinaryPath on your PATH. Remove it with:"
                Write-Warn "  $invocation uninstall huitzo"
                break
            }
            if ($LASTEXITCODE -eq 1) {
                # pip ran and reported the package is absent. Nothing to report,
                # and no point asking a second interpreter about the same thing.
                break
            }
            # Anything else (e.g. exit 9009 from the Microsoft Store python.exe
            # stub) means this candidate is not a usable pip: try the next one.
        }
    } finally {
        $ErrorActionPreference = $previousEap
        $global:LASTEXITCODE = 0
    }
}

# 4. Download launcher binary
$TmpFile = Join-Path $env:TEMP "huitzo-install-$([System.Guid]::NewGuid().ToString('N')).exe"
Write-Step "Downloading $ASSET..."
try {
    Invoke-WebRequest -Uri $assetInfo.browser_download_url -OutFile $TmpFile -UseBasicParsing
} catch {
    Write-Fail "Download failed: $_"
}

# 5. Verify SHA256 checksum. There is no path past this block that installs an
#    unverified binary: no checksum asset, an unreadable checksum, or a mismatch
#    all abort. "Skipping verification" is not a thing an installer gets to do.
if (-not $sha256Info) {
    Remove-Item $TmpFile -Force -ErrorAction SilentlyContinue
    Write-Fail "Release $($release.tag_name) publishes no '$ASSET.sha256' - refusing to install an unverified binary."
}
Write-Step "Verifying checksum..."
try {
    # Invoke-RestMethod returns a decoded String on both Windows PowerShell 5.1
    # and PowerShell 7. (Invoke-WebRequest's .Content is a Byte[] on 5.1, so .Trim()
    # would throw there - which previously got downgraded to a warning and SKIPPED
    # verification, installing an UNVERIFIED binary.) The [string] cast keeps the
    # normal string case a no-op while forcing any unexpected non-string into a
    # (fatal) mismatch/verification failure below rather than a silent skip.
    $checksumContent = ([string](Invoke-RestMethod -Uri $sha256Info.browser_download_url -UseBasicParsing)).Trim()
    $expected = ($checksumContent -split '\s+')[0].ToLower()
    if ($expected -notmatch '^[0-9a-f]{64}$') {
        throw "published checksum is not a SHA-256 digest: '$checksumContent'"
    }
    $actual   = (Get-FileHash -Path $TmpFile -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected) {
        Remove-Item $TmpFile -Force -ErrorAction SilentlyContinue
        Write-Fail "Checksum mismatch!`n  Expected: $expected`n  Got:      $actual"
    }
    Write-Ok "Checksum OK"
} catch {
    # A failure to FETCH or PARSE the checksum must NOT silently proceed: refuse
    # to install an unverified binary (#39). This is fatal.
    Remove-Item $TmpFile -Force -ErrorAction SilentlyContinue
    Write-Fail "Checksum verification failed - refusing to install unverified binary: $_"
}

# 6. Install binary
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force $InstallDir | Out-Null
}
if (Test-Path $BinaryPath) {
    Write-Step "Replacing existing launcher binary..."
    Remove-Item $BinaryPath -Force
}
Move-Item $TmpFile $BinaryPath
Write-Ok "Installed -> $BinaryPath"

# 7. Add to user PATH (permanent)
if ($env:HUITZO_NO_MODIFY_PATH -ne "1") {
    Add-ToUserPath $InstallDir
    if (-not (($env:PATH -split ';') -contains $InstallDir)) {
        $env:PATH = "$InstallDir;$env:PATH"
    }
}

# 8. Capability check (in-launcher prober) - one command finishes by telling
#    the user what is present and what is still missing.
Write-Host ""
Write-Host "==> Checking local capabilities" -ForegroundColor White
try {
    & $BinaryPath --launcher-detect --human
} catch {
    Write-Warn "Capability check could not run: $_"
}
# The capability probe is informational only, but it exits non-zero on native
# Windows / when an optional tool (e.g. claude) is missing. Left as-is it would
# leak into the script's exit code (#40) - as would any residual $LASTEXITCODE
# from the earlier best-effort pip probe. Reset before the success banner.
$LASTEXITCODE = 0

# 9. Done
Write-Host ""
Write-Host "[OK] Huitzo CLI installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "  Run now:  " -NoNewline; Write-Host "huitzo --version" -ForegroundColor Yellow
Write-Host "  Login:    " -NoNewline; Write-Host "huitzo login" -ForegroundColor Yellow
Write-Host ""
Write-Host "  On first run the launcher will automatically download" -ForegroundColor DarkGray
Write-Host "  the latest CLI package for your platform." -ForegroundColor DarkGray
Write-Host ""

# End the success path with an explicit success code so a non-zero $LASTEXITCODE
# from the informational capability probe (or any earlier best-effort external
# call) can never mask a successful install (#40).
exit 0
