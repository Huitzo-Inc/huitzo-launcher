# Huitzo CLI Installer — Windows (PowerShell 5.1+)
# Usage: iwr -useb https://raw.githubusercontent.com/Huitzo-Inc/huitzo-launcher/main/install.ps1 | iex
#
# Environment variables:
#   HUITZO_HOME            — override install root (default: $env:USERPROFILE\.huitzo)
#   HUITZO_NO_MODIFY_PATH  — set to 1 to skip PATH modification

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = "Stop"

$REPO  = "Huitzo-Inc/huitzo-launcher"
$ASSET = "huitzo-x86_64-pc-windows-msvc.exe"

$HuitzoHome = if ($env:HUITZO_HOME) { $env:HUITZO_HOME } else { Join-Path $env:USERPROFILE ".huitzo" }
$InstallDir = Join-Path $HuitzoHome "bin"
$BinaryPath = Join-Path $InstallDir "huitzo.exe"
$VenvDir    = Join-Path $HuitzoHome "venv"
$CacheDir   = Join-Path $HuitzoHome "cache"

function Write-Step { param($msg) Write-Host "  $msg" -ForegroundColor Cyan }
function Write-Ok   { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "  [!]  $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "Error: $msg" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "==> Installing Huitzo CLI" -ForegroundColor White

# 1. Fetch latest launcher release
Write-Step "Fetching latest release..."
try {
    $release = Invoke-RestMethod "https://api.github.com/repos/$REPO/releases/latest" -UseBasicParsing
} catch {
    Write-Fail "Could not reach GitHub API: $_"
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

# 3. Remove conflicting pip-installed huitzo
$pipCandidates = @("pip", "pip3", "py -m pip", "python -m pip", "python3 -m pip")
foreach ($pipCmd in $pipCandidates) {
    try {
        $show = & cmd /c "$pipCmd show huitzo 2>nul"
        if ($LASTEXITCODE -eq 0 -and $show) {
            Write-Step "Removing conflicting pip-installed huitzo..."
            & cmd /c "$pipCmd uninstall huitzo -y 2>nul" | Out-Null
            Write-Ok "pip-installed huitzo removed"
            break
        }
    } catch { }
}

# 4. Download launcher binary
$TmpFile = Join-Path $env:TEMP "huitzo-install-$([System.Guid]::NewGuid().ToString('N')).exe"
Write-Step "Downloading $ASSET..."
try {
    Invoke-WebRequest -Uri $assetInfo.browser_download_url -OutFile $TmpFile -UseBasicParsing
} catch {
    Write-Fail "Download failed: $_"
}

# 5. Verify SHA256 checksum
if ($sha256Info) {
    Write-Step "Verifying checksum..."
    try {
        $checksumContent = (Invoke-WebRequest -Uri $sha256Info.browser_download_url -UseBasicParsing).Content.Trim()
        $expected = ($checksumContent -split '\s+')[0].ToLower()
        $actual   = (Get-FileHash -Path $TmpFile -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne $expected) {
            Remove-Item $TmpFile -Force -ErrorAction SilentlyContinue
            Write-Fail "Checksum mismatch!`n  Expected: $expected`n  Got:      $actual"
        }
        Write-Ok "Checksum OK"
    } catch {
        Write-Warn "Could not verify checksum (non-fatal): $_"
    }
} else {
    Write-Warn "No checksum file found for this release — skipping verification."
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
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($userPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("PATH", "$InstallDir;$userPath", "User")
        $env:PATH = "$InstallDir;$env:PATH"
        Write-Ok "Added $InstallDir to your user PATH (permanent)"
        Write-Warn "Restart your terminal for the PATH change to take effect in new sessions."
    } else {
        Write-Ok "$InstallDir is already on your PATH"
    }
}

# 8. Done
Write-Host ""
Write-Host "✓ Huitzo CLI installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "  Run now:  " -NoNewline; Write-Host "huitzo --version" -ForegroundColor Yellow
Write-Host "  Login:    " -NoNewline; Write-Host "huitzo login" -ForegroundColor Yellow
Write-Host ""
Write-Host "  On first run the launcher will automatically download" -ForegroundColor DarkGray
Write-Host "  the latest CLI package for your platform." -ForegroundColor DarkGray
Write-Host ""
