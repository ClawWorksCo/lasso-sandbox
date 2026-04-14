# LASSO team onboarding script (PowerShell)
# Run this once on a new developer machine to set up LASSO with team profiles.
#
# Usage: .\scripts\onboard.ps1

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
# Handle case where script is run from within scripts/ dir
if (Test-Path (Join-Path $PSScriptRoot ".." "profiles")) {
    $ScriptDir = Resolve-Path (Join-Path $PSScriptRoot "..")
}
$LassoConfigDir = Join-Path $env:USERPROFILE ".lasso"
$LassoProfileDir = Join-Path $LassoConfigDir "profiles"

Write-Host "=== LASSO Team Onboarding ===" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python version
try {
    $pythonVersion = & python3 --version 2>&1
    Write-Host "[OK] $pythonVersion" -ForegroundColor Green
} catch {
    try {
        $pythonVersion = & python --version 2>&1
        if ($pythonVersion -match "3\.\d+") {
            Write-Host "[OK] $pythonVersion" -ForegroundColor Green
        } else {
            Write-Host "ERROR: Python 3.10+ required. Found: $pythonVersion" -ForegroundColor Red
            exit 1
        }
    } catch {
        Write-Host "ERROR: Python not found. Install Python 3.10+." -ForegroundColor Red
        exit 1
    }
}

# 2. Install lasso-sandbox
Write-Host ""
Write-Host "Installing lasso-sandbox..."
pip install --quiet lasso-sandbox==0.4.1
Write-Host "[OK] lasso-sandbox installed" -ForegroundColor Green

# 3. Create config directory
New-Item -ItemType Directory -Force -Path $LassoProfileDir | Out-Null

# 4. Copy team profiles
Write-Host ""
Write-Host "Copying team profiles..."
Copy-Item -Path (Join-Path $ScriptDir "profiles" "*.toml") -Destination $LassoProfileDir -Force
Write-Host "[OK] Profiles copied to $LassoProfileDir" -ForegroundColor Green

# 5. Copy team config (if not already present)
$configDest = Join-Path $LassoConfigDir "config.toml"
if (-not (Test-Path $configDest)) {
    Copy-Item -Path (Join-Path $ScriptDir "lasso-config.toml") -Destination $configDest
    Write-Host "[OK] Config copied to $configDest" -ForegroundColor Green
} else {
    Write-Host "[SKIP] Config already exists at $configDest" -ForegroundColor Yellow
}

# 6. Check container runtime
Write-Host ""
Write-Host "Checking container runtime..."
$dockerFound = $false
$podmanFound = $false

try {
    $dockerVersion = & docker --version 2>&1
    Write-Host "[OK] Docker found: $dockerVersion" -ForegroundColor Green
    $dockerFound = $true
} catch {}

if (-not $dockerFound) {
    try {
        $podmanVersion = & podman --version 2>&1
        Write-Host "[OK] Podman found: $podmanVersion" -ForegroundColor Green
        $podmanFound = $true
    } catch {}
}

if (-not $dockerFound -and -not $podmanFound) {
    Write-Host "WARNING: No container runtime found." -ForegroundColor Yellow
    Write-Host "         Install Docker Desktop or Podman Desktop." -ForegroundColor Yellow
    Write-Host "         See: docs\workflows\windows-setup.md" -ForegroundColor Yellow
}

# 7. Run lasso doctor
Write-Host ""
Write-Host "Running lasso check..."
try {
    & lasso check
} catch {
    Write-Host "lasso check reported issues (see above)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Onboarding complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:"
Write-Host "  lasso create team-development --dir .    # Start a development sandbox"
Write-Host "  lasso create team-strict --dir .          # Start a compliance sandbox"
Write-Host "  lasso status                              # List running sandboxes"
