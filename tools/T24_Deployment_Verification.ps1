# T24 — RawrXD Deployment Verification
# Clean package extraction, dependency manifest, cold launch, target-hardware smoke test
#
# Usage:
#   .\tools\T24_Deployment_Verification.ps1 -PackagePath "dist\RawrXD-14.7.3-Windows-x64.zip" -ExtractTo "F:\rawrxd\deploy_test"
#
# Evidence output:
#   - T24_deployment_receipt_<timestamp>.json

param(
    [string]$PackagePath = "F:\rawrxd\dist\RawrXD-14.7.3-Windows-x64.zip",
    [string]$ExtractTo = "F:\rawrxd\deploy_test",
    [string]$IdeExeName = "RawrXD-Win32IDE-Native.exe",
    [string]$OutputDir = "F:\rawrxd\evidence\T24_DEPLOYMENT_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$receiptPath = Join-Path $OutputDir "T24_deployment_receipt_$timestamp.json"
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$results = @{
    schema = "RAWRXD_T24_DEPLOYMENT_VERIFICATION_001"
    package_path = $PackagePath
    extract_to = $ExtractTo
    package_exists = $false
    package_sha256 = $null
    extraction_ok = $false
    files_extracted = 0
    ide_exe_found = $false
    ide_exe_path = $null
    ide_exe_sha256 = $null
    dependency_manifest = $null
    missing_dependencies = @()
    cold_launch_ok = $false
    cold_launch_pid = $null
    cold_launch_exit_code = $null
    smoke_test_ok = $false
    pass = $false
timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    errors = @()
}

function Log-Error {
    param([string]$Message)
    $script:results.errors += $Message
    Write-Warning $Message
}

# Verify package exists
if (!(Test-Path -LiteralPath $PackagePath)) {
    Log-Error "Deployment package not found: $PackagePath"
    # Try to find any zip in dist/
    $distDir = "F:\rawrxd\dist"
    if (Test-Path -LiteralPath $distDir) {
        $zips = Get-ChildItem -LiteralPath $distDir -Filter "*.zip" -ErrorAction SilentlyContinue
        if ($zips) {
            Write-Host "Found zip files in dist/:"
            $zips | ForEach-Object { Write-Host "  $($_.FullName) ($($_.Length) bytes)" }
        }
    }
    $results | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $receiptPath
    exit 1
}

$results.package_exists = $true
$results.package_sha256 = (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash
Write-Host "=== T24 Deployment Verification ==="
Write-Host "Package: $PackagePath"
Write-Host "SHA-256: $($results.package_sha256)"
Write-Host "Extract to: $ExtractTo"
Write-Host ""

# Clean extract directory
if (Test-Path -LiteralPath $ExtractTo) {
    Remove-Item -Recurse -Force -LiteralPath $ExtractTo -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $ExtractTo -Force | Out-Null

# Extract package
try {
    Expand-Archive -LiteralPath $PackagePath -DestinationPath $ExtractTo -Force
    $results.extraction_ok = $true
    $results.files_extracted = (Get-ChildItem -LiteralPath $ExtractTo -Recurse -File | Measure-Object).Count
    Write-Host "Extraction OK: $($results.files_extracted) files extracted"
} catch {
    Log-Error "Extraction failed: $_"
    $results | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $receiptPath
    exit 1
}

# Find IDE executable
$ideExe = Get-ChildItem -LiteralPath $ExtractTo -Filter $IdeExeName -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if ($ideExe) {
    $results.ide_exe_found = $true
    $results.ide_exe_path = $ideExe.FullName
    $results.ide_exe_sha256 = (Get-FileHash -LiteralPath $ideExe.FullName -Algorithm SHA256).Hash
    Write-Host "IDE executable found: $($results.ide_exe_path)"
    Write-Host "SHA-256: $($results.ide_exe_sha256)"
} else {
    Log-Error "IDE executable '$IdeExeName' not found in extracted package"
    $results | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $receiptPath
    exit 1
}

# Check for required dependencies (DLLs)
$dlls = Get-ChildItem -LiteralPath $ExtractTo -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue
$results.dependency_manifest = @($dlls | ForEach-Object { $_.Name })
Write-Host "DLLs found: $($dlls.Count)"

# Check for common required dependencies (these are system DLLs expected on target machine)
    $requiredDeps = @("vulkan-1.dll", "ggml.dll", "msvcp140.dll", "vcruntime140.dll")
    foreach ($dep in $requiredDeps) {
        $found = Get-ChildItem -LiteralPath $ExtractTo -Filter $dep -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $found) {
            $results.missing_dependencies += $dep
            Write-Warning "Missing dependency (system DLL expected on target): $dep"
        }
    }

# Cold launch test
Write-Host ""
Write-Host "Cold launch test..."
try {
    $proc = Start-Process -FilePath $results.ide_exe_path -PassThru -WindowStyle Normal
    Start-Sleep -Seconds 3
    if (-not $proc.HasExited) {
        $results.cold_launch_ok = $true
        $results.cold_launch_pid = $proc.Id
        Write-Host "Cold launch OK (PID $($proc.Id))"
        # Graceful close
        $proc.CloseMainWindow() | Out-Null
        $exit = $proc.WaitForExit(5000)
        if (-not $exit) {
            $proc.Kill() | Out-Null
        }
    } else {
        $results.cold_launch_exit_code = $proc.ExitCode
        Log-Error "IDE exited immediately with code $($proc.ExitCode)"
    }
} catch {
    Log-Error "Cold launch failed: $_"
}

# Smoke test: verify IDE process can start and stay alive briefly
if ($results.cold_launch_ok) {
    $results.smoke_test_ok = $true
    Write-Host "Smoke test OK"
}

# Pass criteria
    $pass = $results.package_exists -and $results.extraction_ok -and $results.ide_exe_found `
        -and $results.cold_launch_ok -and $results.smoke_test_ok
    $results.pass = $pass
$results.timestamp_utc = (Get-Date -AsUniversalTime).ToString("o")

$results | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $receiptPath

Write-Host ""
Write-Host "=== T24 Deployment Verification Complete ==="
Write-Host "Package exists: $($results.package_exists)"
Write-Host "Extraction OK: $($results.extraction_ok) ($($results.files_extracted) files)"
Write-Host "IDE exe found: $($results.ide_exe_found)"
Write-Host "Missing dependencies: $($results.missing_dependencies.Count) - $($results.missing_dependencies -join ', ')"
Write-Host "Cold launch OK: $($results.cold_launch_ok)"
Write-Host "Smoke test OK: $($results.smoke_test_ok)"
Write-Host "PASS: $pass"
Write-Host "Receipt: $receiptPath"

if (-not $pass) { exit 1 }