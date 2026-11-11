# verify_release.ps1
# Phase F.1 Batch 3/5: Release verification and validation

param(
    [Parameter(Mandatory=$true)]
    [string]$ReleaseDir,
    
    [string]$ExpectedVersion,
    [switch]$VerifySignatures,
    [switch]$VerifyChecksums,
    [switch]$TestInstallation,
    [switch]$GenerateReport,
    [string]$ReportPath = ".\verification_report.json"
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Logging
# ============================================================================

function Write-Status($Message) {
    Write-Host "[VERIFY] $Message" -ForegroundColor Cyan
}

function Write-Success($Message) {
    Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Write-Warning($Message) {
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Error($Message) {
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

# ============================================================================
# File Validation
# ============================================================================

function Test-ReleaseFiles {
    param([string]$Dir)
    
    Write-Status "Validating release files..."
    
    $requiredFiles = @(
        "rawrxd.exe",
        "rawrxd-benchmark.exe",
        "config.yaml",
        "README.md",
        "LICENSE"
    )
    
    $results = @{
        present = @()
        missing = @()
        extra = @()
    }
    
    $actualFiles = Get-ChildItem -Path $Dir -File | Select-Object -ExpandProperty Name
    
    foreach ($file in $requiredFiles) {
        if ($actualFiles -contains $file) {
            $results.present += $file
        } else {
            $results.missing += $file
        }
    }
    
    foreach ($file in $actualFiles) {
        if ($requiredFiles -notcontains $file -and -not $file.EndsWith(".checksums") -and -not $file.EndsWith(".manifest.json")) {
            $results.extra += $file
        }
    }
    
    return $results
}

# ============================================================================
# Signature Validation
# ============================================================================

function Test-AllSignatures {
    param([string]$Dir)
    
    Write-Status "Verifying code signatures..."
    
    $executables = Get-ChildItem -Path $Dir -Filter "*.exe"
    $results = @()
    
    foreach ($exe in $executables) {
        $sig = Get-AuthenticodeSignature -FilePath $exe.FullName
        $result = @{
            file = $exe.Name
            status = $sig.Status
            signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
            timestamp = if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.Subject } else { $null }
        }
        $results += $result
        
        if ($sig.Status -eq "Valid") {
            Write-Success "$($exe.Name) - Signed by $($result.signer)"
        } else {
            Write-Error "$($exe.Name) - $($sig.Status)"
        }
    }
    
    return $results
}

# ============================================================================
# Checksum Validation
# ============================================================================

function Test-AllChecksums {
    param([string]$Dir)
    
    Write-Status "Verifying checksums..."
    
    $checksumFiles = Get-ChildItem -Path $Dir -Filter "*.checksums"
    $results = @()
    
    foreach ($cf in $checksumFiles) {
        $baseName = $cf.BaseName
        $targetFile = Join-Path $Dir $baseName
        
        if (-not (Test-Path $targetFile)) {
            Write-Warning "Checksum file $cf has no matching target file"
            continue
        }
        
        # Parse checksum file
        $content = Get-Content $cf.FullName
        $sha256Line = $content | Where-Object { $_ -match "^SHA256:\s*(.+)" } | Select-Object -First 1
        
        if ($sha256Line -match "^SHA256:\s*(.+)") {
            $expectedHash = $Matches[1].Trim().ToLower()
            $actualHash = (Get-FileHash -Path $targetFile -Algorithm SHA256).Hash.ToLower()
            
            $result = @{
                file = $baseName
                expected = $expectedHash
                actual = $actualHash
                valid = ($expectedHash -eq $actualHash)
            }
            $results += $result
            
            if ($result.valid) {
                Write-Success "$baseName - Checksum valid"
            } else {
                Write-Error "$baseName - Checksum mismatch!"
            }
        }
    }
    
    return $results
}

# ============================================================================
# Version Validation
# ============================================================================

function Test-VersionInfo {
    param(
        [string]$Dir,
        [string]$Expected
    )
    
    Write-Status "Validating version information..."
    
    $exePath = Join-Path $Dir "rawrxd.exe"
    if (-not (Test-Path $exePath)) {
        return @{ valid = $false; error = "rawrxd.exe not found" }
    }
    
    # Get file version
    $fileVersion = (Get-ItemProperty $exePath).VersionInfo.FileVersion
    $productVersion = (Get-ItemProperty $exePath).VersionInfo.ProductVersion
    
    $result = @{
        file_version = $fileVersion
        product_version = $productVersion
        expected = $Expected
        valid = $true
    }
    
    if ($Expected -and $productVersion -ne $Expected) {
        $result.valid = $false
        $result.error = "Version mismatch: expected $Expected, got $productVersion"
        Write-Error $result.error
    } else {
        Write-Success "Version: $productVersion"
    }
    
    return $result
}

# ============================================================================
# Installation Test
# ============================================================================

function Test-Installation {
    param([string]$Dir)
    
    Write-Status "Testing installation..."
    
    $results = @{
        binary_runs = $false
        help_works = $false
        version_works = $false
        benchmark_works = $false
    }
    
    $exePath = Join-Path $Dir "rawrxd.exe"
    $benchmarkPath = Join-Path $Dir "rawrxd-benchmark.exe"
    
    # Test --version
    try {
        $version = & $exePath --version 2>&1
        $results.version_works = ($LASTEXITCODE -eq 0)
        if ($results.version_works) {
            Write-Success "Version check: $version"
        }
    } catch {
        Write-Error "Version check failed: $_"
    }
    
    # Test --help
    try {
        $help = & $exePath --help 2>&1
        $results.help_works = ($LASTEXITCODE -eq 0 -or $help -match "usage|options|commands")
        if ($results.help_works) {
            Write-Success "Help command works"
        }
    } catch {
        Write-Error "Help check failed: $_"
    }
    
    # Test benchmark --help
    if (Test-Path $benchmarkPath) {
        try {
            $benchHelp = & $benchmarkPath --help 2>&1
            $results.benchmark_works = ($LASTEXITCODE -eq 0)
            if ($results.benchmark_works) {
                Write-Success "Benchmark help works"
            }
        } catch {
            Write-Error "Benchmark check failed: $_"
        }
    }
    
    return $results
}

# ============================================================================
# Security Scan
# ============================================================================

function Invoke-SecurityScan {
    param([string]$Dir)
    
    Write-Status "Running security scan..."
    
    $results = @{
        issues = @()
        warnings = @()
        passed = $true
    }
    
    # Check for unsigned executables
    $executables = Get-ChildItem -Path $Dir -Filter "*.exe"
    foreach ($exe in $executables) {
        $sig = Get-AuthenticodeSignature -FilePath $exe.FullName
        if ($sig.Status -ne "Valid") {
            $results.issues += "Unsigned executable: $($exe.Name)"
            $results.passed = $false
        }
    }
    
    # Check for suspicious files
    $suspicious = Get-ChildItem -Path $Dir | Where-Object { 
        $_.Extension -in @('.dll', '.sys', '.drv') -and 
        $_.Name -notmatch "^(rawrxd|benchmark)"
    }
    
    foreach ($file in $suspicious) {
        $results.warnings += "Unexpected file: $($file.Name)"
    }
    
    # Check file sizes (sanity check)
    $mainExe = Join-Path $Dir "rawrxd.exe"
    if (Test-Path $mainExe) {
        $size = (Get-Item $mainExe).Length
        if ($size -lt 100KB) {
            $results.issues += "Main executable suspiciously small ($size bytes)"
            $results.passed = $false
        }
        if ($size -gt 500MB) {
            $results.warnings += "Main executable unusually large ($([math]::Round($size/1MB, 2)) MB)"
        }
    }
    
    if ($results.passed -and $results.issues.Count -eq 0) {
        Write-Success "Security scan passed"
    } else {
        Write-Error "Security scan found $($results.issues.Count) issues"
    }
    
    return $results
}

# ============================================================================
# Report Generation
# ============================================================================

function Export-VerificationReport {
    param(
        [hashtable]$Results,
        [string]$Path
    )
    
    Write-Status "Generating verification report..."
    
    $report = @{
        timestamp = Get-Date -Format "o"
        release_directory = $ReleaseDir
        summary = @{
            total_checks = 0
            passed = 0
            failed = 0
            warnings = 0
        }
        details = $Results
    }
    
    # Calculate summary
    foreach ($key in $Results.Keys) {
        $section = $Results[$key]
        $report.summary.total_checks++
        
        if ($section -is [hashtable] -and $section.ContainsKey("valid")) {
            if ($section.valid) {
                $report.summary.passed++
            } else {
                $report.summary.failed++
            }
        } elseif ($section -is [hashtable] -and $section.ContainsKey("passed")) {
            if ($section.passed) {
                $report.summary.passed++
            } else {
                $report.summary.failed++
            }
        }
    }
    
    $report.summary.status = if ($report.summary.failed -eq 0) { "PASSED" } else { "FAILED" }
    
    $report | ConvertTo-Json -Depth 5 | Out-File $Path -Encoding UTF8
    Write-Success "Report saved: $Path"
    
    return $report
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host ""
    Write-Host "=== RawrXD Release Verification ===" -ForegroundColor Cyan
    Write-Host "Release Directory: $ReleaseDir"
    Write-Host ""
    
    if (-not (Test-Path $ReleaseDir)) {
        Write-Error "Release directory not found: $ReleaseDir"
        exit 1
    }
    
    $results = @{}
    
    # File validation
    $results.files = Test-ReleaseFiles -Dir $ReleaseDir
    if ($results.files.missing.Count -gt 0) {
        Write-Error "Missing required files: $($results.files.missing -join ', ')"
    } else {
        Write-Success "All required files present"
    }
    
    # Signature validation
    if ($VerifySignatures) {
        $results.signatures = Test-AllSignatures -Dir $ReleaseDir
    }
    
    # Checksum validation
    if ($VerifyChecksums) {
        $results.checksums = Test-AllChecksums -Dir $ReleaseDir
    }
    
    # Version validation
    $results.version = Test-VersionInfo -Dir $ReleaseDir -Expected $ExpectedVersion
    
    # Security scan
    $results.security = Invoke-SecurityScan -Dir $ReleaseDir
    
    # Installation test
    if ($TestInstallation) {
        $results.installation = Test-Installation -Dir $ReleaseDir
    }
    
    # Generate report
    if ($GenerateReport) {
        $report = Export-VerificationReport -Results $results -Path $ReportPath
    }
    
    # Summary
    Write-Host ""
    Write-Host "=== Verification Summary ===" -ForegroundColor Cyan
    
    $passed = 0
    $failed = 0
    
    if ($results.files.missing.Count -eq 0) { $passed++ } else { $failed++ }
    if ($results.version.valid) { $passed++ } else { $failed++ }
    if ($results.security.passed) { $passed++ } else { $failed++ }
    
    Write-Host "Passed: $passed"
    Write-Host "Failed: $failed"
    
    if ($failed -eq 0) {
        Write-Host ""
        Write-Success "Release verification PASSED"
        exit 0
    } else {
        Write-Host ""
        Write-Error "Release verification FAILED"
        exit 1
    }
}

Main
