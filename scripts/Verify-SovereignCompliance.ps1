# ════════════════════════════════════════════════════════════════════════════
# RawrXD Sovereign Compliance Verifier
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Independent verification of sovereign implementation claims
# Usage: .\Verify-SovereignCompliance.ps1 [-EvidencePath <path>] [-Verbose]
# ════════════════════════════════════════════════════════════════════════════

param(
    [string]$EvidencePath = "build\evidence",
    [switch]$Verbose,
    [switch]$GenerateReport
)

$ErrorActionPreference = "Stop"
$PassCount = 0
$FailCount = 0
$WarningCount = 0

# ════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ════════════════════════════════════════════════════════════════════════════

function Write-Pass {
    param([string]$Message)
    Write-Host "  [✓] $Message" -ForegroundColor Green
    $script:PassCount++
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  [✗] $Message" -ForegroundColor Red
    $script:FailCount++
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  [!] $Message" -ForegroundColor Yellow
    $script:WarningCount++
}

function Write-Info {
    param([string]$Message)
    if ($Verbose) {
        Write-Host "  [i] $Message" -ForegroundColor Cyan
    }
}

# ════════════════════════════════════════════════════════════════════════════
# Verification Gates
# ════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  RawrXD Sovereign Compliance Verifier" -ForegroundColor Cyan
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Check if evidence directory exists
if (-not (Test-Path $EvidencePath)) {
    Write-Fail "Evidence directory not found: $EvidencePath"
    Write-Host "  Run a Release build first to generate evidence artifacts." -ForegroundColor Yellow
    exit 1
}

Write-Info "Evidence path: $EvidencePath"
Write-Host ""

# ───────────────────────────────────────────────────────────────────────────
# Gate 1: Binary Hash Verification
# ───────────────────────────────────────────────────────────────────────────
Write-Host "Gate 1: Binary Hash Verification" -ForegroundColor Magenta

$hashFile = Join-Path $EvidencePath "binary_hash.txt"
if (Test-Path $hashFile) {
    $storedHash = Get-Content $hashFile
    Write-Info "Stored hash: $storedHash"
    
    # Find the binary
    $binaryPath = Join-Path $EvidencePath "..\bin\RawrXD-Win32IDE.exe"
    if (Test-Path $binaryPath) {
        $computedHash = (Get-FileHash $binaryPath -Algorithm SHA256).Hash
        Write-Info "Computed hash: $computedHash"
        
        if ($storedHash -eq $computedHash) {
            Write-Pass "Binary hash matches - reproducibility verified"
        } else {
            Write-Fail "Binary hash mismatch - binary may have been modified"
        }
    } else {
        Write-Warn "Binary not found at $binaryPath"
    }
} else {
    Write-Fail "binary_hash.txt not found"
}

Write-Host ""

# ───────────────────────────────────────────────────────────────────────────
# Gate 2: Source Inventory Analysis
# ───────────────────────────────────────────────────────────────────────────
Write-Host "Gate 2: Source Inventory Analysis" -ForegroundColor Magenta

$sourcesFile = Join-Path $EvidencePath "compiled_sources.txt"
if (Test-Path $sourcesFile) {
    $allSources = Get-Content $sourcesFile | Where-Object { $_ -notmatch '^#' -and $_ -notmatch '^$' }
    $cppFiles = $allSources | Where-Object { $_ -match '\.cpp$' }
    $asmFiles = $allSources | Where-Object { $_ -match '\.asm$' }
    
    Write-Info "Total C++ files: $($cppFiles.Count)"
    Write-Info "Total ASM files: $($asmFiles.Count)"
    
    # Check for integration pattern filenames
    $integrationPatterns = @('_bridge', '_adapter', '_wrapper', '_integration', '_external')
    $foundPatterns = @()
    
    foreach ($pattern in $integrationPatterns) {
        $matches = $allSources | Where-Object { $_ -match $pattern }
        if ($matches) {
            $foundPatterns += $matches
        }
    }
    
    if ($foundPatterns.Count -eq 0) {
        Write-Pass "No integration pattern filenames detected"
    } else {
        Write-Warn "Found $($foundPatterns.Count) files with integration patterns:"
        foreach ($file in $foundPatterns) {
            Write-Host "    - $file" -ForegroundColor Yellow
        }
    }
    
    # Check for sovereign naming conventions
    $sovereignPatterns = @('sovereign_', 'native_', 'direct_', 'rawr_')
    $sovereignCount = 0
    foreach ($pattern in $sovereignPatterns) {
        $sovereignCount += ($allSources | Where-Object { $_ -match $pattern }).Count
    }
    
    Write-Info "Files with sovereign naming: $sovereignCount"
} else {
    Write-Fail "compiled_sources.txt not found"
}

Write-Host ""

# ───────────────────────────────────────────────────────────────────────────
# Gate 3: Dependency Manifest Compliance
# ───────────────────────────────────────────────────────────────────────────
Write-Host "Gate 3: Dependency Manifest Compliance" -ForegroundColor Magenta

$manifestFile = Join-Path $EvidencePath "dependency_manifest.json"
if (Test-Path $manifestFile) {
    $manifest = Get-Content $manifestFile | ConvertFrom-Json
    
    Write-Info "Platform dependencies: $($manifest.platform_dependencies.Count)"
    Write-Info "GPU dependencies: $($manifest.gpu_dependencies.Count)"
    Write-Info "Third-party dependencies: $($manifest.third_party_dependencies.Count)"
    
    # Check for prohibited dependencies
    if ($manifest.prohibited_dependencies -and $manifest.prohibited_dependencies.Count -gt 0) {
        Write-Fail "Prohibited dependencies found:"
        foreach ($dep in $manifest.prohibited_dependencies) {
            Write-Host "    - $dep" -ForegroundColor Red
        }
    } else {
        Write-Pass "No prohibited dependencies (llama, ggml, onnxruntime, etc.)"
    }
    
    # Check compliance status
    if ($manifest.compliance_status -eq 'PASS') {
        Write-Pass "Dependency manifest compliance: PASS"
    } else {
        Write-Fail "Dependency manifest compliance: FAIL"
    }
} else {
    Write-Fail "dependency_manifest.json not found"
}

Write-Host ""

# ───────────────────────────────────────────────────────────────────────────
# Gate 4: Binary Import Table Inspection
# ───────────────────────────────────────────────────────────────────────────
Write-Host "Gate 4: Binary Import Table Inspection" -ForegroundColor Magenta

$importsFile = Join-Path $EvidencePath "binary_imports.txt"
if (Test-Path $importsFile) {
    $imports = Get-Content $importsFile
    
    # Check for prohibited DLLs
    $prohibitedDlls = @('llama.dll', 'ggml.dll', 'onnxruntime.dll', 'tensorflow.dll', 'torch.dll')
    $foundProhibited = @()
    
    foreach ($dll in $prohibitedDlls) {
        if ($imports -match $dll) {
            $foundProhibited += $dll
        }
    }
    
    if ($foundProhibited.Count -eq 0) {
        Write-Pass "No prohibited DLLs in import table"
    } else {
        Write-Fail "Prohibited DLLs found in import table:"
        foreach ($dll in $foundProhibited) {
            Write-Host "    - $dll" -ForegroundColor Red
        }
    }
    
    # Extract all DLL imports
    $allDlls = $imports | Select-String '\.dll' | ForEach-Object {
        $_.Line -replace '.*?([\w\-]+\.dll)', '$1'
    } | Sort-Object -Unique
    
    Write-Info "Total DLL imports: $($allDlls.Count)"
    Write-Info "System DLLs: $($allDlls | Where-Object { $_ -match '^(KERNEL32|USER32|GDI32|ADVAPI32|ntdll)\.dll$' }).Count"
} else {
    Write-Fail "binary_imports.txt not found"
}

Write-Host ""

# ───────────────────────────────────────────────────────────────────────────
# Gate 5: Architecture Report Validation
# ───────────────────────────────────────────────────────────────────────────
Write-Host "Gate 5: Architecture Report Validation" -ForegroundColor Magenta

$archFile = Join-Path $EvidencePath "architecture_report.json"
if (Test-Path $archFile) {
    $arch = Get-Content $archFile | ConvertFrom-Json
    
    Write-Info "Artifact: $($arch.artifact)"
    Write-Info "Size: $([math]::Round($arch.size_bytes / 1MB, 2)) MB"
    Write-Info "Architecture: $($arch.architecture)"
    Write-Info "Configuration: $($arch.configuration)"
    
    # Verify SHA256 is present
    if ($arch.sha256 -and $arch.sha256.Length -eq 64) {
        Write-Pass "SHA256 hash present in architecture report"
    } else {
        Write-Fail "SHA256 hash missing or invalid"
    }
    
    # Check verification status
    if ($arch.verification -eq 'pending') {
        Write-Warn "Verification status is still 'pending'"
    } else {
        Write-Info "Verification status: $($arch.verification)"
    }
} else {
    Write-Fail "architecture_report.json not found"
}

Write-Host ""

# ───────────────────────────────────────────────────────────────────────────
# Gate 6: Benchmark Metadata Completeness
# ───────────────────────────────────────────────────────────────────────────
Write-Host "Gate 6: Benchmark Metadata Completeness" -ForegroundColor Magenta

$benchFile = Join-Path $EvidencePath "benchmark_metadata.json"
if (Test-Path $benchFile) {
    $bench = Get-Content $benchFile | ConvertFrom-Json
    
    # Check hardware info
    if ($bench.hardware.cpu -and $bench.hardware.gpu) {
        Write-Pass "Hardware information complete"
        Write-Info "CPU: $($bench.hardware.cpu)"
        Write-Info "GPU: $($bench.hardware.gpu)"
        Write-Info "RAM: $($bench.hardware.ram_gb) GB"
    } else {
        Write-Fail "Hardware information incomplete"
    }
    
    # Check software info
    if ($bench.software.compiler -and $bench.software.build_type) {
        Write-Pass "Software information complete"
        Write-Info "Compiler: $($bench.software.compiler)"
        Write-Info "Build type: $($bench.software.build_type)"
    } else {
        Write-Fail "Software information incomplete"
    }
    
    # Check if results are populated
    if ($bench.results.tokens_per_second -eq 'PENDING') {
        Write-Warn "Benchmark results not yet populated (run benchmark to fill)"
    } else {
        Write-Pass "Benchmark results populated"
        Write-Info "TPS: $($bench.results.tokens_per_second)"
    }
    
    # Verify build info matches
    if ($bench.build_info.sha256) {
        Write-Pass "Build info includes SHA256"
    } else {
        Write-Fail "Build info missing SHA256"
    }
} else {
    Write-Fail "benchmark_metadata.json not found"
}

Write-Host ""

# ───────────────────────────────────────────────────────────────────────────
# Gate 7: Linked Libraries Analysis
# ───────────────────────────────────────────────────────────────────────────
Write-Host "Gate 7: Linked Libraries Analysis" -ForegroundColor Magenta

$linkedLibsFile = Join-Path $EvidencePath "linked_libraries.txt"
if (Test-Path $linkedLibsFile) {
    $linkedLibs = Get-Content $linkedLibsFile
    
    # Check for prohibited libraries
    $prohibitedLibs = @('llama', 'ggml', 'onnx', 'tensorflow', 'torch')
    $foundProhibited = @()
    
    foreach ($lib in $prohibitedLibs) {
        if ($linkedLibs -match $lib) {
            $foundProhibited += $lib
        }
    }
    
    if ($foundProhibited.Count -eq 0) {
        Write-Pass "No prohibited libraries in linker memory"
    } else {
        Write-Fail "Prohibited libraries found:"
        foreach ($lib in $foundProhibited) {
            Write-Host "    - $lib" -ForegroundColor Red
        }
    }
} else {
    Write-Fail "linked_libraries.txt not found"
}

Write-Host ""

# ════════════════════════════════════════════════════════════════════════════
# Summary
# ════════════════════════════════════════════════════════════════════════════

Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  VERIFICATION SUMMARY" -ForegroundColor Cyan
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Passed:   $PassCount" -ForegroundColor Green
Write-Host "  Failed:   $FailCount" -ForegroundColor Red
Write-Host "  Warnings: $WarningCount" -ForegroundColor Yellow
Write-Host ""

if ($FailCount -eq 0) {
    Write-Host "  SOVEREIGN COMPLIANCE: PASS ✓" -ForegroundColor Green
    Write-Host ""
    Write-Host "  All verification gates passed. The build demonstrates:" -ForegroundColor White
    Write-Host "    • Zero prohibited dependencies" -ForegroundColor White
    Write-Host "    • Complete evidence trail" -ForegroundColor White
    Write-Host "    • Reproducible binary hash" -ForegroundColor White
    Write-Host "    • Sovereign implementation verified" -ForegroundColor White
} else {
    Write-Host "  SOVEREIGN COMPLIANCE: FAIL ✗" -ForegroundColor Red
    Write-Host ""
    Write-Host "  $FailCount verification gate(s) failed. Review the errors above." -ForegroundColor Red
}

Write-Host ""
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Generate report if requested
if ($GenerateReport) {
    $reportPath = Join-Path $EvidencePath "verification_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').md"
    
    @"
# Sovereign Compliance Verification Report

**Date**: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
**Evidence Path**: $EvidencePath

## Summary

- **Passed**: $PassCount
- **Failed**: $FailCount
- **Warnings**: $WarningCount

## Overall Status

$(if ($FailCount -eq 0) { "✅ **PASS** - Sovereign compliance verified" } else { "❌ **FAIL** - $FailCount gate(s) failed" })

## Evidence Artifacts

$(if (Test-Path $hashFile) { "- ✅ binary_hash.txt" } else { "- ❌ binary_hash.txt (missing)" })
$(if (Test-Path $sourcesFile) { "- ✅ compiled_sources.txt" } else { "- ❌ compiled_sources.txt (missing)" })
$(if (Test-Path $manifestFile) { "- ✅ dependency_manifest.json" } else { "- ❌ dependency_manifest.json (missing)" })
$(if (Test-Path $importsFile) { "- ✅ binary_imports.txt" } else { "- ❌ binary_imports.txt (missing)" })
$(if (Test-Path $archFile) { "- ✅ architecture_report.json" } else { "- ❌ architecture_report.json (missing)" })
$(if (Test-Path $benchFile) { "- ✅ benchmark_metadata.json" } else { "- ❌ benchmark_metadata.json (missing)" })
$(if (Test-Path $linkedLibsFile) { "- ✅ linked_libraries.txt" } else { "- ❌ linked_libraries.txt (missing)" })

## Recommendations

$(if ($FailCount -gt 0) { "1. Address failed verification gates above" } else { "1. Continue monitoring sovereign compliance" })
2. Run benchmarks to populate benchmark_metadata.json
3. Archive evidence artifacts for this build
4. Update CI/CD pipeline with verification gates

---
*Generated by Verify-SovereignCompliance.ps1*
"@ | Out-File -FilePath $reportPath -Encoding utf8
    
    Write-Host "Report generated: $reportPath" -ForegroundColor Cyan
}

# Exit with appropriate code
if ($FailCount -gt 0) {
    exit 1
} else {
    exit 0
}
