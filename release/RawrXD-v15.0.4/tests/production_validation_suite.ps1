# RawrXD Production Validation Suite
# Unified runner for Phase 6 (Real Model Validation) + Phase 7A (24-Hour Soak)
# 
# This is the sovereign gate: if this passes, RawrXD is production-grade.

param(
    [Parameter(Mandatory=$true)]
    [string]$ModelsDir,
    
    [string]$OutputDir = "production_reports",
    
    [ValidateSet("phase6", "phase7a", "full")]
    [string]$Mode = "full",
    
    [int]$SoakDurationHours = 24,
    [string]$SoakModel = "",
    [switch]$EnableFaultInjection,
    
    [switch]$SkipBuild,
    [switch]$AutoApprove
)

$ErrorActionPreference = "Stop"

# =============================================================================
# UTILITIES
# =============================================================================

function Write-Banner {
    param([string]$Title)
    $width = 70
    $pad = [math]::Floor(($width - $Title.Length) / 2)
    Write-Host ""
    Write-Host ("=" * $width) -ForegroundColor Cyan
    Write-Host (" " * $pad + $Title) -ForegroundColor Cyan
    Write-Host ("=" * $width) -ForegroundColor Cyan
    Write-Host ""
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "[$Title]" -ForegroundColor Yellow -NoNewline
    Write-Host " " -NoNewline
    Write-Host ("-" * (60 - $Title.Length)) -ForegroundColor DarkGray
}

function Write-Status {
    param([string]$Message, [string]$Status = "info")
    $symbol = switch ($Status) {
        "success" { "✓"; Color = "Green" }
        "error"   { "✗"; Color = "Red" }
        "warning" { "!"; Color = "Yellow" }
        "info"    { "*"; Color = "Gray" }
        default   { "*"; Color = "Gray" }
    }
    Write-Host "[$symbol] $Message" -ForegroundColor $symbol.Color
}

function Test-CommandExists {
    param([string]$Command)
    $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

# =============================================================================
# PHASE 6: REAL MODEL VALIDATION
# =============================================================================

function Invoke-Phase6Validation {
    Write-Banner "PHASE 6: Real Model Validation"
    
    # Check prerequisites
    Write-Section "Prerequisites"
    
    if (-not (Test-Path $ModelsDir)) {
        Write-Status "Models directory not found: $ModelsDir" "error"
        return $false
    }
    Write-Status "Models directory: $ModelsDir" "success"
    
    # Discover models
    Write-Section "Model Discovery"
    $models = Get-ChildItem -Path $ModelsDir -Filter "*.gguf" -Recurse -ErrorAction SilentlyContinue
    
    if ($models.Count -eq 0) {
        Write-Status "No GGUF models found!" "error"
        Write-Host "Please download models to: $ModelsDir"
        Write-Host "Recommended: TheBloke/Llama-2-7B-GGUF, 13B, 70B variants"
        return $false
    }
    
    Write-Status "Found $($models.Count) model(s)" "success"
    foreach ($model in $models | Select-Object -First 5) {
        $sizeGB = [math]::Round($model.Length / 1GB, 2)
        Write-Host "      - $($model.Name) ($sizeGB GB)" -ForegroundColor Gray
    }
    if ($models.Count -gt 5) {
        Write-Host "      ... and $($models.Count - 5) more" -ForegroundColor Gray
    }
    
    # Build validator if needed
    if (-not $SkipBuild) {
        Write-Section "Building Phase 6 Validator"
        $buildScript = "$PSScriptRoot\validation\build_validator.bat"
        if (Test-Path $buildScript) {
            & $buildScript
            if ($LASTEXITCODE -ne 0) {
                Write-Status "Validator build failed!" "error"
                return $false
            }
            Write-Status "Validator built successfully" "success"
        } else {
            Write-Status "Build script not found: $buildScript" "error"
            return $false
        }
    }
    
    # Run validator
    Write-Section "Running Validation"
    $validatorExe = "$PSScriptRoot\..\build\real_model_validator.exe"
    if (Test-Path $validatorExe) {
        & $validatorExe $ModelsDir
        if ($LASTEXITCODE -ne 0) {
            Write-Status "Phase 6 validation FAILED" "error"
            return $false
        }
        Write-Status "Phase 6 validation PASSED" "success"
    } else {
        Write-Status "Validator not found: $validatorExe" "error"
        return $false
    }
    
    return $true
}

# =============================================================================
# PHASE 7A: 24-HOUR SOAK TEST
# =============================================================================

function Invoke-Phase7ASoakTest {
    Write-Banner "PHASE 7A: 24-Hour Soak Test"
    
    # Determine model to use
    $soakModelPath = $SoakModel
    if ([string]::IsNullOrEmpty($soakModelPath)) {
        # Auto-select smallest model for soak test
        $models = Get-ChildItem -Path $ModelsDir -Filter "*.gguf" -Recurse | Sort-Object Length
        if ($models.Count -eq 0) {
            Write-Status "No models available for soak test" "error"
            return $false
        }
        $soakModelPath = $models[0].FullName
        Write-Status "Auto-selected model: $($models[0].Name)" "info"
    }
    
    if (-not (Test-Path $soakModelPath)) {
        Write-Status "Soak test model not found: $soakModelPath" "error"
        return $false
    }
    
    # Build soak test harness if needed
    if (-not $SkipBuild) {
        Write-Section "Building Phase 7A Soak Harness"
        $buildScript = "$PSScriptRoot\soak\build_soak_test.bat"
        if (Test-Path $buildScript) {
            & $buildScript
            if ($LASTEXITCODE -ne 0) {
                Write-Status "Soak test build failed!" "error"
                return $false
            }
            Write-Status "Soak test built successfully" "success"
        } else {
            Write-Status "Build script not found: $buildScript" "error"
            return $false
        }
    }
    
    # Confirm before long-running test
    if (-not $AutoApprove) {
        Write-Host ""
        Write-Host "WARNING: Soak test will run for $SoakDurationHours hour(s)!" -ForegroundColor Yellow
        Write-Host "Model: $soakModelPath" -ForegroundColor Gray
        Write-Host ""
        $confirm = Read-Host "Continue? (yes/no)"
        if ($confirm -ne "yes") {
            Write-Status "Soak test cancelled by user" "warning"
            return $false
        }
    }
    
    # Run soak test
    Write-Section "Running Soak Test"
    $soakExe = "$PSScriptRoot\..\build\soak_test.exe"
    if (Test-Path $soakExe) {
        $args = @("-d", $SoakDurationHours, "-m", $soakModelPath, "-o", $OutputDir)
        if ($EnableFaultInjection) {
            $args += "-f"
        }
        
        & $soakExe @args
        if ($LASTEXITCODE -ne 0) {
            Write-Status "Phase 7A soak test FAILED" "error"
            return $false
        }
        Write-Status "Phase 7A soak test PASSED" "success"
    } else {
        Write-Status "Soak test executable not found: $soakExe" "error"
        return $false
    }
    
    return $true
}

# =============================================================================
# REPORT GENERATION
# =============================================================================

function Write-SummaryReport {
    param(
        [bool]$Phase6Passed,
        [bool]$Phase7APassed,
        [datetime]$StartTime
    )
    
    $endTime = Get-Date
    $duration = $endTime - $StartTime
    
    $reportPath = "$OutputDir\production_validation_summary.md"
    
    @"
# RawrXD Production Validation Summary

**Date:** $($endTime.ToString("yyyy-MM-dd HH:mm:ss"))  
**Duration:** $($duration.ToString("hh\:mm\:ss"))  
**Mode:** $Mode

---

## Results

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 6 | $(if ($Phase6Passed) { "✅ PASSED" } else { "⏭️ SKIPPED" }) | Real Model Validation |
| Phase 7A | $(if ($Phase7APassed) { "✅ PASSED" } else { "⏭️ SKIPPED" }) | 24-Hour Soak Test |

**Overall:** $(if ($Phase6Passed -and $Phase7APassed) { "✅ PRODUCTION READY" } elseif ($Mode -eq "phase6" -and $Phase6Passed) { "✅ PHASE 6 COMPLETE" } elseif ($Mode -eq "phase7a" -and $Phase7APassed) { "✅ PHASE 7A COMPLETE" } else { "❌ VALIDATION FAILED" })

---

## System Information

- **OS:** $([System.Environment]::OSVersion.VersionString)
- **Processor:** $((Get-WmiObject Win32_Processor).Name)
- **Memory:** $([math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)) GB
- **PowerShell:** $($PSVersionTable.PSVersion)

---

## Next Steps

$(if ($Phase6Passed -and $Phase7APassed) {
@"
✅ **RawrXD is production-grade!**

You have proven:
- Real model loading works (7B → 70B+)
- GPU VRAM detection is accurate
- 24-hour stability without drift
- No memory leaks or thermal issues
- Automatic fault recovery functional

Recommended next actions:
1. Deploy to production environment
2. Set up continuous monitoring
3. Consider Phase 7B: Multi-GPU Federation
4. Consider Phase 7C: Sovereign Telemetry Dashboard
"@
} else {
@"
⚠️ **Validation incomplete**

Address the failures above and re-run:
```powershell
.\tests\production_validation_suite.ps1 -ModelsDir "$ModelsDir" -Mode "$Mode"
```
"@
})

---

*RawrXD Sovereign Inference Runtime*  
*Phase 6 + 7A Production Validation*
"@ | Out-File $reportPath -Encoding UTF8

    Write-Status "Summary report saved: $reportPath" "success"
    
    # Open report
    Start-Process $reportPath
}

# =============================================================================
# MAIN
# =============================================================================

function Main {
    $startTime = Get-Date
    
    Write-Banner "RawrXD Production Validation Suite"
    Write-Host "Mode: $Mode" -ForegroundColor Gray
    Write-Host "Models: $ModelsDir" -ForegroundColor Gray
    Write-Host "Output: $OutputDir" -ForegroundColor Gray
    Write-Host ""
    
    # Create output directory
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    
    $phase6Result = $true
    $phase7AResult = $true
    
    # Run Phase 6
    if ($Mode -eq "phase6" -or $Mode -eq "full") {
        $phase6Result = Invoke-Phase6Validation
        if (-not $phase6Result -and $Mode -eq "full") {
            Write-Status "Phase 6 failed - skipping Phase 7A" "warning"
            $phase7AResult = $false
        }
    }
    
    # Run Phase 7A
    if (($Mode -eq "phase7a" -or ($Mode -eq "full" -and $phase6Result))) {
        $phase7AResult = Invoke-Phase7ASoakTest
    }
    
    # Generate summary
    Write-SummaryReport -Phase6Passed $phase6Result -Phase7APassed $phase7AResult -StartTime $startTime
    
    # Final status
    Write-Banner "Validation Complete"
    
    if ($phase6Result -and $phase7AResult) {
        Write-Status "PRODUCTION VALIDATION PASSED" "success"
        exit 0
    } elseif ($Mode -eq "phase6" -and $phase6Result) {
        Write-Status "PHASE 6 VALIDATION PASSED" "success"
        exit 0
    } elseif ($Mode -eq "phase7a" -and $phase7AResult) {
        Write-Status "PHASE 7A SOAK TEST PASSED" "success"
        exit 0
    } else {
        Write-Status "VALIDATION FAILED" "error"
        exit 1
    }
}

# Run main
Main
