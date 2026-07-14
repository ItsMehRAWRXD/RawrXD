# Phase 6 Validation Runner
# Runs comprehensive production validation tests

param(
    [string]$ModelsDir = "models",
    [string]$OutputDir = "validation_reports",
    [switch]$StressTest,
    [int]$DurationHours = 1
)

$ErrorActionPreference = "Stop"

function Write-Header {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Gray
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

# Initialize
Write-Header "RawrXD Phase 6: Production Validation"

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = "$OutputDir\phase6_validation_$timestamp.md"

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Start report
@"
# RawrXD Phase 6 Validation Report

**Date:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")  
**Models Directory:** $ModelsDir  
**Stress Test:** $($StressTest.IsPresent)  

## System Information

"@ | Out-File $reportFile

# System Info
Write-Header "System Information"

$sysInfo = @"
- OS: $([System.Environment]::OSVersion.VersionString)
- Processor: $((Get-WmiObject Win32_Processor).Name)
- Total Memory: $([math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)) GB
- PowerShell Version: $($PSVersionTable.PSVersion)
"@

Write-Host $sysInfo
$sysInfo | Out-File $reportFile -Append

# GPU Detection (Corrected)
Write-Header "GPU Detection (Corrected)"

Write-Status "Detecting GPU with corrected VRAM calculation..."

# Use dxdiag to get GPU info
$dxdiag = & dxdiag /t "$env:TEMP\dxdiag.txt" 2>$null
Start-Sleep -Seconds 2

$gpuInfo = ""
if (Test-Path "$env:TEMP\dxdiag.txt") {
    $dxContent = Get-Content "$env:TEMP\dxdiag.txt" -Raw
    
    # Extract display device info
    if ($dxContent -match "Display Devices[\s\S]*?Card name:\s*(.+)") {
        $gpuName = $matches[1].Trim()
        Write-Success "GPU: $gpuName"
        $gpuInfo += "- GPU: $gpuName`n"
    }
    
    if ($dxContent -match "Dedicated Memory:\s*(\d+)\s*MB") {
        $dedicatedMB = [int]$matches[1]
        $dedicatedGB = [math]::Round($dedicatedMB / 1024, 2)
        Write-Success "Dedicated VRAM: $dedicatedGB GB"
        $gpuInfo += "- Dedicated VRAM: $dedicatedGB GB`n"
    }
    
    if ($dxContent -match "Display Memory:\s*(\d+)\s*MB") {
        $displayMB = [int]$matches[1]
        $displayGB = [math]::Round($displayMB / 1024, 2)
        Write-Status "Display Memory: $displayGB GB (includes shared)"
        $gpuInfo += "- Display Memory: $displayGB GB`n"
    }
    
    Remove-Item "$env:TEMP\dxdiag.txt" -ErrorAction SilentlyContinue
}

$gpuInfo | Out-File $reportFile -Append

# Model Discovery
Write-Header "Model Discovery"

$models = @()
if (Test-Path $ModelsDir) {
    $models = Get-ChildItem -Path $ModelsDir -Filter "*.gguf" -Recurse -ErrorAction SilentlyContinue
}

if ($models.Count -eq 0) {
    Write-Error "No GGUF models found in: $ModelsDir"
    Write-Warning "Please place models in this directory or specify correct path"
    @"

## Model Discovery

**Status:** FAILED  
**Error:** No GGUF models found in: $ModelsDir

**Action Required:**
1. Download GGUF models from Hugging Face
2. Place them in: $ModelsDir
3. Re-run validation

Example models to test:
- 7B: TheBloke/Llama-2-7B-GGUF
- 13B: TheBloke/Llama-2-13B-GGUF
- 70B: TheBloke/Llama-2-70B-GGUF (if VRAM permits)

"@ | Out-File $reportFile -Append
    
    Write-Header "Validation FAILED"
    exit 1
}

Write-Success "Found $($models.Count) model(s)"

@"

## Model Discovery

**Status:** SUCCESS  
**Models Found:** $($models.Count)

| Model | Size (GB) | Path |
|-------|-----------|------|
"@ | Out-File $reportFile -Append

foreach ($model in $models) {
    $sizeGB = [math]::Round($model.Length / 1GB, 2)
    Write-Status "  - $($model.Name) ($sizeGB GB)"
    "| $($model.Name) | $sizeGB | $($model.FullName) |" | Out-File $reportFile -Append
}

# Build Validator
Write-Header "Building Validator"

$validatorPath = "$PSScriptRoot\build_validator.bat"
if (Test-Path $validatorPath) {
    & $validatorPath
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to build validator"
        exit 1
    }
} else {
    Write-Error "Build script not found: $validatorPath"
    exit 1
}

# Run Validator
Write-Header "Running Real Model Validator"

$validatorExe = "$PSScriptRoot\..\..\build\real_model_validator.exe"
if (Test-Path $validatorExe) {
    & $validatorExe $ModelsDir
    $validatorExit = $LASTEXITCODE
    
    @"

## Validator Results

**Exit Code:** $validatorExit
**Status:** $(if ($validatorExit -eq 0) { "PASSED" } else { "FAILED" })

"@ | Out-File $reportFile -Append
    
    if ($validatorExit -ne 0) {
        Write-Error "Validator failed with exit code: $validatorExit"
    }
} else {
    Write-Error "Validator executable not found: $validatorExe"
    exit 1
}

# Memory Test
Write-Header "Memory Validation"

Write-Status "Checking available system memory..."
$availableMemory = (Get-WmiObject Win32_OperatingSystem).FreePhysicalMemory / 1MB
$totalMemory = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB
Write-Status "Total: $([math]::Round($totalMemory, 2)) GB, Available: $([math]::Round($availableMemory, 2)) GB"

@"

## Memory Validation

- Total Physical Memory: $([math]::Round($totalMemory, 2)) GB
- Available Memory: $([math]::Round($availableMemory, 2)) GB
- Status: $(if ($availableMemory -gt 4096) { "SUFFICIENT" } else { "LOW" })

"@ | Out-File $reportFile -Append

# Stress Test (if requested)
if ($StressTest) {
    Write-Header "Stress Test ($DurationHours hour(s))"
    Write-Warning "Stress test not yet implemented"
    Write-Status "Would run:"
    Write-Status "  - Continuous inference for $DurationHours hours"
    Write-Status "  - Memory leak detection"
    Write-Status "  - Thermal monitoring"
    Write-Status "  - Performance degradation tracking"
}

# Summary
Write-Header "Validation Complete"

@"

## Summary

**Overall Status:** $(if ($validatorExit -eq 0) { "✅ PASSED" } else { "❌ FAILED" })

### Next Steps

$(if ($validatorExit -eq 0) {
@"
1. ✅ Model discovery working
2. ✅ GPU detection corrected
3. ✅ VRAM calculation validated
4. ⏭️ Run inference benchmarks
5. ⏭️ Test quantization variants (Q4, Q5, Q8)
6. ⏭️ Validate large models (13B, 70B)
"@
} else {
@"
1. ❌ Fix model discovery issues
2. ❌ Verify GPU detection logic
3. ⏭️ Re-run validation
4. ⏭️ Then proceed to inference benchmarks
"@
})

---

**Report Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
**Report File:** $reportFile

"@ | Out-File $reportFile -Append

Write-Success "Validation report saved to: $reportFile"

# Open report
Start-Process $reportFile

exit $validatorExit
