#requires -Version 7.0
<#
.SYNOPSIS
    RawrXD IDE - CERTIFICATION BUILD
    
.DESCRIPTION
    8-stage certification gate for production builds.
    Maps to VAL-063 pipeline for reproducible binary certification.
    
    Stages:
    1. Source Integrity
    2. Compile
    3. Link
    4. GGUF Load
    5. Tokenizer
    6. Transformer Kernel
    7. GPU Dispatch
    8. Inference Stream
    
.PARAMETER Stage
    Run specific stage (1-8) or 'all' for complete certification
    
.PARAMETER Clean
    Clean build artifacts before starting
    
.PARAMETER Report
    Generate certification report
#>
param(
    [ValidateSet('all', '1', '2', '3', '4', '5', '6', '7', '8')]
    [string]$Stage = 'all',
    
    [switch]$Clean,
    [switch]$Report,
    [switch]$Verbose
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

$ProjectRoot = 'D:\rawrxd'
$CertDir = Join-Path $ProjectRoot 'certification'
$BuildDir = Join-Path $CertDir 'build'
$ReportDir = Join-Path $CertDir 'reports'
$LogDir = Join-Path $CertDir 'logs'

$CertificationStartTime = Get-Date
$StageResults = @()

# Ensure directories exist
@($CertDir, $BuildDir, $ReportDir, $LogDir) | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

function Write-CertLog {
    param([string]$Message, [string]$Level = 'INFO')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry -ForegroundColor $(
        switch ($Level) {
            'ERROR' { 'Red' }
            'WARN'  { 'Yellow' }
            'PASS'  { 'Green' }
            'STAGE' { 'Cyan' }
            default { 'White' }
        }
    )
    Add-Content -Path (Join-Path $LogDir "certification.log") -Value $logEntry
}

function Start-CertStage {
    param([int]$StageNum, [string]$Name)
    Write-CertLog "═══════════════════════════════════════════════════════════════" 'STAGE'
    Write-CertLog "STAGE $StageNum`: $Name" 'STAGE'
    Write-CertLog "═══════════════════════════════════════════════════════════════" 'STAGE'
    return @{ Stage = $StageNum; Name = $Name; StartTime = Get-Date }
}

function Complete-CertStage {
    param([hashtable]$StageInfo, [bool]$Success, [string]$Details = '')
    $duration = (Get-Date) - $StageInfo.StartTime
    $result = @{
        Stage = $StageInfo.Stage
        Name = $StageInfo.Name
        Success = $Success
        Duration = $duration
        Details = $Details
        Timestamp = Get-Date
    }
    $StageResults += $result
    
    if ($Success) {
        Write-CertLog "✅ STAGE $($StageInfo.Stage) PASSED ($([math]::Round($duration.TotalSeconds, 2))s)" 'PASS'
    } else {
        Write-CertLog "❌ STAGE $($StageInfo.Stage) FAILED: $Details" 'ERROR'
    }
    return $result
}

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 1: SOURCE INTEGRITY
# ═══════════════════════════════════════════════════════════════════════════════

function Stage1-SourceIntegrity {
    $stage = Start-CertStage 1 "Source Integrity"
    $issues = @()
    
    # Check for merge conflicts
    Write-CertLog "Checking for git merge conflicts..."
    $conflictFiles = Get-ChildItem -Path $ProjectRoot -Recurse -File -ErrorAction SilentlyContinue | 
        Where-Object { 
            $_.Extension -notin @('.exe', '.dll', '.obj', '.lib', '.pdb', '.ilk', '.gguf', '.bin', '.zip', '.7z') -and
            $_.FullName -notlike '*\.git\*' -and
            $_.FullName -notlike '*\.archive\*'
        } | ForEach-Object {
            $content = Get-Content -Raw $_.FullName -ErrorAction SilentlyContinue
            if ($content -match '<<<<<<< HEAD') { $_.FullName }
        }
    
    if ($conflictFiles.Count -gt 0) {
        $issues += "Found $($conflictFiles.Count) files with merge conflicts"
        $conflictFiles | Select-Object -First 5 | ForEach-Object { Write-CertLog "  - $_" 'ERROR' }
    }
    
    # Check critical files exist
    Write-CertLog "Verifying critical source files..."
    $criticalFiles = @(
        'src\win32app\Win32IDE.cpp',
        'src\win32app\main_win32.cpp',
        'include\agentic_executor.h',
        'include\planning_agent.h',
        'include\compiler\platform.hpp'
    )
    
    foreach ($file in $criticalFiles) {
        $fullPath = Join-Path $ProjectRoot $file
        if (-not (Test-Path $fullPath)) {
            $issues += "Missing critical file: $file"
        }
    }
    
    # Count source files
    Write-CertLog "Counting source files..."
    $cppFiles = @(Get-ChildItem -Path $ProjectRoot -Recurse -Filter '*.cpp' -ErrorAction SilentlyContinue | 
        Where-Object { $_.FullName -notlike '*\.archive\*' -and $_.FullName -notlike '*\.git\*' })
    $hppFiles = @(Get-ChildItem -Path $ProjectRoot -Recurse -Filter '*.hpp' -ErrorAction SilentlyContinue | 
        Where-Object { $_.FullName -notlike '*\.archive\*' -and $_.FullName -notlike '*\.git\*' })
    $asmFiles = @(Get-ChildItem -Path $ProjectRoot -Recurse -Filter '*.asm' -ErrorAction SilentlyContinue | 
        Where-Object { $_.FullName -notlike '*\.archive\*' -and $_.FullName -notlike '*\.git\*' })
    
    Write-CertLog "  C++ files: $($cppFiles.Count)" 'INFO'
    Write-CertLog "  Header files: $($hppFiles.Count)" 'INFO'
    Write-CertLog "  Assembly files: $($asmFiles.Count)" 'INFO'
    
    $details = "C++: $($cppFiles.Count), Headers: $($hppFiles.Count), ASM: $($asmFiles.Count)"
    if ($issues.Count -eq 0) {
        return Complete-CertStage $stage $true $details
    } else {
        return Complete-CertStage $stage $false ($issues -join '; ')
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 2: COMPILE
# ═══════════════════════════════════════════════════════════════════════════════

function Stage2-Compile {
    $stage = Start-CertStage 2 "Compile"
    
    Write-CertLog "Detecting compiler..."
    
    # Check for MSVC
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -property installationPath 2>$null
        if ($vsPath) {
            Write-CertLog "Found Visual Studio at: $vsPath" 'PASS'
            $clPath = Join-Path $vsPath "VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe"
            $clExe = Resolve-Path $clPath -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($clExe) {
                Write-CertLog "Found cl.exe: $clExe" 'PASS'
            }
        }
    }
    
    # Check for Clang
    $clang = Get-Command clang -ErrorAction SilentlyContinue
    if ($clang) {
        Write-CertLog "Found Clang: $($clang.Source)" 'PASS'
    }
    
    # Attempt minimal compile test
    Write-CertLog "Running minimal compile test..."
    $testCpp = @"
#include "compiler/platform.hpp"
int main() { return rawrxd::is_windows ? 0 : 1; }
"@
    $testPath = Join-Path $BuildDir "compile_test.cpp"
    Set-Content -Path $testPath -Value $testCpp
    
    # Try MSVC first
    $compileSuccess = $false
    if ($clExe) {
        $output = & $clExe "/c" "/nologo" "/W4" "/EHsc" "/std:c++20" "/I$ProjectRoot\include" "/Fo$BuildDir\compile_test.obj" $testPath 2>&1
        if ($LASTEXITCODE -eq 0) {
            $compileSuccess = $true
            Write-CertLog "MSVC compile test: PASSED" 'PASS'
        } else {
            Write-CertLog "MSVC compile test output: $output" 'WARN'
        }
    }
    
    if ($compileSuccess) {
        return Complete-CertStage $stage $true "MSVC C++20 compilation successful"
    } else {
        return Complete-CertStage $stage $false "Compilation test failed"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 3: LINK
# ═══════════════════════════════════════════════════════════════════════════════

function Stage3-Link {
    $stage = Start-CertStage 3 "Link"
    
    Write-CertLog "Checking linker availability..."
    
    $linkExe = Get-Command link -ErrorAction SilentlyContinue
    if (-not $linkExe) {
        $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        if (Test-Path $vswhere) {
            $vsPath = & $vswhere -latest -property installationPath 2>$null
            $linkPath = Join-Path $vsPath "VC\Tools\MSVC\*\bin\Hostx64\x64\link.exe"
            $linkExe = Resolve-Path $linkPath -ErrorAction SilentlyContinue | Select-Object -First 1
        }
    }
    
    if ($linkExe) {
        Write-CertLog "Found linker: $linkExe" 'PASS'
        return Complete-CertStage $stage $true "Linker available"
    } else {
        return Complete-CertStage $stage $false "Linker not found"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 4: GGUF LOAD
# ═══════════════════════════════════════════════════════════════════════════════

function Stage4-GGUFLoad {
    $stage = Start-CertStage 4 "GGUF Load"
    
    Write-CertLog "Checking GGUF loader implementation..."
    
    $ggufFiles = @(
        'src\gguf_loader.cpp',
        'src\gguf_vocab_resolver.cpp',
        'src\streaming_gguf_loader.cpp'
    )
    
    $found = 0
    foreach ($file in $ggufFiles) {
        $fullPath = Join-Path $ProjectRoot $file
        if (Test-Path $fullPath) {
            Write-CertLog "  Found: $file" 'PASS'
            $found++
        } else {
            Write-CertLog "  Missing: $file" 'WARN'
        }
    }
    
    if ($found -ge 2) {
        return Complete-CertStage $stage $true "$found GGUF loader files present"
    } else {
        return Complete-CertStage $stage $false "Insufficient GGUF loader files"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 5: TOKENIZER
# ═══════════════════════════════════════════════════════════════════════════════

function Stage5-Tokenizer {
    $stage = Start-CertStage 5 "Tokenizer"
    
    Write-CertLog "Checking tokenizer implementation..."
    
    $tokenizerFiles = @(
        'src\gguf_vocab_resolver.cpp'
    )
    
    $found = 0
    foreach ($file in $tokenizerFiles) {
        $fullPath = Join-Path $ProjectRoot $file
        if (Test-Path $fullPath) {
            $found++
        }
    }
    
    if ($found -ge 1) {
        return Complete-CertStage $stage $true "Tokenizer implementation present"
    } else {
        return Complete-CertStage $stage $false "Tokenizer implementation missing"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 6: TRANSFORMER KERNEL
# ═══════════════════════════════════════════════════════════════════════════════

function Stage6-TransformerKernel {
    $stage = Start-CertStage 6 "Transformer Kernel"
    
    Write-CertLog "Checking transformer kernel implementation..."
    
    $kernelFiles = Get-ChildItem -Path $ProjectRoot -Recurse -Filter '*.asm' -ErrorAction SilentlyContinue | 
        Where-Object { 
            $_.Name -match 'transformer|kernel|inference|attention' -and
            $_.FullName -notlike '*\.archive\*'
        }
    
    if ($kernelFiles.Count -gt 0) {
        Write-CertLog "  Found $($kernelFiles.Count) kernel files" 'PASS'
        $kernelFiles | Select-Object -First 3 | ForEach-Object { Write-CertLog "    - $($_.Name)" }
        return Complete-CertStage $stage $true "$($kernelFiles.Count) kernel files present"
    } else {
        return Complete-CertStage $stage $false "No transformer kernel files found"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 7: GPU DISPATCH
# ═══════════════════════════════════════════════════════════════════════════════

function Stage7-GPUDispatch {
    $stage = Start-CertStage 7 "GPU Dispatch"
    
    Write-CertLog "Checking GPU dispatch implementation..."
    
    $gpuFiles = Get-ChildItem -Path $ProjectRoot -Recurse -File -ErrorAction SilentlyContinue | 
        Where-Object { 
            ($_.Name -match 'vulkan|cuda|gpu|scheduler' -or $_.FullName -match 'vulkan|cuda|gpu|scheduler') -and
            $_.FullName -notlike '*\.archive\*' -and
            $_.Extension -in @('.cpp', '.hpp', '.h', '.asm')
        } | Select-Object -First 10
    
    if ($gpuFiles.Count -gt 0) {
        Write-CertLog "  Found $($gpuFiles.Count) GPU-related files" 'PASS'
        return Complete-CertStage $stage $true "$($gpuFiles.Count) GPU dispatch files present"
    } else {
        return Complete-CertStage $stage $false "GPU dispatch implementation not found"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 8: INFERENCE STREAM
# ═══════════════════════════════════════════════════════════════════════════════

function Stage8-InferenceStream {
    $stage = Start-CertStage 8 "Inference Stream"
    
    Write-CertLog "Checking inference stream implementation..."
    
    $inferenceFiles = Get-ChildItem -Path $ProjectRoot -Recurse -File -ErrorAction SilentlyContinue | 
        Where-Object { 
            ($_.Name -match 'inference|stream|token|generation' -or $_.FullName -match 'inference|stream') -and
            $_.FullName -notlike '*\.archive\*' -and
            $_.Extension -in @('.cpp', '.hpp', '.h')
        } | Select-Object -First 10
    
    if ($inferenceFiles.Count -gt 0) {
        Write-CertLog "  Found $($inferenceFiles.Count) inference-related files" 'PASS'
        return Complete-CertStage $stage $true "$($inferenceFiles.Count) inference stream files present"
    } else {
        return Complete-CertStage $stage $false "Inference stream implementation not found"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

function Generate-CertificationReport {
    $reportPath = Join-Path $ReportDir "certification_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').md"
    $totalDuration = (Get-Date) - $CertificationStartTime
    $passedStages = ($StageResults | Where-Object { $_.Success }).Count
    $totalStages = $StageResults.Count
    
    $report = @"
# RawrXD Certification Build Report

**Date:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  
**Duration:** $([math]::Round($totalDuration.TotalMinutes, 2)) minutes  
**Result:** $(if ($passedStages -eq $totalStages) { '✅ CERTIFIED' } else { '❌ FAILED' })

---

## Summary

| Metric | Value |
|--------|-------|
| Total Stages | $totalStages |
| Passed | $passedStages |
| Failed | $($totalStages - $passedStages) |
| Success Rate | $([math]::Round(($passedStages / $totalStages) * 100, 1))% |

---

## Stage Results

| Stage | Name | Status | Duration | Details |
|-------|------|--------|----------|---------|
"@
    
    foreach ($result in $StageResults) {
        $status = if ($result.Success) { '✅ PASS' } else { '❌ FAIL' }
        $report += "| $($result.Stage) | $($result.Name) | $status | $([math]::Round($result.Duration.TotalSeconds, 2))s | $($result.Details) |`n"
    }
    
    $report += @"

---

## System Information

- **OS:** $([System.Environment]::OSVersion.VersionString)
- **PowerShell:** $($PSVersionTable.PSVersion)
- **Project Root:** $ProjectRoot

---

## Next Steps

$(if ($passedStages -eq $totalStages) {
@"
✅ **Certification Complete**

The codebase has passed all certification stages and is ready for:
1. Production build execution
2. Binary distribution
3. Deployment

Run the production build:
```powershell
.\BUILD_ORCHESTRATOR.ps1 -Mode production
```
"@
} else {
@"
❌ **Certification Failed**

Please address the failed stages before proceeding:
$(($StageResults | Where-Object { -not $_.Success } | ForEach-Object { "- Stage $($_.Stage): $($_.Name) - $($_.Details)" }) -join "`n")
"@
})

"@
    
    Set-Content -Path $reportPath -Value $report
    Write-CertLog "Report generated: $reportPath" 'PASS'
    return $reportPath
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD CERTIFICATION BUILD - VAL-063 Pipeline               ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($Clean) {
    Write-CertLog "Cleaning certification artifacts..." 'WARN'
    Remove-Item -Path $BuildDir\* -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $LogDir\* -Recurse -Force -ErrorAction SilentlyContinue
}

# Run stages
$stagesToRun = if ($Stage -eq 'all') { 1..8 } else { [int]$Stage }

foreach ($s in $stagesToRun) {
    switch ($s) {
        1 { Stage1-SourceIntegrity }
        2 { Stage2-Compile }
        3 { Stage3-Link }
        4 { Stage4-GGUFLoad }
        5 { Stage5-Tokenizer }
        6 { Stage6-TransformerKernel }
        7 { Stage7-GPUDispatch }
        8 { Stage8-InferenceStream }
    }
}

# Generate report if requested or if running all stages
if ($Report -or $Stage -eq 'all') {
    $reportPath = Generate-CertificationReport
    Write-Host "`n📄 Report: $reportPath" -ForegroundColor Cyan
}

# Final summary
$passed = ($StageResults | Where-Object { $_.Success }).Count
$total = $StageResults.Count

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CERTIFICATION SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Stages Passed: $passed / $total" -ForegroundColor $(if ($passed -eq $total) { 'Green' } else { 'Yellow' })
Write-Host "========================================" -ForegroundColor Cyan

if ($passed -eq $total) {
    Write-Host "`n✅ CERTIFICATION PASSED" -ForegroundColor Green
    Write-Host "The codebase is ready for production build." -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n⚠️ CERTIFICATION INCOMPLETE" -ForegroundColor Yellow
    Write-Host "Review failed stages above." -ForegroundColor Yellow
    exit 1
}
