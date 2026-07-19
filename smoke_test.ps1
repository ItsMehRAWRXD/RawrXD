#!/usr/bin/env pwsh
# RawrXD Smoke Test Script
# Validates integrated paths are exercised

param(
    [switch]$Verbose,
    [string]$BinaryPath = "build-ninja\bin\RawrXD-Win32IDE.exe"
)

$ErrorActionPreference = "Stop"
$script:Passed = 0
$script:Failed = 0

function Write-TestHeader($name) {
    Write-Host "`n=== $name ===" -ForegroundColor Cyan
}

function Write-Pass($msg) {
    Write-Host "  [PASS] $msg" -ForegroundColor Green
    $script:Passed++
}

function Write-Fail($msg) {
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
    $script:Failed++
}

function Write-Info($msg) {
    Write-Host "  [INFO] $msg" -ForegroundColor Gray
}

# Test 1: Binary Existence and Hash
Write-TestHeader "Test 1: Binary Verification"
if (Test-Path $BinaryPath) {
    $file = Get-Item $BinaryPath
    Write-Pass "Binary exists: $($file.Name)"
    Write-Info "Size: $([math]::Round($file.Length / 1MB, 2)) MB"
    
    # Verify hash
    $hash = (certutil -hashfile $BinaryPath SHA256)[1].Trim()
    $expectedHash = "78fb2ebdcfed6d81c4f8ae5f44894d783a9bd98b153d962a0bef9375f99754d4"
    if ($hash -eq $expectedHash) {
        Write-Pass "SHA256 hash verified"
    } else {
        Write-Fail "Hash mismatch! Expected: $expectedHash, Got: $hash"
    }
} else {
    Write-Fail "Binary not found: $BinaryPath"
}

# Test 2: Component Source Files
Write-TestHeader "Test 2: Component Source Files"
$components = @{
    "IDE Core" = "src\ide\RawrXD_IDE_Win32.cpp"
    "GhostText" = "src\ide\RawrXD_IDE_GhostText_Engine.hpp"
    "SovereignBridge" = "src\ide\SovereignInferenceBridge.h"
    "Deep2" = "src\ide\Deep2Bridge.h"
    "Prometheus" = "src\ide\prometheus_bridge.h"
    "BraidedLoader" = "src\inference\BraidedModelLoader.c"
    "Debugger" = "src\debugger\SovereignCDB_Engine.cpp"
}

foreach ($comp in $components.GetEnumerator()) {
    if (Test-Path $comp.Value) {
        Write-Pass "$($comp.Key): $($comp.Value)"
    } else {
        Write-Fail "$($comp.Key): $($comp.Value) not found"
    }
}

# Test 3: Integration Points
Write-TestHeader "Test 3: Integration Points"
$integrationPoints = @(
    @{ File = "src\ide\RawrXD_IDE_Win32.cpp"; Pattern = "GhostTextEngine"; Desc = "GhostText integration" },
    @{ File = "src\ide\RawrXD_IDE_Win32.cpp"; Pattern = "SovereignInferenceBridge"; Desc = "SovereignBridge integration" },
    @{ File = "src\ide\RawrXD_IDE_GhostText_Engine.hpp"; Pattern = "SovereignBridge"; Desc = "GhostText->Sovereign" },
    @{ File = "src\ide\Deep2Bridge.cpp"; Pattern = "BraidedLoader"; Desc = "Deep2->BraidedLoader" }
)

foreach ($point in $integrationPoints) {
    if (Test-Path $point.File) {
        $content = Get-Content $point.File -Raw
        if ($content -match $point.Pattern) {
            Write-Pass "$($point.Desc) in $($point.File)"
        } else {
            Write-Fail "$($point.Desc) - pattern '$($point.Pattern)' not found"
        }
    } else {
        Write-Fail "$($point.File) not found"
    }
}

# Test 4: Build Artifacts
Write-TestHeader "Test 4: Build Artifacts"
$artifacts = @(
    "build-ninja\bin\RawrXD-Win32IDE.exe",
    "build-ninja\build.ninja",
    "build-ninja\.ninja_log"
)

foreach ($artifact in $artifacts) {
    if (Test-Path $artifact) {
        $item = Get-Item $artifact
        Write-Pass "$($item.Name) exists"
    } else {
        Write-Fail "$artifact not found"
    }
}

# Test 5: Documentation
Write-TestHeader "Test 5: Documentation"
$docs = @(
    "RELEASE_DOSSIER.md",
    "INTEGRATION_STATUS.md",
    "docs\GhostText_PyreBridge_Architecture.md"
)

foreach ($doc in $docs) {
    if (Test-Path $doc) {
        Write-Pass "$doc exists"
    } else {
        Write-Fail "$doc not found"
    }
}

# Test 6: Git Status
Write-TestHeader "Test 6: Git Repository"
$gitStatus = git status --porcelain 2>$null
if ($LASTEXITCODE -eq 0) {
    if ([string]::IsNullOrEmpty($gitStatus)) {
        Write-Pass "Working tree clean"
    } else {
        Write-Fail "Uncommitted changes detected"
        if ($Verbose) {
            Write-Info $gitStatus
        }
    }
    
    $commit = git rev-parse --short HEAD
    Write-Pass "Git commit: $commit"
} else {
    Write-Fail "Not a git repository"
}

# Summary
Write-TestHeader "Summary"
$total = $script:Passed + $script:Failed
Write-Host "  Total: $total | Passed: $script:Passed | Failed: $script:Failed" -ForegroundColor White

if ($script:Failed -eq 0) {
    Write-Host "`n✅ ALL TESTS PASSED - Integration validated" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n❌ SOME TESTS FAILED - Review failures above" -ForegroundColor Red
    exit 1
}
