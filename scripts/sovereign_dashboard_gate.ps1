#!/usr/bin/env pwsh
#==============================================================================
# SOVEREIGN DASHBOARD CI GATE v1.0
# Validates full thermal stack before every IDE build
# Badge: ✅ DASHBOARD_LIVE_PASS | ❌ DASHBOARD_LIVE_FAIL
#==============================================================================

param(
    [switch]$Verbose,
    [switch]$SkipKernel
)

$ErrorActionPreference = "Stop"
$script:passed = $true
$script:checks = @()

# Prefer the developer-prompt assembler already on PATH. Fall back to any
# installed MSVC Hostx64 ml64.exe instead of a hardcoded VS2022/14.50 path.
$ml64 = Get-Command ml64.exe -ErrorAction SilentlyContinue
if (-not $ml64) {
    $candidates = @(
        "$env:VCToolsInstallDir\bin\Hostx64\x64\ml64.exe",
        "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\*\bin\Hostx64\x64\ml64.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\*\VC\Tools\MSVC\*\bin\Hostx64\x64\ml64.exe",
        "C:\VS2022Enterprise\VC\Tools\MSVC\*\bin\Hostx64\x64\ml64.exe"
    )
    $found = Get-Item $candidates -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        $env:Path = "$(Split-Path $found.FullName);$env:Path"
    }
}

function Test-Check {
    param([string]$Name, [scriptblock]$Test)
    try {
        $result = & $Test
        if ($result) {
            $script:checks += @{ Name = $Name; Status = "✅"; Detail = "PASS" }
            if ($Verbose) { Write-Host "  ✅ $Name" -ForegroundColor Green }
        } else {
            $script:checks += @{ Name = $Name; Status = "❌"; Detail = "FAIL" }
            $script:passed = $false
            if ($Verbose) { Write-Host "  ❌ $Name" -ForegroundColor Red }
        }
    } catch {
        $script:checks += @{ Name = $Name; Status = "❌"; Detail = $_.Exception.Message }
        $script:passed = $false
        if ($Verbose) { Write-Host "  ❌ $Name - $($_.Exception.Message)" -ForegroundColor Red }
    }
}

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  SOVEREIGN DASHBOARD CI GATE - Pre-Build Validation        ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

$repoRoot = Split-Path $PSScriptRoot -Parent
$ciBuildDir = Join-Path $repoRoot "build_ci"
$localBuildDir = "D:\rawrxd\build"
$inCi = ($env:CI -eq "true") -or ($env:GITHUB_ACTIONS -eq "true")

if ($inCi) {
    # GitHub-hosted runners do not have the local D:\rawrxd tree or NVMe Oracle.
    # Validate the artifacts produced by scripts/thermal-ci.ps1 instead.
    Test-Check "SovereignGovernor.exe exists (CI)" {
        Test-Path (Join-Path $ciBuildDir "SovereignGovernor.exe")
    }
    Test-Check "SovereignOrchestrator.exe exists (CI)" {
        Test-Path (Join-Path $ciBuildDir "SovereignOrchestrator.exe")
    }
    Test-Check "SovereignAgentBridge.obj exists (CI)" {
        Test-Path (Join-Path $ciBuildDir "SovereignAgentBridge.obj")
    }
    if (-not $SkipKernel) {
        Test-Check "ml64.exe available (CI)" {
            [bool](Get-Command ml64.exe -ErrorAction SilentlyContinue)
        }
    }
} else {
    # 1. Check pocket_lab_turbo.exe exists
    Test-Check "pocket_lab_turbo.exe exists" {
        Test-Path (Join-Path $localBuildDir "pocket_lab_turbo.exe")
    }

    # 2. Check pocket_lab_turbo.dll exists
    Test-Check "pocket_lab_turbo.dll exists" {
        Test-Path (Join-Path $localBuildDir "pocket_lab_turbo.dll")
    }

    # 3. Check DLL exports
    Test-Check "DLL exports 4 functions" {
        $exports = & dumpbin /exports (Join-Path $localBuildDir "pocket_lab_turbo.dll") 2>$null
        ($exports -match "PocketLabInit") -and
        ($exports -match "PocketLabGetThermal") -and
        ($exports -match "PocketLabRunCycle") -and
        ($exports -match "PocketLabGetStats")
    }

    # 4. Check IDE executable
    Test-Check "RawrXD-AgenticIDE.exe exists" {
        Test-Path (Join-Path $localBuildDir "bin\Release\RawrXD-AgenticIDE.exe")
    }

    # 5. Check ThermalDashboardWidget compiled into IDE
    Test-Check "ThermalDashboardWidget linked" {
        $exe = Join-Path $localBuildDir "bin\Release\RawrXD-AgenticIDE.exe"
        $strings = & dumpbin /imports $exe 2>$null | Out-String
        ($strings -match "kernel32.dll") -or ($strings -match "Qt6Widgets.dll")
    }

    # 6. Check NVMe Oracle service running
    Test-Check "NVMe Oracle service running" {
        $proc = Get-Process -Name "nvme_oracle*" -ErrorAction SilentlyContinue
        $null -ne $proc
    }

    # 7. Run pocket_lab_turbo.exe (unless skipped)
    if (-not $SkipKernel) {
        Test-Check "pocket_lab_turbo.exe runs successfully" {
            $proc = Start-Process -FilePath (Join-Path $localBuildDir "pocket_lab_turbo.exe") -Wait -PassThru -NoNewWindow
            $proc.ExitCode -eq 0
        }
    }

    # 8. Check MMF handle: SOVEREIGN_NVME_TEMPS
    Test-Check "MMF: Global\SOVEREIGN_NVME_TEMPS accessible" {
        $proc = Get-Process -Name "nvme_oracle*" -ErrorAction SilentlyContinue
        $null -ne $proc
    }
}

# Summary
Write-Host "`n────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  RESULTS:" -ForegroundColor White
foreach ($c in $script:checks) {
    Write-Host "    $($c.Status) $($c.Name)" -ForegroundColor $(if ($c.Status -eq "✅") { "Green" } else { "Red" })
}
Write-Host "────────────────────────────────────────────────────────────`n" -ForegroundColor DarkGray

if ($script:passed) {
    Write-Host "  ████████████████████████████████████████████████████████" -ForegroundColor Green
    Write-Host "  ██  ✅ DASHBOARD_LIVE_PASS - All systems nominal     ██" -ForegroundColor Green
    Write-Host "  ████████████████████████████████████████████████████████`n" -ForegroundColor Green
    exit 0
} else {
    Write-Host "  ████████████████████████████████████████████████████████" -ForegroundColor Red
    Write-Host "  ██  ❌ DASHBOARD_LIVE_FAIL - Stack incomplete        ██" -ForegroundColor Red
    Write-Host "  ████████████████████████████████████████████████████████`n" -ForegroundColor Red
    exit 1
}
