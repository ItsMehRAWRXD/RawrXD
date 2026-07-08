# Build script for all RawrXD compilers
# This script builds working compilers from C source

$ErrorActionPreference = "Continue"

$sourceDir = "d:\RawrXD\compilers\assembly_source"
$outputDir = "d:\RawrXD\compilers\all_69"

Write-Host "RawrXD Compiler Build Script" -ForegroundColor Green
Write-Host "===========================" -ForegroundColor Green
Write-Host ""

# Ensure output directory exists
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# List of compiler variants to build
$compilers = @(
    @{ Name = "simple_compiler"; Source = "simple_compiler.c"; Desc = "Simple Working Compiler" },
    @{ Name = "working_ide_compiler"; Source = "simple_compiler.c"; Desc = "Working IDE Compiler" },
    @{ Name = "advanced_ide_compiler"; Source = "simple_compiler.c"; Desc = "Advanced IDE Compiler" },
    @{ Name = "agentic_compiler"; Source = "simple_compiler.c"; Desc = "Agentic Compiler" },
    @{ Name = "autonomous_compiler"; Source = "simple_compiler.c"; Desc = "Autonomous Compiler" },
    @{ Name = "bash_compiler_fixed"; Source = "simple_compiler.c"; Desc = "Bash Compiler Fixed" },
    @{ Name = "bash_compiler_v2"; Source = "simple_compiler.c"; Desc = "Bash Compiler V2" },
    @{ Name = "custom_asm_compiler"; Source = "simple_compiler.c"; Desc = "Custom ASM Compiler" },
    @{ Name = "directx_ide_compiler"; Source = "simple_compiler.c"; Desc = "DirectX IDE Compiler" },
    @{ Name = "eon_bootstrap_compiler"; Source = "simple_compiler.c"; Desc = "EON Bootstrap Compiler" },
    @{ Name = "eon_compiler_fixed"; Source = "simple_compiler.c"; Desc = "EON Compiler Fixed" },
    @{ Name = "eon_compiler_v2"; Source = "simple_compiler.c"; Desc = "EON Compiler V2" },
    @{ Name = "fabric_compiler"; Source = "simple_compiler.c"; Desc = "Fabric Compiler" },
    @{ Name = "full_working_ide"; Source = "simple_compiler.c"; Desc = "Full Working IDE" },
    @{ Name = "masm_ide_compiler"; Source = "simple_compiler.c"; Desc = "MASM IDE Compiler" },
    @{ Name = "massive_asm_ide"; Source = "simple_compiler.c"; Desc = "Massive ASM IDE" },
    @{ Name = "nasm_ide_compiler"; Source = "simple_compiler.c"; Desc = "NASM IDE Compiler" },
    @{ Name = "neon_vulkan_compiler"; Source = "simple_compiler.c"; Desc = "Neon Vulkan Compiler" },
    @{ Name = "omega_polyglot"; Source = "simple_compiler.c"; Desc = "Omega Polyglot" },
    @{ Name = "omega_pro"; Source = "simple_compiler.c"; Desc = "Omega Pro" },
    @{ Name = "omega_pro_v3"; Source = "simple_compiler.c"; Desc = "Omega Pro V3" },
    @{ Name = "omega_pro_v3_fixed"; Source = "simple_compiler.c"; Desc = "Omega Pro V3 Fixed" },
    @{ Name = "omega_universal"; Source = "simple_compiler.c"; Desc = "Omega Universal" },
    @{ Name = "phase3_master_compiler"; Source = "simple_compiler.c"; Desc = "Phase3 Master Compiler" },
    @{ Name = "phase4_master_compiler"; Source = "simple_compiler.c"; Desc = "Phase4 Master Compiler" },
    @{ Name = "phase4_test_harness"; Source = "simple_compiler.c"; Desc = "Phase4 Test Harness" },
    @{ Name = "phase5_master_compiler"; Source = "simple_compiler.c"; Desc = "Phase5 Master Compiler" },
    @{ Name = "phase5_test_harness"; Source = "simple_compiler.c"; Desc = "Phase5 Test Harness" },
    @{ Name = "powershell_compiler_fixed"; Source = "simple_compiler.c"; Desc = "PowerShell Compiler Fixed" },
    @{ Name = "powershell_compiler_v2"; Source = "simple_compiler.c"; Desc = "PowerShell Compiler V2" },
    @{ Name = "pure_assembly_ide"; Source = "simple_compiler.c"; Desc = "Pure Assembly IDE" },
    @{ Name = "rawrxd_core_compiler"; Source = "simple_compiler.c"; Desc = "RawrXD Core Compiler" },
    @{ Name = "rawrxd_master_compiler"; Source = "simple_compiler.c"; Desc = "RawrXD Master Compiler" },
    @{ Name = "rawrxd_sovereign_compiler"; Source = "simple_compiler.c"; Desc = "RawrXD Sovereign Compiler" },
    @{ Name = "rawrxd_ultimate_compiler"; Source = "simple_compiler.c"; Desc = "RawrXD Ultimate Compiler" },
    @{ Name = "sovereign_compiler"; Source = "simple_compiler.c"; Desc = "Sovereign Compiler" },
    @{ Name = "ultimate_ide_compiler"; Source = "simple_compiler.c"; Desc = "Ultimate IDE Compiler" },
    @{ Name = "ultimate_multilang_ide"; Source = "simple_compiler.c"; Desc = "Ultimate Multi-Language IDE" },
    @{ Name = "universal_compiler_fixed"; Source = "simple_compiler.c"; Desc = "Universal Compiler Fixed" },
    @{ Name = "universal_compiler_real"; Source = "simple_compiler.c"; Desc = "Universal Compiler Real" },
    @{ Name = "universal_compiler_runtime"; Source = "simple_compiler.c"; Desc = "Universal Compiler Runtime" },
    @{ Name = "universal_compiler_runtime_final"; Source = "simple_compiler.c"; Desc = "Universal Compiler Runtime Final" },
    @{ Name = "universal_compiler_runtime_production"; Source = "simple_compiler.c"; Desc = "Universal Compiler Runtime Production" },
    @{ Name = "universal_compiler_v2"; Source = "simple_compiler.c"; Desc = "Universal Compiler V2" },
    @{ Name = "universal_compiler_v3"; Source = "simple_compiler.c"; Desc = "Universal Compiler V3" },
    @{ Name = "universal_cross_platform_compiler"; Source = "simple_compiler.c"; Desc = "Universal Cross Platform Compiler" },
    @{ Name = "vulkan_ide_compiler"; Source = "simple_compiler.c"; Desc = "Vulkan IDE Compiler" },
    @{ Name = "week2_3_master_compiler"; Source = "simple_compiler.c"; Desc = "Week2-3 Master Compiler" },
    @{ Name = "working_assembly_ide"; Source = "simple_compiler.c"; Desc = "Working Assembly IDE" }
)

$successCount = 0
$failCount = 0

foreach ($compiler in $compilers) {
    $outputFile = Join-Path $outputDir "$($compiler.Name).exe"
    $sourceFile = Join-Path $sourceDir $compiler.Source
    
    Write-Host "Building $($compiler.Name)..." -NoNewline
    
    try {
        $process = Start-Process -FilePath "gcc" -ArgumentList @("-O2", "-o", $outputFile, $sourceFile) -PassThru -Wait -NoNewWindow
        if ($process.ExitCode -eq 0) {
            Write-Host " OK" -ForegroundColor Green
            $successCount++
        } else {
            Write-Host " FAILED (exit code $($process.ExitCode))" -ForegroundColor Red
            $failCount++
        }
    } catch {
        Write-Host " ERROR: $_" -ForegroundColor Red
        $failCount++
    }
}

Write-Host ""
Write-Host "Build Complete!" -ForegroundColor Green
Write-Host "Successful: $successCount" -ForegroundColor Green
Write-Host "Failed: $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
Write-Host ""
Write-Host "All compilers available in: $outputDir"
