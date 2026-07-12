#==============================================================================
# build_unified_cli.ps1
# Build script for Sovereign Unified CLI
# Phase 8: Unified Runtime with Subsystem Registry
#==============================================================================

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Sovereign Unified CLI - Phase 8 Build" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$SRC_DIR = "d:\rawrxd\src"
$CORE_DIR = "$SRC_DIR\core"
$CLI_DIR = "$SRC_DIR\cli"
$ASM_DIR = "d:\src\asm"
$OUT_DIR = "d:\rawrxd\bin"
$OBJ_DIR = "d:\rawrxd\obj"
$VS_ROOT = "C:\Program Files\Microsoft Visual Studio\18\Enterprise"
$MSVC_VER = "14.51.36231"
$VS_TOOLS = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\bin\Hostx64\x64"

# Create directories
if (!(Test-Path $OUT_DIR)) {
    New-Item -ItemType Directory -Path $OUT_DIR -Force | Out-Null
}
if (!(Test-Path $OBJ_DIR)) {
    New-Item -ItemType Directory -Path $OBJ_DIR -Force | Out-Null
}

# Setup environment
$env:INCLUDE = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared;$ASM_DIR;$SRC_DIR"
$env:LIB = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64;$ASM_DIR"
$env:PATH = "$VS_TOOLS;$env:PATH"

# Tool paths
$CL = "$VS_TOOLS\cl.exe"
$LINK = "$VS_TOOLS\link.exe"

Write-Host "Building Unified CLI Components..." -ForegroundColor Yellow
Write-Host ""

# Compile Subsystem Registry
Write-Host "[1/4] Compiling SubsystemRegistry.cpp..." -NoNewline
$compileArgs = "/c", "/O2", "/W3", "/nologo", "/EHsc", "/MT", "/std:c++17", "/D_CRT_SECURE_NO_WARNINGS", "/I`"$ASM_DIR`"", "/I`"$SRC_DIR`"", "/Fo`"$OBJ_DIR\SovereignSubsystemRegistry.obj`"", "`"$CORE_DIR\SovereignSubsystemRegistry.cpp`""
$proc = Start-Process -FilePath $CL -ArgumentList $compileArgs -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -eq 0) { Write-Host " OK" -ForegroundColor Green }
else { Write-Host " FAILED" -ForegroundColor Red; exit 1 }

# Compile Roslyn Subsystem (included as header, skip separate compilation)
Write-Host "[2/4] Roslyn Subsystem (included via header)..." -NoNewline
Write-Host " SKIPPED (included in main)" -ForegroundColor Yellow

# Compile Unified CLI
Write-Host "[3/4] Compiling SovereignCLI_Unified.cpp..." -NoNewline
$compileArgs = "/c", "/O2", "/W3", "/nologo", "/EHsc", "/MT", "/std:c++17", "/D_CRT_SECURE_NO_WARNINGS", "/I`"$ASM_DIR`"", "/I`"$SRC_DIR`"", "/Fo`"$OBJ_DIR\SovereignCLI_Unified.obj`"", "`"$CLI_DIR\SovereignCLI_Unified.cpp`""
$proc = Start-Process -FilePath $CL -ArgumentList $compileArgs -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -eq 0) { Write-Host " OK" -ForegroundColor Green }
else { Write-Host " FAILED" -ForegroundColor Red; exit 1 }

# Link Unified CLI (14 MASM objects - working set)
Write-Host "[4/4] Linking SovereignCLI_Unified.exe (14 objects)..." -NoNewline
$linkArgs = "/SUBSYSTEM:CONSOLE", "/LARGEADDRESSAWARE:NO", `
    "/OUT:`"$OUT_DIR\SovereignCLI_Unified.exe`"", `
    "`"$OBJ_DIR\SovereignCLI_Unified.obj`"", `
    "`"$OBJ_DIR\SovereignSubsystemRegistry.obj`"", `
    "`"$ASM_DIR\Sovereign_RMSNorm.obj`"", `
    "`"$ASM_DIR\Sovereign_LayerNorm.obj`"", `
    "`"$ASM_DIR\Sovereign_ResidualAdd.obj`"", `
    "`"$ASM_DIR\Sovereign_RoPE.obj`"", `
    "`"$ASM_DIR\Sovereign_Q4K_Dequant.obj`"", `
    "`"$ASM_DIR\Sovereign_Q4Q8_MatMul_AVX512.obj`"", `
    "`"$ASM_DIR\Sovereign_Q4Q8_MatMul_Intrinsics.obj`"", `
    "`"$ASM_DIR\Sovereign_FlashAttention_Intrinsics.obj`"", `
    "`"$ASM_DIR\Sovereign_Attention_Scoring.obj`"", `
    "`"$ASM_DIR\Sovereign_Sampler.obj`"", `
    "`"$ASM_DIR\Sovereign_Version.obj`"", `
    "`"$ASM_DIR\Sovereign_Legacy_Kernels.obj`"", `
    "`"$ASM_DIR\Sovereign_Dequant.obj`"", `
    "`"$ASM_DIR\Sovereign_GEMM_Stub.obj`"", `
    "libcmt.lib", "libvcruntime.lib", "libucrt.lib", `
    "kernel32.lib", "user32.lib", "shell32.lib"
$proc = Start-Process -FilePath $LINK -ArgumentList $linkArgs -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -eq 0) { Write-Host " OK" -ForegroundColor Green }
else { Write-Host " FAILED" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "Build Complete" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Output: $OUT_DIR\SovereignCLI_Unified.exe" -ForegroundColor White
Write-Host ""
Write-Host "This build includes:" -ForegroundColor Gray
Write-Host "  - Subsystem Registry (10 subsystems)" -ForegroundColor Gray
Write-Host "  - Unified Command Router" -ForegroundColor Gray
Write-Host "  - Auto-routing for kernel/roslyn/java/codexpro/sunshine/titan/vulkan" -ForegroundColor Gray
Write-Host "  - JSON output for all subsystems" -ForegroundColor Gray
Write-Host ""
