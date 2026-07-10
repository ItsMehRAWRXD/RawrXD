# Build Integrated Sovereign CLI
# Full Phase 7 integration: MASM + Memory Bridge + Kernel Registry
#
# Date: July 10, 2026

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Sovereign CLI - Phase 7 Complete Integration" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$SRC_DIR = "d:\rawrxd\src"
$ASM_DIR = "d:\src\asm"
$OUT_DIR = "d:\rawrxd\bin"
$VS_ROOT = "C:\Program Files\Microsoft Visual Studio\18\Enterprise"
$MSVC_VER = "14.51.36231"
$VS_TOOLS = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\bin\Hostx64\x64"

# Create output directory
if (!(Test-Path $OUT_DIR)) {
    New-Item -ItemType Directory -Path $OUT_DIR -Force | Out-Null
}

# Setup environment
$env:INCLUDE = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared;$SRC_DIR;$ASM_DIR"
$env:LIB = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64;$ASM_DIR"
$env:PATH = "$VS_TOOLS;$env:PATH"

# Tool paths
$CL = "$VS_TOOLS\cl.exe"
$LINK = "$VS_TOOLS\link.exe"

# Compiler flags
$CFLAGS = "/c", "/O2", "/W3", "/nologo", "/EHsc", "/MD", "/I`"$SRC_DIR`"", "/I`"$ASM_DIR`""

# Library files
$LIBS = @(
    "`"$ASM_DIR\Sovereign_RMSNorm.lib`"",
    "`"$ASM_DIR\Sovereign_LayerNorm.lib`"",
    "`"$ASM_DIR\Sovereign_ResidualAdd.lib`"",
    "`"$ASM_DIR\Sovereign_RoPE.lib`"",
    "`"$ASM_DIR\Sovereign_Q4K_Dequant.lib`"",
    "`"$ASM_DIR\Sovereign_Legacy_Kernels.lib`"",
    "`"$ASM_DIR\Sovereign_Intrinsics.lib`"",
    "`"$ASM_DIR\SovereignMemoryBridge.lib`"",
    "kernel32.lib",
    "user32.lib"
)

Write-Host "Building Sovereign CLI..." -ForegroundColor Yellow
Write-Host ""

# Compile CLI
Write-Host "[1/1] Compiling SovereignCLI_Integrated.cpp..." -ForegroundColor Yellow
$compileArgs = $CFLAGS + "/Fo`"$OUT_DIR\SovereignCLI_Integrated.obj`"" + "`"$SRC_DIR\cli\SovereignCLI_Integrated.cpp`""
$proc = Start-Process -FilePath $CL -ArgumentList $compileArgs -Wait -PassThru -NoNewWindow

if ($proc.ExitCode -ne 0) {
    Write-Host "ERROR: CLI compilation failed!" -ForegroundColor Red
    exit 1
}
Write-Host "    OK: SovereignCLI_Integrated.obj" -ForegroundColor Green

# Link executable
Write-Host ""
Write-Host "[2/2] Linking executable..." -ForegroundColor Yellow
$linkArgs = "/SUBSYSTEM:CONSOLE", "/NODEFAULTLIB:libcmt.lib", "/OUT:`"$OUT_DIR\SovereignCLI.exe`"", "`"$OUT_DIR\SovereignCLI_Integrated.obj`"" + $LIBS
$proc = Start-Process -FilePath $LINK -ArgumentList $linkArgs -Wait -PassThru -NoNewWindow

if ($proc.ExitCode -ne 0) {
    Write-Host "ERROR: Link failed!" -ForegroundColor Red
    exit 1
}
Write-Host "    OK: SovereignCLI.exe" -ForegroundColor Green

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Build Complete" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Output: $OUT_DIR\SovereignCLI.exe" -ForegroundColor White
Write-Host ""
Write-Host "Usage:" -ForegroundColor White
Write-Host "  SovereignCLI.exe status      - Show system status" -ForegroundColor Gray
Write-Host "  SovereignCLI.exe benchmark   - Run kernel benchmarks" -ForegroundColor Gray
Write-Host "  SovereignCLI.exe validate    - Validate kernel correctness" -ForegroundColor Gray
Write-Host "  SovereignCLI.exe memory      - Show memory bridge status" -ForegroundColor Gray
Write-Host ""
