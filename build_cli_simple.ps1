# Build Simple Sovereign CLI
# Links directly against MASM kernel libraries
#
# Date: July 10, 2026

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Sovereign CLI (Simple) - Phase 7 Complete" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$SRC_DIR = "d:\rawrxd\src\cli"
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
$env:INCLUDE = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared;$ASM_DIR"
$env:LIB = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64;$ASM_DIR"
$env:PATH = "$VS_TOOLS;$env:PATH"

# Tool paths
$CL = "$VS_TOOLS\cl.exe"
$LINK = "$VS_TOOLS\link.exe"

# Compiler flags
$CFLAGS = "/c", "/O2", "/W3", "/nologo", "/EHsc", "/MT", "/I`"$ASM_DIR`""

# Compile MemoryBridge if needed
$MEMORY_OBJ = "$ASM_DIR\SovereignMemoryBridge.obj"
if (!(Test-Path $MEMORY_OBJ)) {
    Write-Host "[0/2] Compiling SovereignMemoryBridge.cpp..." -ForegroundColor Yellow
    $mbCompileArgs = $CFLAGS + "/Fo`"$MEMORY_OBJ`"" + "`"$ASM_DIR\SovereignMemoryBridge.cpp`""
    $proc = Start-Process -FilePath $CL -ArgumentList $mbCompileArgs -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) {
        Write-Host "WARNING: MemoryBridge compilation failed, memory command will be unavailable" -ForegroundColor Yellow
    } else {
        Write-Host "    OK: SovereignMemoryBridge.obj" -ForegroundColor Green
    }
}

# Library files
$LIBS = @(
    "`"$ASM_DIR\Sovereign_KernelDispatch.obj`"",
    "`"$ASM_DIR\Sovereign_RMSNorm.lib`"",
    "`"$ASM_DIR\Sovereign_LayerNorm.lib`"",
    "`"$ASM_DIR\Sovereign_ResidualAdd.lib`"",
    "`"$ASM_DIR\Sovereign_RoPE.lib`"",
    "`"$ASM_DIR\Sovereign_Q4K_Dequant.lib`"",
    "`"$ASM_DIR\Sovereign_Legacy_Kernels.lib`"",
    "`"$ASM_DIR\Sovereign_Intrinsics.lib`"",
    "libcmt.lib",
    "libvcruntime.lib",
    "libucrt.lib",
    "kernel32.lib",
    "user32.lib"
)



Write-Host "Building Sovereign CLI (Simple)..." -ForegroundColor Yellow
Write-Host ""

# Compile CLI
Write-Host "[1/2] Compiling SovereignCLI_Simple.cpp..." -ForegroundColor Yellow
$compileArgs = $CFLAGS + "/Fo`"$OUT_DIR\SovereignCLI_Simple.obj`"" + "`"$SRC_DIR\SovereignCLI_Simple.cpp`""
$proc = Start-Process -FilePath $CL -ArgumentList $compileArgs -Wait -PassThru -NoNewWindow

if ($proc.ExitCode -ne 0) {
    Write-Host "ERROR: CLI compilation failed!" -ForegroundColor Red
    exit 1
}
Write-Host "    OK: SovereignCLI_Simple.obj" -ForegroundColor Green

# Link executable
Write-Host ""
Write-Host "[2/2] Linking executable..." -ForegroundColor Yellow
$linkArgs = "/SUBSYSTEM:CONSOLE", "/NODEFAULTLIB:libcmt.lib", "/OUT:`"$OUT_DIR\SovereignCLI.exe`"", "`"$OUT_DIR\SovereignCLI_Simple.obj`"" + $LIBS
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
Write-Host "  SovereignCLI.exe status      - Show kernel status" -ForegroundColor Gray
Write-Host "  SovereignCLI.exe benchmark   - Run kernel benchmarks" -ForegroundColor Gray
Write-Host "  SovereignCLI.exe validate    - Validate kernel correctness" -ForegroundColor Gray
Write-Host "  SovereignCLI.exe test        - Run all tests" -ForegroundColor Gray
Write-Host ""
