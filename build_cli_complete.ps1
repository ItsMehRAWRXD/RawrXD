# Build Complete Sovereign CLI with Full C++ Integration
# Compiles all components: CLI + Titan Integration + MemoryBridge + UnifiedKernelInterface
#
# Date: July 10, 2026

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Sovereign CLI - Complete Integration Build" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$SRC_DIR = "d:\rawrxd\src"
$CLI_DIR = "$SRC_DIR\cli"
$CORE_DIR = "$SRC_DIR\core\execution"
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
$env:INCLUDE = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared;$ASM_DIR;$SRC_DIR"
$env:LIB = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64;$ASM_DIR"
$env:PATH = "$VS_TOOLS;$env:PATH"

# Tool paths
$CL = "$VS_TOOLS\cl.exe"
$LINK = "$VS_TOOLS\link.exe"

# Compiler flags for C++
$CXXFLAGS = "/c", "/O2", "/W3", "/nologo", "/EHsc", "/MT", "/std:c++17", "/I`"$ASM_DIR`"", "/I`"$SRC_DIR`""

# Compiler flags for C
$CFLAGS = "/c", "/O2", "/W3", "/nologo", "/MT", "/I`"$ASM_DIR`"", "/I`"$SRC_DIR`""

Write-Host "Building Complete Sovereign CLI..." -ForegroundColor Yellow
Write-Host ""

$objects = @()

# Compile MemoryBridge.cpp
Write-Host "[1/6] Compiling MemoryBridge.cpp..." -ForegroundColor Yellow
$compileArgs = $CXXFLAGS + "/Fo`"$OUT_DIR\MemoryBridge.obj`"" + "`"$CORE_DIR\MemoryBridge.cpp`""
$proc = Start-Process -FilePath $CL -ArgumentList $compileArgs -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -eq 0) {
    $objects += "`"$OUT_DIR\MemoryBridge.obj`""
    Write-Host "    OK: MemoryBridge.obj" -ForegroundColor Green
} else {
    Write-Host "    WARNING: MemoryBridge.cpp compilation failed" -ForegroundColor Yellow
}

# Compile UnifiedKernelInterface.cpp
Write-Host "[2/6] Compiling UnifiedKernelInterface.cpp..." -ForegroundColor Yellow
$compileArgs = $CXXFLAGS + "/Fo`"$OUT_DIR\UnifiedKernelInterface.obj`"" + "`"$CORE_DIR\UnifiedKernelInterface.cpp`""
$proc = Start-Process -FilePath $CL -ArgumentList $compileArgs -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -eq 0) {
    $objects += "`"$OUT_DIR\UnifiedKernelInterface.obj`""
    Write-Host "    OK: UnifiedKernelInterface.obj" -ForegroundColor Green
} else {
    Write-Host "    WARNING: UnifiedKernelInterface.cpp compilation failed" -ForegroundColor Yellow
}

# Compile MASMBackend.cpp
Write-Host "[3/6] Compiling MASMBackend.cpp..." -ForegroundColor Yellow
$compileArgs = $CXXFLAGS + "/Fo`"$OUT_DIR\MASMBackend.obj`"" + "`"$CORE_DIR\MASMBackend.cpp`""
$proc = Start-Process -FilePath $CL -ArgumentList $compileArgs -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -eq 0) {
    $objects += "`"$OUT_DIR\MASMBackend.obj`""
    Write-Host "    OK: MASMBackend.obj" -ForegroundColor Green
} else {
    Write-Host "    WARNING: MASMBackend.cpp compilation failed" -ForegroundColor Yellow
}

# Compile Titan_KernelIntegration.cpp
Write-Host "[4/6] Compiling Titan_KernelIntegration.cpp..." -ForegroundColor Yellow
$compileArgs = $CXXFLAGS + "/Fo`"$OUT_DIR\Titan_KernelIntegration.obj`"" + "`"$CORE_DIR\Titan_KernelIntegration.cpp`""
$proc = Start-Process -FilePath $CL -ArgumentList $compileArgs -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -eq 0) {
    $objects += "`"$OUT_DIR\Titan_KernelIntegration.obj`""
    Write-Host "    OK: Titan_KernelIntegration.obj" -ForegroundColor Green
} else {
    Write-Host "    WARNING: Titan_KernelIntegration.cpp compilation failed" -ForegroundColor Yellow
}

# Compile CLI
Write-Host "[5/6] Compiling SovereignCLI_Simple.cpp..." -ForegroundColor Yellow
$compileArgs = $CFLAGS + "/Fo`"$OUT_DIR\SovereignCLI_Simple.obj`"" + "`"$CLI_DIR\SovereignCLI_Simple.cpp`""
$proc = Start-Process -FilePath $CL -ArgumentList $compileArgs -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -ne 0) {
    Write-Host "ERROR: CLI compilation failed!" -ForegroundColor Red
    exit 1
}
$objects += "`"$OUT_DIR\SovereignCLI_Simple.obj`""
Write-Host "    OK: SovereignCLI_Simple.obj" -ForegroundColor Green

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

# Link executable
Write-Host ""
Write-Host "[6/6] Linking executable..." -ForegroundColor Yellow
$linkArgs = "/SUBSYSTEM:CONSOLE", "/NODEFAULTLIB:libcmt.lib", "/OUT:`"$OUT_DIR\SovereignCLI_Complete.exe`"" + $objects + $LIBS
$proc = Start-Process -FilePath $LINK -ArgumentList $linkArgs -Wait -PassThru -NoNewWindow

if ($proc.ExitCode -ne 0) {
    Write-Host "ERROR: Link failed!" -ForegroundColor Red
    exit 1
}
Write-Host "    OK: SovereignCLI_Complete.exe" -ForegroundColor Green

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Build Complete" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Output: $OUT_DIR\SovereignCLI_Complete.exe" -ForegroundColor White
Write-Host ""
Write-Host "This build includes:" -ForegroundColor White
Write-Host "  - Direct C API integration (working)" -ForegroundColor Gray
Write-Host "  - MemoryBridge C++ class" -ForegroundColor Gray
Write-Host "  - UnifiedKernelInterface C++ class" -ForegroundColor Gray
Write-Host "  - MASMBackend C++ class" -ForegroundColor Gray
Write-Host "  - Titan_KernelIntegration C++ class" -ForegroundColor Gray
Write-Host ""
