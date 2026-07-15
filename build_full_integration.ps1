# Full Integration Build Script for Sovereign CLI
# Phase 7C.2 - Complete MASM Backend Integration

Write-Host "=============================================================================="
Write-Host "Sovereign Full Integration Build - Phase 7C.2"
Write-Host "=============================================================================="
Write-Host ""

# Configuration
$BuildDir = "d:\rawrxd\build_cli"
$SrcDir = "d:\rawrxd\src"
$AsmDir = "d:\src\asm"

# MSVC paths
$MSVC_ROOT = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"
$WINSDK_INC = "C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0"
$WINSDK_LIB = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0"

$CL = Join-Path $MSVC_ROOT "bin\Hostx64\x64\cl.exe"
$LINK = Join-Path $MSVC_ROOT "bin\Hostx64\x64\link.exe"

Write-Host "Using MSVC: $MSVC_ROOT"
Write-Host "Build Directory: $BuildDir"
Write-Host ""

# Create build directory
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
}

# Include paths
$Includes = @(
    "/I$($MSVC_ROOT)\include",
    "/I$($WINSDK_INC)\um",
    "/I$($WINSDK_INC)\shared",
    "/I$($WINSDK_INC)\ucrt",
    "/I$($SrcDir)",
    "/I$($SrcDir)\core\execution",
    "/I$($AsmDir)"
)

# Compiler flags
$CXXFLAGS = @("/std:c++17", "/O2", "/arch:AVX2", "/DNDEBUG", "/D_WIN32", "/EHsc", "/W3", "/nologo", "/c")

# Source files to compile
$Sources = @(
    @{File="$($SrcDir)\core\execution\MASMBackend.cpp"; Obj="MASMBackend.obj"},
    @{File="$($SrcDir)\core\execution\ReferenceBackend.cpp"; Obj="ReferenceBackend.obj"},
    @{File="$($SrcDir)\core\execution\IntrinsicsBackend.cpp"; Obj="IntrinsicsBackend.obj"},
    @{File="$($SrcDir)\core\execution\KernelRegistry.cpp"; Obj="KernelRegistry.obj"},
    @{File="$($SrcDir)\core\execution\SovereignGraphRunner_v2.cpp"; Obj="SovereignGraphRunner_v2.obj"},
    @{File="$($AsmDir)\Sovereign_KernelDispatch.cpp"; Obj="Sovereign_KernelDispatch.obj"},
    @{File="d:\rawrxd\cli_full.cpp"; Obj="cli_full.obj"}
)

# Compile each source file
$Objects = @()
$Index = 0
foreach ($Source in $Sources) {
    $Index++
    $ObjPath = "$($BuildDir)\$($Source.Obj)"
    $Objects += $ObjPath
    
    Write-Host "[$Index/$($Sources.Count)] Compiling $($Source.File)..."
    
    $CompileArgs = $CXXFLAGS + $Includes + @($Source.File, "/Fo$ObjPath")
    & $CL @CompileArgs
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: Compilation of $($Source.File)" -ForegroundColor Red
        exit 1
    }
    Write-Host "  > $($Source.Obj)"
}

Write-Host ""

# Link everything
Write-Host "Linking SovereignCLI_Full.exe..."
Write-Host ""

$LinkArgs = @(
    "/OUT:$($BuildDir)\SovereignCLI_Full.exe",
    "/SUBSYSTEM:CONSOLE",
    "/MACHINE:X64",
    "/nologo",
    "/LIBPATH:$($MSVC_ROOT)\lib\x64",
    "/LIBPATH:$($WINSDK_LIB)\um\x64",
    "/LIBPATH:$($WINSDK_LIB)\ucrt\x64",
    "/LIBPATH:$($AsmDir)"
) + $Objects + @(
    "Sovereign_Legacy_Kernels.lib",
    "Sovereign_Intrinsics.lib",
    "Sovereign_RMSNorm.lib",
    "Sovereign_ResidualAdd.lib",
    "Sovereign_RoPE.lib",
    "Sovereign_LayerNorm.lib",
    "Sovereign_Q4K_Dequant.lib",
    "kernel32.lib",
    "user32.lib",
    "ucrt.lib",
    "vcruntime.lib",
    "msvcrt.lib"
)

& $LINK @LinkArgs

if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED: Linking" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=============================================================================="
Write-Host "BUILD SUCCESSFUL" -ForegroundColor Green
Write-Host "=============================================================================="
Write-Host ""
Write-Host "Output: $($BuildDir)\SovereignCLI_Full.exe"
Write-Host ""
Write-Host "Run with:"
Write-Host "  $($BuildDir)\SovereignCLI_Full.exe test"
Write-Host "  $($BuildDir)\SovereignCLI_Full.exe validate"
Write-Host "  $($BuildDir)\SovereignCLI_Full.exe backends"
Write-Host "  $($BuildDir)\SovereignCLI_Full.exe info"
Write-Host "=============================================================================="
