# Build script for minimal CLI using MSVC
# Links against the actual kernel .lib files

Write-Host "=============================================================================="
Write-Host "Sovereign CLI Minimal Build - Phase 7C.2"
Write-Host "=============================================================================="
Write-Host ""

# Configuration
$BuildDir = "d:\rawrxd\build_cli"
$AsmDir = "d:\src\asm"
$SourceFile = "d:\rawrxd\cli_minimal.cpp"

# MSVC paths
$MSVC_ROOT = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"
$WINSDK_INC = "C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0"
$WINSDK_LIB = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0"

$CL = Join-Path $MSVC_ROOT "bin\Hostx64\x64\cl.exe"
$LINK = Join-Path $MSVC_ROOT "bin\Hostx64\x64\link.exe"

Write-Host "Using MSVC: $MSVC_ROOT"
Write-Host ""

# Create build directory
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
}

# Determine which source file to build
if ($args.Count -gt 0 -and $args[0] -eq "phase7d") {
    $SourceFile = "d:\rawrxd\cli_phase7d.cpp"
    $OutputName = "SovereignCLI_Phase7D.exe"
} elseif ($args.Count -gt 0 -and $args[0] -eq "phase7e") {
    $SourceFile = "d:\rawrxd\cli_phase7e.cpp"
    $OutputName = "SovereignCLI_Phase7E.exe"
} else {
    $SourceFile = "d:\rawrxd\cli_full.cpp"
    $OutputName = "SovereignCLI.exe"
}

# Build CLI main and dispatch
Write-Host "[1/3] Compiling cli_full.cpp..."

$CompileArgs = @(
    "/std:c++17", "/O2", "/arch:AVX2", "/DNDEBUG", "/D_WIN32", "/EHsc", "/W3", "/nologo", "/c",
    "/I$($MSVC_ROOT)\include",
    "/I$($WINSDK_INC)\um",
    "/I$($WINSDK_INC)\shared",
    "/I$($WINSDK_INC)\ucrt",
    $SourceFile,
    "/Fo$($BuildDir)\cli_full.obj"
)

& $CL @CompileArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED: cli_full.cpp compilation" -ForegroundColor Red
    exit 1
}
Write-Host "> cli_full.obj compiled"
Write-Host ""

Write-Host "[2/3] Compiling Sovereign_KernelDispatch.cpp..."

$DispatchCompileArgs = @(
    "/std:c++17", "/O2", "/arch:AVX2", "/DNDEBUG", "/D_WIN32", "/EHsc", "/W3", "/nologo", "/c",
    "/I$($MSVC_ROOT)\include",
    "/I$($WINSDK_INC)\um",
    "/I$($WINSDK_INC)\shared",
    "/I$($WINSDK_INC)\ucrt",
    "$($AsmDir)\Sovereign_KernelDispatch.cpp",
    "/Fo$($BuildDir)\Sovereign_KernelDispatch.obj"
)

& $CL @DispatchCompileArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED: Sovereign_KernelDispatch.cpp compilation" -ForegroundColor Red
    exit 1
}
Write-Host "> Sovereign_KernelDispatch.obj compiled"
Write-Host ""

# Link with kernel libraries
Write-Host "[3/3] Linking $OutputName..."
Write-Host ""

$LinkArgs = @(
    "/OUT:$($BuildDir)\$OutputName",
    "/SUBSYSTEM:CONSOLE", "/MACHINE:X64", "/nologo",
    "/LIBPATH:$($MSVC_ROOT)\lib\x64",
    "/LIBPATH:$($WINSDK_LIB)\um\x64",
    "/LIBPATH:$($WINSDK_LIB)\ucrt\x64",
    "$($BuildDir)\cli_full.obj",
    "$($BuildDir)\Sovereign_KernelDispatch.obj",
    "$($AsmDir)\Sovereign_Legacy_Kernels.lib",
    "$($AsmDir)\Sovereign_Intrinsics.lib",
    "$($AsmDir)\Sovereign_RMSNorm.lib",
    "$($AsmDir)\Sovereign_ResidualAdd.lib",
    "$($AsmDir)\Sovereign_RoPE.lib",
    "$($AsmDir)\Sovereign_LayerNorm.lib",
    "$($AsmDir)\Sovereign_Q4K_Dequant.lib",
    "kernel32.lib", "user32.lib", "ucrt.lib", "vcruntime.lib", "msvcrt.lib"
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
Write-Host "Output: $($BuildDir)\$OutputName"
Write-Host ""
Write-Host "Run with:"
Write-Host "  $($BuildDir)\$OutputName test"
Write-Host "  $($BuildDir)\$OutputName validate"
Write-Host "  $($BuildDir)\$OutputName backends"
Write-Host "  $($BuildDir)\$OutputName info"
Write-Host "=============================================================================="
