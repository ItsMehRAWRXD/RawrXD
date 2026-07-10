# Build Titan Kernel Integration
# Links Titan dispatch layer with real Sovereign kernels
#
# Date: July 10, 2026

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Titan Kernel Integration Build" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$SRC_DIR = "d:\rawrxd\src\core\execution"
$ASM_DIR = "d:\src\asm"
$OUT_DIR = "d:\rawrxd\bin"
$VS_ROOT = "C:\Program Files\Microsoft Visual Studio\18\Enterprise"
$MSVC_VER = "14.51.36231"
$VS_TOOLS = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\bin\Hostx64\x64"

# Create output directory
if (!(Test-Path $OUT_DIR)) {
    New-Item -ItemType Directory -Path $OUT_DIR -Force | Out-Null
}

# Setup environment (include Windows SDK)
$WINSDK_VER = "10.0.22621.0"
$WINSDK_ROOT = "C:\Program Files (x86)\Windows Kits\10"
$env:INCLUDE = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\include;$WINSDK_ROOT\Include\$WINSDK_VER\ucrt;$WINSDK_ROOT\Include\$WINSDK_VER\um;$WINSDK_ROOT\Include\$WINSDK_VER\shared;$env:INCLUDE"
$env:LIB = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\lib\x64;$WINSDK_ROOT\Lib\$WINSDK_VER\ucrt\x64;$WINSDK_ROOT\Lib\$WINSDK_VER\um\x64;$env:LIB"
$env:PATH = "$VS_TOOLS;$env:PATH"

# Tool paths
$CL = "$VS_TOOLS\cl.exe"
$LINK = "$VS_TOOLS\link.exe"
$LIB_TOOL = "$VS_TOOLS\lib.exe"

# Include paths
$INCLUDES = "/I`"$ASM_DIR`" /I`"$SRC_DIR`""

# Compiler flags
$CFLAGS = "/c /O2 /arch:AVX2 /W3 /nologo /EHsc /MD $INCLUDES"

# Linker flags
$LFLAGS = "/SUBSYSTEM:CONSOLE /NODEFAULTLIB:libcmt.lib /LARGEADDRESSAWARE"

# Library files to link
$LIBS = @(
    "`"$ASM_DIR\Sovereign_Intrinsics.lib`"",
    "`"$ASM_DIR\Sovereign_RMSNorm.lib`"",
    "`"$ASM_DIR\Sovereign_RoPE.lib`"",
    "`"$ASM_DIR\Sovereign_LayerNorm.lib`"",
    "`"$ASM_DIR\Sovereign_ResidualAdd.lib`"",
    "`"$ASM_DIR\Sovereign_Q4K_Dequant.lib`"",
    "`"$ASM_DIR\Sovereign_Legacy_Kernels.lib`"",
    "kernel32.lib",
    "user32.lib"
)

Write-Host "[1/3] Compiling Titan_KernelIntegration.cpp..." -ForegroundColor Yellow
$compileArgs = "$CFLAGS /Fo`"$OUT_DIR\Titan_KernelIntegration.obj`" `"$SRC_DIR\Titan_KernelIntegration.cpp`""
$proc = Start-Process -FilePath $CL -ArgumentList $compileArgs -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -ne 0) {
    Write-Host "ERROR: Compilation failed!" -ForegroundColor Red
    exit 1
}
Write-Host "    OK: Titan_KernelIntegration.obj" -ForegroundColor Green

Write-Host ""
Write-Host "[2/3] Creating Titan_KernelIntegration.lib..." -ForegroundColor Yellow
$libArgs = "/nologo /out:`"$OUT_DIR\Titan_KernelIntegration.lib`" `"$OUT_DIR\Titan_KernelIntegration.obj`""
$proc = Start-Process -FilePath $LIB_TOOL -ArgumentList $libArgs -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -ne 0) {
    Write-Host "ERROR: Library creation failed!" -ForegroundColor Red
    exit 1
}
Write-Host "    OK: Titan_KernelIntegration.lib" -ForegroundColor Green

Write-Host ""
Write-Host "[3/3] Building test executable..." -ForegroundColor Yellow
$testSource = "d:\rawrxd\test_titan_integration.cpp"
if (Test-Path $testSource) {
    $testCompileArgs = "$CFLAGS /Fo`"$OUT_DIR\test_titan_integration.obj`" `"$testSource`""
    $proc = Start-Process -FilePath $CL -ArgumentList $testCompileArgs -Wait -PassThru -NoNewWindow
    
    if ($proc.ExitCode -eq 0 -and (Test-Path "$OUT_DIR\test_titan_integration.obj")) {
        $linkArgs = "$LFLAGS /OUT:`"$OUT_DIR\test_titan_integration.exe`" `"$OUT_DIR\test_titan_integration.obj`" `"$OUT_DIR\Titan_KernelIntegration.obj`" $($LIBS -join ' ')"
        $proc = Start-Process -FilePath $LINK -ArgumentList $linkArgs -Wait -PassThru -NoNewWindow
        
        if ($proc.ExitCode -eq 0) {
            Write-Host "    OK: test_titan_integration.exe" -ForegroundColor Green
        } else {
            Write-Host "    WARNING: Test executable link failed" -ForegroundColor Yellow
        }
    } else {
        Write-Host "    WARNING: Test compilation failed" -ForegroundColor Yellow
    }
} else {
    Write-Host "    INFO: No test file found, skipping test executable" -ForegroundColor Gray
}

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Build Complete" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Output files:" -ForegroundColor White
Get-ChildItem "$OUT_DIR\Titan_KernelIntegration.*" | ForEach-Object { Write-Host "  $($_.Name)" }
Write-Host ""
Write-Host "Libraries linked:" -ForegroundColor White
Write-Host "  - Sovereign_Intrinsics.lib (Phase 7B)"
Write-Host "  - Sovereign_RMSNorm.lib"
Write-Host "  - Sovereign_RoPE.lib"
Write-Host "  - Sovereign_LayerNorm.lib"
Write-Host "  - Sovereign_ResidualAdd.lib"
Write-Host "  - Sovereign_Q4K_Dequant.lib"
Write-Host "  - Sovereign_Legacy_Kernels.lib (Phase 7A)"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Replace TitanStubs.cpp with Titan_KernelIntegration.cpp in your build"
Write-Host "  2. Link against Titan_KernelIntegration.lib"
Write-Host "  3. Call Titan_InitializeKernelSystem() before using kernels"
Write-Host "  4. Use Titan_ExecuteComputeKernel() with real computation"
Write-Host ""
