# Build MASM Backend with proper library linking
# Links MASMBackend against all Sovereign kernel libraries
#
# Date: July 10, 2026

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "MASM Backend Build with Kernel Libraries" -ForegroundColor Cyan
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

# Setup environment
$env:INCLUDE = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared;$ASM_DIR"
$env:LIB = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64;$ASM_DIR"
$env:PATH = "$VS_TOOLS;$env:PATH"

# Tool paths
$CL = "$VS_TOOLS\cl.exe"
$LINK = "$VS_TOOLS\link.exe"

# Compiler flags
$CFLAGS = "/c", "/O2", "/W3", "/nologo", "/EHsc", "/MD", "/I`"$SRC_DIR`"", "/I`"$ASM_DIR`""

# Library files to link
$LIBS = @(
    "`"$ASM_DIR\Sovereign_RMSNorm.lib`"",
    "`"$ASM_DIR\Sovereign_LayerNorm.lib`"",
    "`"$ASM_DIR\Sovereign_ResidualAdd.lib`"",
    "`"$ASM_DIR\Sovereign_RoPE.lib`"",
    "`"$ASM_DIR\Sovereign_Q4K_Dequant.lib`"",
    "`"$ASM_DIR\Sovereign_Legacy_Kernels.lib`"",
    "`"$ASM_DIR\Sovereign_Intrinsics.lib`"",
    "kernel32.lib",
    "user32.lib"
)

Write-Host "[1/2] Compiling MASMBackend.cpp..." -ForegroundColor Yellow
$compileArgs = $CFLAGS + "/Fo`"$OUT_DIR\MASMBackend.obj`"" + "`"$SRC_DIR\MASMBackend.cpp`""
$proc = Start-Process -FilePath $CL -ArgumentList $compileArgs -Wait -PassThru -NoNewWindow

if ($proc.ExitCode -ne 0) {
    Write-Host "ERROR: MASMBackend compilation failed!" -ForegroundColor Red
    exit 1
}
Write-Host "    OK: MASMBackend.obj" -ForegroundColor Green

Write-Host ""
Write-Host "[2/2] Creating MASMBackend static library..." -ForegroundColor Yellow
$libArgs = "/nologo", "/out:`"$OUT_DIR\MASMBackend.lib`"", "`"$OUT_DIR\MASMBackend.obj`""
$proc = Start-Process -FilePath "$VS_TOOLS\lib.exe" -ArgumentList $libArgs -Wait -PassThru -NoNewWindow

if ($proc.ExitCode -ne 0) {
    Write-Host "ERROR: Library creation failed!" -ForegroundColor Red
    exit 1
}
Write-Host "    OK: MASMBackend.lib" -ForegroundColor Green

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Build Complete" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Output files:" -ForegroundColor White
Get-ChildItem "$OUT_DIR\MASMBackend.*" | ForEach-Object { Write-Host "  $($_.Name)" }
Write-Host ""
Write-Host "Linked libraries:" -ForegroundColor White
Write-Host "  - Sovereign_RMSNorm.lib"
Write-Host "  - Sovereign_LayerNorm.lib"
Write-Host "  - Sovereign_ResidualAdd.lib"
Write-Host "  - Sovereign_RoPE.lib"
Write-Host "  - Sovereign_Q4K_Dequant.lib"
Write-Host "  - Sovereign_Legacy_Kernels.lib"
Write-Host "  - Sovereign_Intrinsics.lib"
Write-Host ""
Write-Host "Next: Build test executable" -ForegroundColor White
Write-Host ""
