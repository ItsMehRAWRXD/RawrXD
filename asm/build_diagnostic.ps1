# Build Kernel Loading Diagnostic
# PowerShell version to handle paths with spaces
#
# Date: July 10, 2026

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Kernel Loading Diagnostic Build" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$SRC_DIR = "d:\src\asm"
$OUT_DIR = "$SRC_DIR\bin"
$VS_ROOT = "C:\Program Files\Microsoft Visual Studio\18\Enterprise"
$MSVC_VER = "14.51.36231"
$VS_TOOLS = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\bin\Hostx64\x64"

# Create output directory
if (!(Test-Path $OUT_DIR)) {
    New-Item -ItemType Directory -Path $OUT_DIR -Force | Out-Null
}

# Setup environment
$env:INCLUDE = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared"
$env:LIB = "$VS_ROOT\VC\Tools\MSVC\$MSVC_VER\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
$env:PATH = "$VS_TOOLS;$env:PATH"

# Tool paths
$CL = "$VS_TOOLS\cl.exe"

# Compiler flags
$CFLAGS = "/EHsc", "/O2", "/W3", "/nologo", "/MD"

Write-Host "[1/1] Compiling diagnose_kernel_loading.cpp..." -ForegroundColor Yellow

$compileArgs = $CFLAGS + "/Fo$OUT_DIR\diagnose_kernel_loading.obj" + "/Fe$OUT_DIR\diagnose_kernel_loading.exe" + "$SRC_DIR\diagnose_kernel_loading.cpp"
$proc = Start-Process -FilePath $CL -ArgumentList $compileArgs -Wait -PassThru -NoNewWindow

if ($proc.ExitCode -ne 0) {
    Write-Host "ERROR: Compilation failed!" -ForegroundColor Red
    exit 1
}

Write-Host "    OK: diagnose_kernel_loading.exe" -ForegroundColor Green

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Build Complete" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Run the diagnostic with:" -ForegroundColor White
Write-Host "  $OUT_DIR\diagnose_kernel_loading.exe" -ForegroundColor Yellow
Write-Host ""
Write-Host "This will check:" -ForegroundColor White
Write-Host "  - Library file existence" -ForegroundColor Gray
Write-Host "  - Export table inspection" -ForegroundColor Gray
Write-Host "  - Function pointer loading" -ForegroundColor Gray
Write-Host "  - Direct kernel calls" -ForegroundColor Gray
Write-Host ""
