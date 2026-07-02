# ============================================================================
# Build Phase 11 Integration Test
# Links assembly loader with Phase 22-23 codebase
# ============================================================================

param(
    [switch]$Clean,
    [switch]$Run
)

$ErrorActionPreference = "Stop"

# Paths
$ROOT = "D:\RawrXD"
$BUILD_DIR = "$ROOT\build\phase11_test"
$LOADER_LIB = "$ROOT\build\120b_loader\RawrXD_120B_Loader.lib"
$LOADER_HDR = "$ROOT\build\120b_loader\RawrXD_120B_Loader.h"

# VS2022 paths
$VS_PATH = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"
$CL = "$VS_PATH\bin\Hostx64\x64\cl.exe"
$LINK = "$VS_PATH\bin\Hostx64\x64\link.exe"

# Verify assembly library exists
if (-not (Test-Path $LOADER_LIB)) {
    Write-Host "ERROR: Assembly library not found. Run build_120b_loader.ps1 first!" -ForegroundColor Red
    exit 1
}

Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Phase 11 Integration Test Build                               ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Clean if requested
if ($Clean -and (Test-Path $BUILD_DIR)) {
    Remove-Item -Recurse -Force $BUILD_DIR
    Write-Host "Cleaned build directory" -ForegroundColor Yellow
}

# Create build directory
New-Item -ItemType Directory -Force -Path $BUILD_DIR | Out-Null

# Source files
$SRC = "$ROOT\src\tests\phase11_integration_test.cpp"
$OBJ = "$BUILD_DIR\phase11_integration_test.obj"
$EXE = "$BUILD_DIR\phase11_integration_test.exe"

# Include paths
$INCLUDES = @(
    "/I`"$ROOT\src`"",
    "/I`"$ROOT\src\core`"",
    "/I`"$ROOT\src\swarm`"",
    "/I`"$ROOT\build\120b_loader`""
)

# Compiler flags
$CXXFLAGS = @(
    "/std:c++20",
    "/O2",              # Optimize for speed
    "/EHsc",            # Exception handling
    "/MD",              # Multi-threaded DLL runtime
    "/W3",              # Warning level 3
    "/nologo",
    "/Fo`"$OBJ`""
) + $INCLUDES

# Linker flags
$LDFLAGS = @(
    "/OUT:`"$EXE`"",
    "/LIBPATH:`"$ROOT\build\120b_loader`"",
    "RawrXD_120B_Loader.lib",
    "kernel32.lib",
    "user32.lib",
    "advapi32.lib",
    "/nologo"
)

# Compile
Write-Host "Compiling Phase 11 integration test..." -NoNewline
$compileProc = Start-Process -FilePath $CL -ArgumentList ($CXXFLAGS + "/c", "`"$SRC`"") `
    -WorkingDirectory $BUILD_DIR -PassThru -Wait -RedirectStandardOutput "$BUILD_DIR\compile.log" -RedirectStandardError "$BUILD_DIR\compile.err"

if ($compileProc.ExitCode -ne 0) {
    Write-Host " FAILED" -ForegroundColor Red
    Get-Content "$BUILD_DIR\compile.err" | Write-Host -ForegroundColor Red
    exit 1
}
Write-Host " OK" -ForegroundColor Green

# Link
Write-Host "Linking with assembly library..." -NoNewline
$linkProc = Start-Process -FilePath $LINK -ArgumentList ($LDFLAGS + "`"$OBJ`"") `
    -WorkingDirectory $BUILD_DIR -PassThru -Wait -RedirectStandardOutput "$BUILD_DIR\link.log" -RedirectStandardError "$BUILD_DIR\link.err"

if ($linkProc.ExitCode -ne 0) {
    Write-Host " FAILED" -ForegroundColor Red
    Get-Content "$BUILD_DIR\link.err" | Write-Host -ForegroundColor Red
    exit 1
}
Write-Host " OK" -ForegroundColor Green

Write-Host ""
Write-Host "Build Summary:" -ForegroundColor Cyan
Write-Host "  Executable: $EXE"
Write-Host "  Library: $LOADER_LIB"
Write-Host ""

# Run if requested
if ($Run) {
    Write-Host "Running Phase 11 integration test..." -ForegroundColor Cyan
    Write-Host ""
    
    $testProc = Start-Process -FilePath $EXE -WorkingDirectory $BUILD_DIR `
        -PassThru -Wait -NoNewWindow
    
    Write-Host ""
    if ($testProc.ExitCode -eq 0) {
        Write-Host "✅ Phase 11 integration test PASSED" -ForegroundColor Green
    } else {
        Write-Host "❌ Phase 11 integration test FAILED" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "To run manually: $EXE" -ForegroundColor Yellow
