# RawrXD_Error_Recovery_Test_Build.ps1
# Build and run error recovery test suite using GCC

param(
    [switch]$Clean,
    [switch]$Run,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Paths
$MASM_PATH = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$GCC_PATH = "C:\ProgramData\mingw64\mingw64\bin\gcc.exe"
$SRC_DIR = "D:\RawrXD"
$OBJ_DIR = "$SRC_DIR\obj"
$BIN_DIR = "$SRC_DIR\bin"

# Create directories
if (!(Test-Path $OBJ_DIR)) { New-Item -ItemType Directory -Path $OBJ_DIR -Force | Out-Null }
if (!(Test-Path $BIN_DIR)) { New-Item -ItemType Directory -Path $BIN_DIR -Force | Out-Null }

# Clean if requested
if ($Clean) {
    Write-Host "Cleaning build artifacts..." -ForegroundColor Yellow
    Remove-Item "$OBJ_DIR\*" -ErrorAction SilentlyContinue
    Remove-Item "$BIN_DIR\*" -ErrorAction SilentlyContinue
}

Write-Host "Building RawrXD Error Recovery Test Suite..." -ForegroundColor Cyan
Write-Host ""

# Assemble error recovery module
Write-Host "[1/2] Assembling RawrXD_Error_Recovery.asm..." -NoNewline
try {
    $asmResult = & $MASM_PATH `
        /c /W3 /nologo /Zi `
        /Fo "$OBJ_DIR\RawrXD_Error_Recovery.obj" `
        "$SRC_DIR\RawrXD_Error_Recovery.asm" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host $asmResult
        exit 1
    }
    Write-Host " OK" -ForegroundColor Green
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host $_
    exit 1
}

# Compile C test harness
Write-Host "[2/2] Compiling RawrXD_Error_Recovery_Test.c..." -NoNewline
try {
    $cResult = & $GCC_PATH `
        -O2 -Wall `
        -o "$BIN_DIR\RawrXD_Error_Recovery_Test.exe" `
        "$SRC_DIR\RawrXD_Error_Recovery_Test.c" `
        "$OBJ_DIR\RawrXD_Error_Recovery.obj" `
        -lkernel32 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host $cResult
        exit 1
    }
    Write-Host " OK" -ForegroundColor Green
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host $_
    exit 1
} `
    /Fe "$BIN_DIR\RawrXD_Error_Recovery_Test.exe" `
    "$SRC_DIR\RawrXD_Error_Recovery_Test.c" `
    "$OBJ_DIR\RawrXD_Error_Recovery.obj" `
    kernel32.lib `
    /link /SUBSYSTEM:CONSOLE 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host $clResult
    exit 1
}
Write-Host " OK" -ForegroundColor Green

Write-Host ""
Write-Host "Build successful!" -ForegroundColor Green
Write-Host "  Binary: $BIN_DIR\RawrXD_Error_Recovery_Test.exe" -ForegroundColor Gray

# Run if requested
if ($Run) {
    Write-Host ""
    Write-Host "Running test suite..." -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor DarkGray
    & "$BIN_DIR\RawrXD_Error_Recovery_Test.exe"
    $testExit = $LASTEXITCODE
    Write-Host "========================================" -ForegroundColor DarkGray
    
    if ($testExit -eq 0) {
        Write-Host "All tests passed!" -ForegroundColor Green
    } else {
        Write-Host "Some tests failed (exit code: $testExit)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Usage:" -ForegroundColor Yellow
Write-Host "  .\RawrXD_Error_Recovery_Test_Build.ps1 -Run    # Build and run tests"
Write-Host "  .\RawrXD_Error_Recovery_Test_Build.ps1 -Clean  # Clean build"
