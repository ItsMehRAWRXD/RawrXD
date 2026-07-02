# build_sovereign_engine.ps1
# Phase 22: Build script for Sovereign Engine Controller using available tools

$ErrorActionPreference = "Stop"

# Configuration
$PROJECT_ROOT = "D:\RawrXD"
$BUILD_DIR = "$PROJECT_ROOT\build"
$SRC_DIR = "$PROJECT_ROOT\src"
$ASM_DIR = "$PROJECT_ROOT\asm"

# Toolchain
$ML64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$GCC = "C:\ProgramData\mingw64\mingw64\bin\gcc.exe"
$GXX = "C:\ProgramData\mingw64\mingw64\bin\g++.exe"

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "Phase 11: Assembling x64 ASM Loader" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

# Create build directories
New-Item -ItemType Directory -Force -Path "$BUILD_DIR\obj" | Out-Null
New-Item -ItemType Directory -Force -Path "$BUILD_DIR\bin" | Out-Null

# Assemble Phase 11 loader
Write-Host "Assembling RawrXD_120B_Loader.asm..." -NoNewline
& $ML64 /c /W3 /nologo /Fo "$BUILD_DIR\obj\RawrXD_120B_Loader.obj" "$ASM_DIR\RawrXD_120B_Loader.asm"
if ($LASTEXITCODE -ne 0) {
    Write-Host " FAILED" -ForegroundColor Red
    exit 1
}
Write-Host " OK" -ForegroundColor Green

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "Phase 22: Compiling C++ Engine Core" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

# Compile C++ sources
$sources = @(
    "$SRC_DIR\core\sovereign_thread_pool.cpp"
    "$SRC_DIR\core\sovereign_engine_controller_integration.cpp"
)

foreach ($source in $sources) {
    if (Test-Path $source) {
        $obj_name = [System.IO.Path]::GetFileNameWithoutExtension($source) + ".obj"
        Write-Host "Compiling $obj_name..." -NoNewline
        
        & $GXX -c -O2 -std=c++17 -I"$SRC_DIR" -I"$SRC_DIR\core" -DNDEBUG -o "$BUILD_DIR\obj\$obj_name" $source 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host " FAILED" -ForegroundColor Red
            exit 1
        }
        Write-Host " OK" -ForegroundColor Green
    } else {
        Write-Host "Warning: $source not found, skipping..." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "Build Summary" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "Object files created:" -ForegroundColor Gray
Get-ChildItem "$BUILD_DIR\obj\*.obj" | ForEach-Object { Write-Host "  $($_.Name)" -ForegroundColor Gray }

Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green
Write-Host "  Build directory: $BUILD_DIR" -ForegroundColor Gray
Write-Host ""
Write-Host "Note: Linking step requires all object files including:" -ForegroundColor Yellow
Write-Host "  - RawrXD_120B_Loader.obj (Phase 11 ASM)" -ForegroundColor Yellow
Write-Host "  - sovereign_thread_pool.obj (Phase 22)" -ForegroundColor Yellow
Write-Host "  - sovereign_engine_controller_integration.obj (Phase 22)" -ForegroundColor Yellow
