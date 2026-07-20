#=============================================================================
# VAL-030.1 Jukebox Build Script
# Builds the B008 streaming mechanism
#=============================================================================

param(
    [string]$Configuration = "Release",
    [switch]$RunTests = $false
)

$ErrorActionPreference = "Stop"

Write-Host "RawrXD VAL-030.1 Jukebox Build" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""

# Create output directories
New-Item -ItemType Directory -Force -Path "bin" | Out-Null
New-Item -ItemType Directory -Force -Path "obj" | Out-Null
New-Item -ItemType Directory -Force -Path "test_data" | Out-Null

# Compiler settings
$ML64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$CL = "cl.exe"
$LINK = "link.exe"

# Compiler flags
$CXXFLAGS = "/O2 /std:c++20 /arch:AVX512 /EHsc /W4"
$DEFINES = "/DWIN32 /D_WINDOWS /DNDEBUG /DRAWRXD_VAL030"
$INCLUDES = "/I. /Isrc"

if ($Configuration -eq "Debug") {
    $CXXFLAGS = "/Od /std:c++20 /arch:AVX512 /EHsc /W4 /Zi"
    $DEFINES = "/DWIN32 /D_WINDOWS /D_DEBUG /DRAWRXD_VAL030"
}

Write-Host "Building VAL-030.1 Jukebox Components..." -ForegroundColor Yellow
Write-Host ""

# Step 1: Assemble MASM worker
Write-Host "[1/5] Assembling jukebox.asm..." -NoNewline
try {
    & $ML64 /c src\memory\jukebox.asm /Fo:obj\jukebox_asm.obj 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host " OK" -ForegroundColor Green
    } else {
        Write-Host " FAILED" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host " SKIPPED (MASM not available, using C++ only)" -ForegroundColor Yellow
    # Create empty object file placeholder
    "" | Out-File -FilePath "obj\jukebox_asm.obj" -Encoding ASCII
}

# Step 2: Compile B008 format
Write-Host "[2/5] Compiling b008_format.hpp (header only)..." -NoNewline
Write-Host " OK" -ForegroundColor Green

# Step 3: Compile Jukebox C++
Write-Host "[3/5] Compiling jukebox.cpp..." -NoNewline
& $CL $CXXFLAGS $DEFINES $INCLUDES /c src\memory\jukebox.cpp /Fo:obj\jukebox_cpp.obj 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " FAILED" -ForegroundColor Red
    exit 1
}

# Step 4: Compile Tensor Residency Planner
Write-Host "[4/5] Compiling tensor_residency_planner.cpp..." -NoNewline
& $CL $CXXFLAGS $DEFINES $INCLUDES /c src\memory\tensor_residency_planner.cpp /Fo:obj\tensor_residency_planner.obj 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " FAILED" -ForegroundColor Red
    exit 1
}

# Step 5: Compile test harness
Write-Host "[5/5] Compiling test_jukebox_stream.cpp..." -NoNewline
& $CL $CXXFLAGS $DEFINES $INCLUDES /c tests\test_jukebox_stream.cpp /Fo:obj\test_jukebox_stream.obj 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " FAILED" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Linking..." -ForegroundColor Yellow

# Link test executable
& $LINK /OUT:bin\test_jukebox.exe `
    obj\jukebox_cpp.obj `
    obj\tensor_residency_planner.obj `
    obj\test_jukebox_stream.obj `
    /SUBSYSTEM:CONSOLE `
    /MACHINE:X64 2>&1 | Out-Null

if ($LASTEXITCODE -eq 0) {
    Write-Host "Link OK" -ForegroundColor Green
} else {
    Write-Host "Link FAILED" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Build Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Artifacts:" -ForegroundColor Cyan
Write-Host "  bin\test_jukebox.exe    - Jukebox stream test"
Write-Host ""

if ($RunTests) {
    Write-Host "Running VAL-030.1 Tests..." -ForegroundColor Yellow
    Write-Host ""
    
    # Run test with 70B simulation (smaller for quick validation)
    & .\bin\test_jukebox.exe 100 256
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "VAL-030.1 PASSED" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "VAL-030.1 FAILED" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Run: .\build_jukebox.ps1 -RunTests"
Write-Host "  2. Validate: bin\test_jukebox.exe"
Write-Host "  3. Phase 1: Connect to 70B model"
