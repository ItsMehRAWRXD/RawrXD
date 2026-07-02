# =============================================================================
# build_swarm_benchmark.ps1
# Build script for Swarm Benchmark with Prometheus + CSV output
# =============================================================================

param(
    [switch]$Run,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

# Configuration
$MSVC_PATH = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"
$ZMQ_PATH = "C:\Program Files\ZeroMQ 4.3.4"  # Adjust path as needed
$OUTPUT_DIR = "d:\RawrXD\build\benchmark"

# Create output directory
if ($Clean -and (Test-Path $OUTPUT_DIR)) {
    Remove-Item -Recurse -Force $OUTPUT_DIR
}
New-Item -ItemType Directory -Force -Path $OUTPUT_DIR | Out-Null

Write-Host "Building Sovereign Swarm Benchmark..." -ForegroundColor Cyan
Write-Host ""

# Compiler settings
$CL = "$MSVC_PATH\bin\Hostx64\x64\cl.exe"
$FLAGS = @(
    "/O2",                    # Optimize for speed
    "/arch:AVX2",             # Enable AVX2
    "/EHsc",                  # Exception handling
    "/MT",                    # Static runtime
    "/std:c++17",             # C++17
    "/W3",                    # Warning level 3
    "/wd4996"                 # Disable deprecation warnings
)

$INCLUDES = @(
    "/I.",
    "/I$MSVC_PATH\include",
    "/I$env:WindowsSdkDir\Include\$env:WindowsSdkVersion\um",
    "/I$env:WindowsSdkDir\Include\$env:WindowsSdkVersion\ucrt"
)

# Add ZeroMQ if available
if (Test-Path $ZMQ_PATH) {
    $INCLUDES += "/I$ZMQ_PATH\include"
    $LIBS = @(
        "/LIBPATH:$ZMQ_PATH\lib",
        "libzmq-mt-s-4_3_4.lib"  # Static ZMQ library
    )
} else {
    Write-Host "Warning: ZeroMQ not found at $ZMQ_PATH" -ForegroundColor Yellow
    Write-Host "Building without ZMQ support (simulation mode)" -ForegroundColor Yellow
    $LIBS = @("kernel32.lib", "user32.lib", "advapi32.lib")
}

# Source files
$SOURCES = @(
    "src\tests\swarm_benchmark.cpp",
    "src\telemetry\sovereign_metrics_collector.cpp"
)

# Compile
Write-Host "Compiling sources..." -NoNewline
$OBJ_FILES = @()

foreach ($src in $SOURCES) {
    $obj = "$OUTPUT_DIR\$(Split-Path $src -Leaf).obj"
    $OBJ_FILES += $obj
    
    $args = $FLAGS + $INCLUDES + @("/c", "/Fo:`"$obj`"", "`"$src`"")
    
    $proc = Start-Process -FilePath $CL -ArgumentList $args `
        -PassThru -Wait -NoNewWindow `
        -RedirectStandardOutput "$OUTPUT_DIR\compile.log" `
        -RedirectStandardError "$OUTPUT_DIR\compile.err"
    
    if ($proc.ExitCode -ne 0) {
        Write-Host " FAILED" -ForegroundColor Red
        Get-Content "$OUTPUT_DIR\compile.err" | Write-Host -ForegroundColor Red
        exit 1
    }
}

Write-Host " OK" -ForegroundColor Green

# Link
Write-Host "Linking executable..." -NoNewline

$EXE = "$OUTPUT_DIR\swarm_benchmark.exe"
$LINK_ARGS = @(
    "/Fe:`"$EXE`"",
    "/MACHINE:X64"
) + $OBJ_FILES + $LIBS

$proc = Start-Process -FilePath $CL -ArgumentList $LINK_ARGS `
    -PassThru -Wait -NoNewWindow `
    -RedirectStandardOutput "$OUTPUT_DIR\link.log" `
    -RedirectStandardError "$OUTPUT_DIR\link.err"

if ($proc.ExitCode -ne 0) {
    Write-Host " FAILED" -ForegroundColor Red
    Get-Content "$OUTPUT_DIR\link.err" | Write-Host -ForegroundColor Red
    exit 1
}

Write-Host " OK" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green
Write-Host "  Executable: $EXE" -ForegroundColor Cyan
Write-Host "  Size: $([math]::Round((Get-Item $EXE).Length/1KB, 2)) KB" -ForegroundColor Cyan
Write-Host ""

if ($Run) {
    Write-Host "Running benchmark..." -ForegroundColor Green
    Write-Host ""
    
    Push-Location $OUTPUT_DIR
    & $EXE --workers 2 --context 131072 --duration 10 --csv swarm_results.csv
    Pop-Location
}

Write-Host ""
Write-Host "Usage examples:" -ForegroundColor Yellow
Write-Host "  .\swarm_benchmark.exe --workers 2 --context 128000 --duration 60"
Write-Host "  .\swarm_benchmark.exe --workers 4 --duration 300 --csv results.csv"
Write-Host "  .\swarm_benchmark.exe --help"
