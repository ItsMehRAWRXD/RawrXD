# Sovereign Substrate - Quick Start Script
# Usage: .\quick-start.ps1

$ErrorActionPreference = "Stop"

# Colors
$Red = "Red"
$Green = "Green"
$Yellow = "Yellow"
$Blue = "Cyan"

Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║           Sovereign Substrate - Quick Start                  ║
║                                                              ║
║  The IDE is now autonomous. Let it evolve.                   ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor $Blue

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor $Yellow

$cmake = Get-Command cmake -ErrorAction SilentlyContinue
if (-not $cmake) {
    Write-Host "Error: CMake is not installed" -ForegroundColor $Red
    Write-Host "Please install CMake 3.16 or later"
    exit 1
}

$compiler = Get-Command cl -ErrorAction SilentlyContinue
if (-not $compiler) {
    Write-Host "Error: Visual Studio C++ compiler not found" -ForegroundColor $Red
    Write-Host "Please run from Developer Command Prompt"
    exit 1
}

Write-Host "✓ Prerequisites met" -ForegroundColor $Green

# Create build directory
Write-Host "Setting up build environment..." -ForegroundColor $Yellow
New-Item -ItemType Directory -Force -Path build | Out-Null
Set-Location build

# Configure
Write-Host "Configuring build..." -ForegroundColor $Yellow
cmake .. `
    -DCMAKE_BUILD_TYPE=Release `
    -DRAWR_BUILD_TESTS=ON `
    -DRAWR_BUILD_DEMO=ON `
    -DRAWR_SECURITY_HARDENING=ON `
    -DRAWR_MODEL_ADAPTER=ON `
    -DRAWR_PERSISTENCE=ON `
    -DRAWR_TELEMETRY=ON

# Build
Write-Host "Building Sovereign Substrate..." -ForegroundColor $Yellow
cmake --build . --config Release --parallel

Write-Host "✓ Build complete" -ForegroundColor $Green

# Run tests
Write-Host "Running tests..." -ForegroundColor $Yellow
$testResult = ctest -C Release --output-on-failure
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ All tests passed" -ForegroundColor $Green
} else {
    Write-Host "✗ Some tests failed" -ForegroundColor $Red
    exit 1
}

# Run demo
Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║                    Running Demo                               ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor $Yellow

.\demo\Release\demo_sovereign_substrate.exe

Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║              Sovereign Substrate Ready!                      ║
║                                                              ║
║  Next steps:                                                 ║
║    1. Read START_HERE_SOVEREIGN.md                          ║
║    2. Explore examples\ directory                           ║
║    3. Check out the API documentation                       ║
║                                                              ║
║  The IDE is now autonomous.                                  ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor $Green
