# Build Sovereign Loader with Pure MASM Kernels
# Compiles all MASM assembly files and links with minimal C launcher (no Qt)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   RawrXD Sovereign Loader - MASM Kernel Build System      ║" -ForegroundColor Cyan
Write-Host "║   Pure Assembly Performance | Zero Qt Overhead            ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Paths
$projectRoot = "C:\Users\HiH8e\Downloads\RawrXD-production-lazy-init"
$kernelDir = Join-Path $projectRoot "kernels"
$srcDir = Join-Path $projectRoot "src"
$buildDir = Join-Path $projectRoot "build-sovereign"
$binDir = Join-Path $buildDir "bin"

# Create build directories
if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
}
if (-not (Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir | Out-Null
}

# Initialize Visual Studio environment
Write-Host "[0/4] Initializing Visual Studio 2022 environment..." -ForegroundColor Yellow

$vsPath = "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vsPath)) {
    $vsPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
}
if (-not (Test-Path $vsPath)) {
    $vsPath = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}

if (-not (Test-Path $vsPath)) {
    Write-Host "  ✗ Visual Studio 2022 not found!" -ForegroundColor Red
    Write-Host "  Please install Visual Studio 2022 with C++ build tools" -ForegroundColor Red
    exit 1
}

# Run vcvars64 and capture environment
cmd /c "`"$vsPath`" >nul 2>&1 && set" | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') {
        [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
    }
}

Write-Host "  ✓ Visual Studio environment loaded" -ForegroundColor Green
Write-Host ""

Write-Host "[1/4] Assembling MASM kernels..." -ForegroundColor Yellow

# Compile MASM files
$masmFiles = @(
    "universal_quant_kernel.asm",
    "beaconism_dispatcher.asm",
    "dimensional_pool.asm"
)

$objFiles = @()

foreach ($asmFile in $masmFiles) {
    $asmPath = Join-Path $kernelDir $asmFile
    $objName = [System.IO.Path]::GetFileNameWithoutExtension($asmFile) + ".obj"
    $objPath = Join-Path $buildDir $objName
    
    if (Test-Path $asmPath) {
        Write-Host "  → Assembling $asmFile..." -NoNewline
        
        $result = & ml64.exe /c /Fo"$objPath" "$asmPath" 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host " ✓" -ForegroundColor Green
            $objFiles += $objPath
        } else {
            Write-Host " ✗" -ForegroundColor Red
            Write-Host "Error output:" -ForegroundColor Red
            Write-Host $result -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "  ✗ File not found: $asmPath" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "[2/4] Compiling C launcher..." -ForegroundColor Yellow

$cFile = Join-Path $srcDir "sovereign_loader.c"
$cObj = Join-Path $buildDir "sovereign_loader.obj"

if (Test-Path $cFile) {
    Write-Host "  → Compiling sovereign_loader.c..." -NoNewline
    
    # Compile with optimizations (/O2), x64, and proper calling convention
    $result = & cl.exe /c /O2 /Fo"$cObj" "$cFile" /nologo 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host " ✓" -ForegroundColor Green
    } else {
        Write-Host " ✗" -ForegroundColor Red
        Write-Host $result -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  ✗ File not found: $cFile" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[3/4] Linking executable..." -ForegroundColor Yellow

$exePath = Join-Path $binDir "SovereignLoader.exe"
$allObjs = @($cObj) + $objFiles
$objList = $allObjs -join " "

Write-Host "  → Linking SovereignLoader.exe..." -NoNewline

# Link with proper Windows subsystem and entry point
$result = & link.exe /OUT:"$exePath" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup $objList kernel32.lib user32.lib 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host " ✓" -ForegroundColor Green
} else {
    Write-Host " ✗" -ForegroundColor Red
    Write-Host $result -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[4/4] Verifying build..." -ForegroundColor Yellow

if (Test-Path $exePath) {
    $exeSize = (Get-Item $exePath).Length
    $exeSizeKB = [math]::Round($exeSize / 1024, 2)
    
    Write-Host "  ✓ Executable created: $exePath" -ForegroundColor Green
    Write-Host "  → Size: $exeSizeKB KB" -ForegroundColor Cyan
    Write-Host "  → Architecture: x64 (Pure MASM + Minimal C)" -ForegroundColor Cyan
    Write-Host "  → Dependencies: None (native Windows API only)" -ForegroundColor Cyan
} else {
    Write-Host "  ✗ Executable not found!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  BUILD SUCCESSFUL" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "Run the sovereign loader:" -ForegroundColor White
Write-Host "  cd $binDir" -ForegroundColor Gray
Write-Host "  .\SovereignLoader.exe" -ForegroundColor Gray
Write-Host ""
Write-Host "This will execute the pure MASM kernels with:" -ForegroundColor White
Write-Host "  • Universal 10^-8 quantization" -ForegroundColor Gray
Write-Host "  • 1:11 dimensional pooling" -ForegroundColor Gray
Write-Host "  • Beaconism protocol" -ForegroundColor Gray
Write-Host "  • 11-sided circular mirror geometry" -ForegroundColor Gray
Write-Host ""
