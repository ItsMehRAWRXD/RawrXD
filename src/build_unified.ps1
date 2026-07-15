# ============================================================================
# RAWRXD FINAL UNIFIED SYSTEM - BUILD SCRIPT (PowerShell)
# Zero-Dependency Model Loading & Streaming + Complete Infrastructure
# ============================================================================

# Find VS2022 installation
$VSPath = "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $VSPath)) {
    $VSPath = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
}
if (-not (Test-Path $VSPath)) {
    $VSPath = "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
}
if (-not (Test-Path $VSPath)) {
    $VSPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
}

if (-not (Test-Path $VSPath)) {
    Write-Error "Visual Studio 2022 not found!"
    exit 1
}

Write-Host "Found VS2022 at: $VSPath"

# Import VS environment
$env:Path = (cmd /c "`"$VSPath`" && echo %PATH%")

# Configuration
$SrcDir = $PSScriptRoot
$OutDir = Join-Path $SrcDir "..\bin"
$ObjDir = Join-Path $SrcDir "..\obj"

# Compiler settings
$CXX = "cl.exe"
$CXXFLAGS = @(
    "/std:c++20",
    "/O2",
    "/W3",
    "/EHsc",
    "/nologo",
    "/MP",
    "/D_CRT_SECURE_NO_WARNINGS",
    "/DWIN32_LEAN_AND_MEAN",
    "/DNOMINMAX",
    "/I`"$SrcDir`""
)

$LDFLAGS = @(
    "/SUBSYSTEM:CONSOLE",
    "/MACHINE:X64"
)

# Create output directories
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path $ObjDir | Out-Null

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  RAWRXD FINAL UNIFIED SYSTEM - BUILD" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Source: $SrcDir"
Write-Host "  Output: $OutDir"
Write-Host "  Objects: $ObjDir"
Write-Host ""

# Source files
$Sources = @(
    "$SrcDir\RawrXD_Final_Unified.cpp",
    "$SrcDir\RawrXD_Final_Unified_Part2.cpp",
    "$SrcDir\RawrXD_Final_Unified_Part3.cpp"
)

$Objects = @(
    "$ObjDir\RawrXD_Final_Unified.obj",
    "$ObjDir\RawrXD_Final_Unified_Part2.obj",
    "$ObjDir\RawrXD_Final_Unified_Part3.obj"
)

# Compile each source file
$step = 1
$totalSteps = 5

for ($i = 0; $i -lt $Sources.Count; $i++) {
    $source = $Sources[$i]
    $object = $Objects[$i]
    $sourceName = Split-Path $source -Leaf
    
    Write-Host "[$step/$totalSteps] Compiling $sourceName..." -ForegroundColor Yellow
    
    $args = $CXXFLAGS + "/c" + "/Fo`"$object`"" + "`"$source`""
    
    $process = Start-Process -FilePath $CXX -ArgumentList $args -Wait -PassThru -NoNewWindow
    
    if ($process.ExitCode -ne 0) {
        Write-Host ""
        Write-Host "ERROR: Compilation failed!" -ForegroundColor Red
        Write-Host ""
        exit 1
    }
    
    $step++
}

# Link library
Write-Host "[$step/$totalSteps] Linking RawrXD_Unified.exe..." -ForegroundColor Yellow
$linkArgs = $LDFLAGS + "/OUT:`"$OutDir\RawrXD_Unified.exe`"" + $Objects

$process = Start-Process -FilePath "link.exe" -ArgumentList $linkArgs -Wait -PassThru -NoNewWindow

if ($process.ExitCode -ne 0) {
    Write-Host ""
    Write-Host "ERROR: Linking failed!" -ForegroundColor Red
    Write-Host ""
    exit 1
}

$step++

# Build demo
Write-Host "[$step/$totalSteps] Building demo_unified.exe..." -ForegroundColor Yellow
$demoArgs = $CXXFLAGS + "/Fe`"$OutDir\demo_unified.exe`"" + "`"$SrcDir\demo_unified.cpp`"" + $Objects + "/link" + $LDFLAGS

$process = Start-Process -FilePath $CXX -ArgumentList $demoArgs -Wait -PassThru -NoNewWindow

if ($process.ExitCode -ne 0) {
    Write-Host ""
    Write-Host "ERROR: Demo build failed!" -ForegroundColor Red
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "  BUILD SUCCESSFUL" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green
Write-Host ""

# Show file info
$exePath = "$OutDir\RawrXD_Unified.exe"
$demoPath = "$OutDir\demo_unified.exe"

if (Test-Path $exePath) {
    $fileInfo = Get-Item $exePath
    Write-Host "  Output: $exePath"
    Write-Host "  Size: $($fileInfo.Length) bytes ($([math]::Round($fileInfo.Length / 1KB, 2)) KB)"
}

if (Test-Path $demoPath) {
    $fileInfo = Get-Item $demoPath
    Write-Host "  Demo: $demoPath"
    Write-Host "  Size: $($fileInfo.Length) bytes ($([math]::Round($fileInfo.Length / 1KB, 2)) KB)"
}

Write-Host ""
