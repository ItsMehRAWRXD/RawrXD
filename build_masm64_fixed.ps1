# RawrXD Pure MASM64 Build Script - Fixed
# Zero C++ dependencies - Pure assembly build

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    
    [switch]$Clean,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# MSVC Tool Paths
$VS2022 = "C:\VS2022Enterprise"
$MSVC = "$VS2022\VC\Tools\MSVC\14.50.35717"
$ML64 = "$MSVC\bin\Hostx64\x64\ml64.exe"
$LINK = "$MSVC\bin\Hostx64\x64\link.exe"

# Windows Kits
$KitsRoot = "C:\Program Files (x86)\Windows Kits\10\Lib"
$KitsVer = Get-ChildItem -Path $KitsRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
$KitsUcrt = Join-Path $KitsVer.FullName "ucrt\x64"
$KitsUm = Join-Path $KitsVer.FullName "um\x64"

# Project paths
$ProjectRoot = $PSScriptRoot
$SrcAsmDir = Join-Path $ProjectRoot "src\asm"
$MonolithicDir = Join-Path $SrcAsmDir "monolithic"
$BuildDir = Join-Path $ProjectRoot "build\MASM64"
$OutputDir = Join-Path $ProjectRoot "build\Release"

# Output binary
$OutputExe = Join-Path $OutputDir "RawrXD_IDE.exe"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  RawrXD Pure MASM64 Build System" -ForegroundColor Cyan
Write-Host "  Zero C++ Dependencies" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Verify toolchain
if (-not (Test-Path $ML64)) {
    Write-Host "[ERROR] ml64.exe not found at: $ML64" -ForegroundColor Red
    Write-Host "Please install Visual Studio 2022 with MASM tools" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $LINK)) {
    Write-Host "[ERROR] link.exe not found at: $LINK" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Toolchain verified" -ForegroundColor Green
Write-Host "  ml64: $ML64" -ForegroundColor Gray
Write-Host "  link: $LINK" -ForegroundColor Gray

# Clean if requested
if ($Clean) {
    Write-Host "`n[*] Cleaning build artifacts..." -ForegroundColor Yellow
    if (Test-Path $BuildDir) { Remove-Item $BuildDir -Recurse -Force }
    if (Test-Path $OutputDir) { Remove-Item $OutputDir -Recurse -Force }
    Write-Host "[OK] Clean complete" -ForegroundColor Green
    exit 0
}

# Create directories
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Collect all ASM files
$AsmFiles = @()
$ObjFiles = @()

# Get all monolithic files
Write-Host "`n[*] Scanning monolithic directory..." -ForegroundColor Yellow
$MonolithicFiles = Get-ChildItem -Path $MonolithicDir -Filter "*.asm" -File
foreach ($file in $MonolithicFiles) {
    $AsmFiles += $file.FullName
}
Write-Host "  Found $($MonolithicFiles.Count) monolithic files" -ForegroundColor Gray

# Get all top-level ASM files
Write-Host "`n[*] Scanning top-level ASM files..." -ForegroundColor Yellow
$TopLevelFiles = Get-ChildItem -Path $SrcAsmDir -Filter "*.asm" -File | Where-Object { $_.Name -ne "RawrXD_UnifiedDebugger.asm" }
foreach ($file in $TopLevelFiles) {
    $AsmFiles += $file.FullName
}
Write-Host "  Found $($TopLevelFiles.Count) top-level files" -ForegroundColor Gray

# Add unified debugger
$UnifiedDebugger = Join-Path $SrcAsmDir "RawrXD_UnifiedDebugger.asm"
if (Test-Path $UnifiedDebugger) {
    $AsmFiles += $UnifiedDebugger
    Write-Host "  Added unified debugger" -ForegroundColor Gray
}

Write-Host "`n[*] Assembling $($AsmFiles.Count) ASM files..." -ForegroundColor Yellow

$Errors = @()
$SuccessCount = 0

foreach ($asmFile in $AsmFiles) {
    $fileName = [System.IO.Path]::GetFileName($asmFile)
    $objFile = Join-Path $BuildDir ($fileName -replace '\.asm$', '.obj')
    
    Write-Host "  Assembling: $fileName" -ForegroundColor Gray -NoNewline
    
    $mlArgs = @(
        "/c",
        "/nologo",
        "/Zi",
        "/Zd",
        "/Fo", $objFile,
        $asmFile
    )
    
    $result = & $ML64 @mlArgs 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        $ObjFiles += $objFile
        Write-Host " [OK]" -ForegroundColor Green
        $SuccessCount++
    } else {
        Write-Host " [FAIL]" -ForegroundColor Red
        $Errors += "Failed: $fileName`n$result"
    }
}

Write-Host "`n[*] Assembly results: $SuccessCount/$($AsmFiles.Count) files compiled" -ForegroundColor $(if ($SuccessCount -eq $AsmFiles.Count) { "Green" } else { "Yellow" })

if ($Errors.Count -gt 0) {
    Write-Host "`n[ERROR] Assembly failures:" -ForegroundColor Red
    foreach ($err in $Errors) {
        Write-Host $err -ForegroundColor Red
    }
    exit 1
}

# Link
Write-Host "`n[*] Linking..." -ForegroundColor Yellow

$LibPaths = @(
    "/LIBPATH:`"$KitsUcrt`"",
    "/LIBPATH:`"$KitsUm`""
)

$Libs = @(
    "kernel32.lib",
    "user32.lib",
    "gdi32.lib",
    "comdlg32.lib",
    "comctl32.lib",
    "shell32.lib",
    "ole32.lib",
    "oleaut32.lib",
    "ws2_32.lib",
    "advapi32.lib"
)

$LinkArgs = @(
    "/nologo",
    "/subsystem:windows",
    "/entry:WinMain",
    "/out:$OutputExe"
) + $LibPaths + $Libs + $ObjFiles

Write-Host "  Linking $($ObjFiles.Count) object files..." -ForegroundColor Gray

$result = & $LINK @LinkArgs 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[OK] Build successful!" -ForegroundColor Green
    Write-Host "  Output: $OutputExe" -ForegroundColor Gray
    
    # Show file size
    if (Test-Path $OutputExe) {
        $size = (Get-Item $OutputExe).Length
        Write-Host "  Size: $([math]::Round($size / 1MB, 2)) MB" -ForegroundColor Gray
    }
} else {
    Write-Host "`n[ERROR] Link failed:" -ForegroundColor Red
    Write-Host $result -ForegroundColor Red
    exit 1
}