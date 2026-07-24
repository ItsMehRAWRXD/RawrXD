# Build-MASM-Inference.ps1
# Assembles pure x64 MASM tensor kernels and links with C++ inference engine
# Zero dependencies — no GGML, no external math libs
#
# Usage: .\Build-MASM-Inference.ps1 [-Clean]

param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceDir = Join-Path $ScriptDir "src"
$MasmDir = Join-Path $SourceDir "masm"
$BuildDir = Join-Path $ScriptDir "build_masm"
$MasmPath = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"

Write-Host "=== RawrXD MASM Inference Build ===" -ForegroundColor Cyan
Write-Host "MASM: $MasmPath" -ForegroundColor Gray
Write-Host "Source: $MasmDir" -ForegroundColor Gray
Write-Host "Build: $BuildDir" -ForegroundColor Gray

# Clean
if ($Clean -and (Test-Path $BuildDir)) {
    Remove-Item -Recurse -Force $BuildDir
    Write-Host "Cleaned build directory" -ForegroundColor Yellow
}

# Create build directory
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

# Check MASM exists
if (-not (Test-Path $MasmPath)) {
    Write-Host "MASM not found at $MasmPath" -ForegroundColor Red
    Write-Host "Trying 'ml64' from PATH..." -ForegroundColor Yellow
    $MasmPath = "ml64"
}

# ============================================================================
# STEP 1: Assemble MASM files
# ============================================================================
$AsmFiles = @(
    "rawrxd_math_masm.asm",
    "rawrxd_transformer_masm.asm"
)

$ObjFiles = @()
$Assembled = $true

foreach ($asm in $AsmFiles) {
    $srcPath = Join-Path $MasmDir $asm
    $objName = [System.IO.Path]::ChangeExtension($asm, ".obj")
    $objPath = Join-Path $BuildDir $objName
    
    Write-Host "Assembling: $asm" -ForegroundColor Green
    
    $cmd = "`"$MasmPath`" /c /Cp /W3 /I`"$MasmDir`" /Fo`"$objPath`" `"$srcPath`""
    Write-Host "  $cmd" -ForegroundColor DarkGray
    
    $result = Invoke-Expression $cmd
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  FAILED to assemble $asm (exit code: $LASTEXITCODE)" -ForegroundColor Red
        $Assembled = $false
    } else {
        Write-Host "  OK -> $objName" -ForegroundColor Green
        $ObjFiles += $objPath
    }
}

if (-not $Assembled) {
    Write-Host "`nERROR: MASM assembly failed" -ForegroundColor Red
    exit 1
}

# ============================================================================
# STEP 2: Compile C++ test harness
# ============================================================================
Write-Host "`nCompiling C++ test harness..." -ForegroundColor Cyan

$ClPath = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
$CppFiles = @(
    "ai_model_caller_real.cpp"
)

$CppCompiled = $true
$CppObjFiles = @()

foreach ($cpp in $CppFiles) {
    $srcPath = Join-Path $SourceDir $cpp
    $objName = [System.IO.Path]::ChangeExtension($cpp, ".obj")
    $objPath = Join-Path $BuildDir $objName
    
    Write-Host "Compiling: $cpp" -ForegroundColor Green
    
    $cmd = "`"$ClPath`" /c /nologo /O2 /arch:AVX2 /EHsc /I`"$SourceDir`" /Fo`"$objPath`" `"$srcPath`""
    Write-Host "  $cmd" -ForegroundColor DarkGray
    
    $result = Invoke-Expression $cmd
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  FAILED to compile $cpp (exit code: $LASTEXITCODE)" -ForegroundColor Red
        $CppCompiled = $false
    } else {
        Write-Host "  OK -> $objName" -ForegroundColor Green
        $CppObjFiles += $objPath
    }
}

if (-not $CppCompiled) {
    Write-Host "`nERROR: C++ compilation failed" -ForegroundColor Red
    exit 1
}

# ============================================================================
# STEP 3: Link
# ============================================================================
Write-Host "`nLinking..." -ForegroundColor Cyan

$LinkPath = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
$OutputExe = Join-Path $BuildDir "rawrxd_masm_inference_test.exe"

$AllObjs = $ObjFiles + $CppObjFiles
$ObjList = $AllObjs -join " "

$cmd = "`"$LinkPath`" /nologo /OUT:`"$OutputExe`" $ObjList kernel32.lib user32.lib"
Write-Host "  $cmd" -ForegroundColor DarkGray

$result = Invoke-Expression $cmd
if ($LASTEXITCODE -ne 0) {
    Write-Host "  FAILED to link (exit code: $LASTEXITCODE)" -ForegroundColor Red
    exit 1
}

Write-Host "`n=== BUILD SUCCESSFUL ===" -ForegroundColor Green
Write-Host "Output: $OutputExe" -ForegroundColor Cyan
Write-Host "`nObject files:" -ForegroundColor Gray
foreach ($obj in $AllObjs) {
    Write-Host "  $obj" -ForegroundColor DarkGray
}

# ============================================================================
# STEP 4: Verify no GGML dependencies
# ============================================================================
Write-Host "`nVerifying no GGML dependencies..." -ForegroundColor Cyan
$DumpbinPath = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\dumpbin.exe"

if (Test-Path $DumpbinPath) {
    $deps = & $DumpbinPath /IMPORTS $OutputExe 2>&1 | Out-String
    if ($deps -match "ggml") {
        Write-Host "WARNING: GGML dependency detected!" -ForegroundColor Red
    } else {
        Write-Host "No GGML dependencies found — clean build!" -ForegroundColor Green
    }
}

Write-Host "`nDone." -ForegroundColor Cyan
