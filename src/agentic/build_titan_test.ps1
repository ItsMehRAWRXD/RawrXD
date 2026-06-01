# Titan Engine MASM64 Build Script (PowerShell)
# Compiles the assembly and C++ test harness, then links them together

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Titan Engine MASM64 Build Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Paths
$VSPath = "C:\VS2022Enterprise"
$MSVCPath = "$VSPath\VC\Tools\MSVC\14.50.35717"
$WinSDKPath = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0"
$ML64 = "$MSVCPath\bin\Hostx64\x64\ml64.exe"
$SrcDir = "d:\rawrxd\src\agentic"
$AsmSrc = "$SrcDir\RawrXD_Absolutely_Complete.asm"
$CppSrc = "$SrcDir\titan_test_harness.cpp"
$AsmObj = "$SrcDir\titan_engine.obj"
$CppObj = "$SrcDir\titan_test_harness.obj"
$ExeOut = "$SrcDir\TitanTest.exe"

# Step 1: Assemble MASM
Write-Host "[STEP 1] Assembling MASM64 source..." -ForegroundColor Yellow
Write-Host "  Source: $AsmSrc"
Write-Host "  Output: $AsmObj"

& $ML64 /c /nologo /W3 /Fo $AsmObj $AsmSrc
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Assembly failed!" -ForegroundColor Red
    exit 1
}
Write-Host "  Assembly successful." -ForegroundColor Green
Write-Host ""

# Step 2: Compile C++ using VS Developer Command Prompt
Write-Host "[STEP 2] Compiling C++ test harness..." -ForegroundColor Yellow
Write-Host "  Source: $CppSrc"
Write-Host "  Output: $CppObj"

# Find vcvarsall.bat
$VcVarsAll = "$VSPath\VC\Auxiliary\Build\vcvarsall.bat"
if (-not (Test-Path $VcVarsAll)) {
    Write-Host "ERROR: Cannot find vcvarsall.bat at $VcVarsAll" -ForegroundColor Red
    exit 1
}

# Compile using VS environment
$compileCmd = @"
@echo off
call "$VcVarsAll" x64 >nul 2>&1
cl /c /EHsc /nologo /W3 /Fo"$CppObj" "$CppSrc"
"@

$compileBat = "$SrcDir\temp_compile.bat"
$compileCmd | Out-File -FilePath $compileBat -Encoding ASCII

& cmd /c $compileBat
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: C++ compilation failed!" -ForegroundColor Red
    Remove-Item $compileBat -ErrorAction SilentlyContinue
    exit 1
}
Remove-Item $compileBat -ErrorAction SilentlyContinue

Write-Host "  Compilation successful." -ForegroundColor Green
Write-Host ""

# Step 3: Link
Write-Host "[STEP 3] Linking executable..." -ForegroundColor Yellow
Write-Host "  Objects: $AsmObj, $CppObj"
Write-Host "  Output: $ExeOut"

$linkCmd = @"
@echo off
call "$VcVarsAll" x64
link /NOLOGO /SUBSYSTEM:CONSOLE /MACHINE:X64 /LIBPATH:"$WinSDKPath\um\x64" /LIBPATH:"$WinSDKPath\ucrt\x64" /OUT:"$ExeOut" "$AsmObj" "$CppObj" kernel32.lib ntdll.lib uuid.lib
"@

$linkBat = "$SrcDir\temp_link.bat"
$linkCmd | Out-File -FilePath $linkBat -Encoding ASCII

& cmd /c $linkBat
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Linking failed!" -ForegroundColor Red
    Remove-Item $linkBat -ErrorAction SilentlyContinue
    exit 1
}
Remove-Item $linkBat -ErrorAction SilentlyContinue

Write-Host "  Linking successful." -ForegroundColor Green
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "BUILD COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Executable: $ExeOut" -ForegroundColor White
Write-Host ""
Write-Host "To run the tests:" -ForegroundColor Yellow
Write-Host "  $ExeOut" -ForegroundColor White
Write-Host ""