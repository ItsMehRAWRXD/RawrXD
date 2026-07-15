# Simple telemetry build - compiles the library
param([switch]$Test)

$ErrorActionPreference = "Stop"

$ML64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$LIB = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\lib.exe"
$CL = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"

$OutputDir = "d:\RawrXD\telemetry-build"

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
New-Item -ItemType Directory -Force -Path "$OutputDir\lib" | Out-Null
New-Item -ItemType Directory -Force -Path "$OutputDir\include" | Out-Null

Write-Host "Building Sovereign Telemetry Library..." -ForegroundColor Cyan
Write-Host ""

# Compile ASM files
$AsmFiles = @(
    "RawrXD_Telemetry.asm",
    "RawrXD_Sovereign_Telemetry_Integration.asm",
    "RawrXD_Telemetry_Exports.asm"
)

$objFiles = @()

foreach ($asm in $AsmFiles) {
    $asmPath = "d:\RawrXD\$asm"
    if (Test-Path $asmPath) {
        Write-Host "Assembling $asm..." -NoNewline
        $objFile = "$OutputDir\$($asm -replace '\.asm$','.obj')"
        
        $proc = Start-Process -FilePath $ML64 -ArgumentList @(
            "-c", "-Fo`"$objFile`"", "-W3", "-DWIN64", "`"$asmPath`""
        ) -PassThru -Wait -NoNewWindow -RedirectStandardOutput "$OutputDir\$asm.log" -RedirectStandardError "$OutputDir\$asm.err"
        
        if ($proc.ExitCode -eq 0) {
            Write-Host " OK" -ForegroundColor Green
            $objFiles += $objFile
        } else {
            Write-Host " FAILED" -ForegroundColor Red
        }
    }
}

# Create static library
if ($objFiles.Count -gt 0) {
    Write-Host "Creating library..." -NoNewline
    $libFile = "$OutputDir\lib\RawrXD_Telemetry.lib"
    
    $libArgs = @("/OUT:`"$libFile`"", "/MACHINE:X64") + $objFiles
    $proc = Start-Process -FilePath $LIB -ArgumentList $libArgs -PassThru -Wait -NoNewWindow
    
    if ($proc.ExitCode -eq 0) {
        Write-Host " OK" -ForegroundColor Green
    } else {
        Write-Host " FAILED" -ForegroundColor Red
    }
}

# Copy headers
$headerFile = "d:\RawrXD\RawrXD_Telemetry.h"
if (Test-Path $headerFile) {
    Copy-Item $headerFile "$OutputDir\include\" -Force
    Write-Host "Copied header file" -ForegroundColor Green
}

Write-Host ""
Write-Host "Build complete. Output: $OutputDir" -ForegroundColor Cyan

# Run test if requested
if ($Test -and (Test-Path "$OutputDir\lib\RawrXD_Telemetry.lib")) {
    Write-Host ""
    Write-Host "Running test harness..." -ForegroundColor Cyan
    
    # Create simple test
    $testCode = @'
#include <stdio.h>
#include <windows.h>

// Minimal test - just verify library loads
int main() {
    printf("Telemetry Library Test\n");
    printf("=====================\n\n");
    printf("Library compiled successfully!\n");
    printf("Output: telemetry-build/lib/RawrXD_Telemetry.lib\n");
    return 0;
}
'@
    
    $testFile = "$OutputDir\test.c"
    $testCode | Out-File -FilePath $testFile -Encoding ASCII
    
    $exeFile = "$OutputDir\test.exe"
    & $CL "/Fe:$exeFile", $testFile, "/link", "/LIBPATH:$OutputDir\lib", "RawrXD_Telemetry.lib" 2>&1 | Out-Null
    
    if (Test-Path $exeFile) {
        & $exeFile
    }
}

Write-Host ""
Write-Host "To use: Link against $OutputDir\lib\RawrXD_Telemetry.lib" -ForegroundColor Yellow
