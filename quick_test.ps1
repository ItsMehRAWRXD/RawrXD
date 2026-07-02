#!/usr/bin/env powershell
# Quick AMX/INT8 Test - Compile and Run
# Usage: .\quick_test.ps1 [-Compiler msvc|gcc]

param(
    [string]$Compiler = "msvc"
)

$ErrorActionPreference = "Stop"

cd d:\rawrxd

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Quick AMX/INT8 Validation Test" -ForegroundColor Cyan
Write-Host "Compiler: $Compiler" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

if ($Compiler -eq "msvc") {
    Write-Host "Using Microsoft Visual C++..." -ForegroundColor Green
    
    # Try to find VS2022
    $vsWhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
    
    if (Test-Path $vsWhere) {
        $vsRoot = & $vsWhere -latest -property installationPath
        
        if ($vsRoot) {
            $vcvarsPath = Join-Path $vsRoot "VC\Auxiliary\Build\vcvars64.bat"
            
            if (Test-Path $vcvarsPath) {
                Write-Host "Found VS at: $vsRoot" -ForegroundColor Gray
                
                # Create a temporary batch file to capture environment
                $tempBat = [System.IO.Path]::GetTempFileName() + ".bat"
                @"
call "$vcvarsPath" > nul 2>&1
set
"@ | Out-File -FilePath $tempBat -Encoding ASCII
                
                # Run and capture environment
                $envVars = cmd /c $tempBat
                Remove-Item $tempBat
                
                # Parse and set environment variables
                foreach ($line in $envVars) {
                    if ($line -match "^(\w+)=(.*)$") {
                        $name = $matches[1]
                        $value = $matches[2]
                        Set-Item -Path "Env:$name" -Value $value -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }
    
    # Compile
    Write-Host "Compiling with cl.exe..." -ForegroundColor Yellow
    & cl.exe /O2 /arch:AVX512 /EHsc /nologo quick_amx_test.cpp /Fe:quick_amx_test.exe 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        throw "MSVC compilation failed!"
    }
} elseif ($Compiler -eq "gcc") {
    Write-Host "Using MinGW GCC..." -ForegroundColor Green
    
    # Compile
    Write-Host "Compiling with g++..." -ForegroundColor Yellow
    & g++ -O3 -march=native -o quick_amx_test.exe quick_amx_test.cpp 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        throw "GCC compilation failed!"
    }
} else {
    throw "Unknown compiler: $Compiler. Use 'msvc' or 'gcc'"
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Compilation successful!" -ForegroundColor Green
Write-Host "Running test..." -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""

# Run the test
& .\quick_amx_test.exe

$testResult = $LASTEXITCODE

Write-Host ""
Write-Host "==========================================" -ForegroundColor $(if ($testResult -eq 0) { "Green" } else { "Red" })
if ($testResult -eq 0) {
    Write-Host "TEST PASSED" -ForegroundColor Green
} else {
    Write-Host "TEST FAILED with exit code $testResult" -ForegroundColor Red
}
Write-Host "==========================================" -ForegroundColor $(if ($testResult -eq 0) { "Green" } else { "Red" })

exit $testResult
