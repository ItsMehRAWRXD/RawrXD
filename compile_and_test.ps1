#!/usr/bin/env pwsh
# Compile and run GGUF test

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "GGUF Architecture Detection Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Find cl.exe
$clPaths = @(
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64\cl.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64\cl.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64\cl.exe",
    "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36207\bin\Hostx64\x64\cl.exe",
    "D:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
)

$clPath = $null
foreach ($path in $clPaths) {
    if (Test-Path $path) {
        $clPath = $path
        break
    }
}

if (-not $clPath) {
    # Try to find dynamically
    $vsPaths = @(
        "C:\Program Files\Microsoft Visual Studio\2022",
        "C:\Program Files\Microsoft Visual Studio\18",
        "D:\VS2022Enterprise"
    )
    
    foreach ($vsPath in $vsPaths) {
        if (Test-Path $vsPath) {
            $clExe = Get-ChildItem -Path $vsPath -Filter "cl.exe" -Recurse -ErrorAction SilentlyContinue | 
                     Where-Object { $_.FullName -like "*Hostx64*" } | 
                     Select-Object -First 1
            if ($clExe) {
                $clPath = $clExe.FullName
                break
            }
        }
    }
}

if (-not $clPath) {
    Write-Host "ERROR: Could not find cl.exe" -ForegroundColor Red
    Write-Host "Please run from a Visual Studio Developer Command Prompt" -ForegroundColor Yellow
    exit 1
}

Write-Host "Found compiler: $clPath" -ForegroundColor Green

# Compile
cd d:\rawrxd

Write-Host ""
Write-Host "Compiling standalone_gguf_test.cpp..." -ForegroundColor Yellow

& $clPath /EHsc /W3 /O2 /Fe:gguf_test.exe standalone_gguf_test.cpp 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED to compile" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "SUCCESS: gguf_test.exe built" -ForegroundColor Green
Write-Host ""

# Check if model exists
$modelPath = "F:\OllamaModels\Qwen3.5-40B-Claude-4.6-Opus-Deckard-Heretic-Uncensored-Thinking.Q4_K_M.gguf"
if (Test-Path $modelPath) {
    Write-Host "Found 40B model, running test..." -ForegroundColor Yellow
    Write-Host ""
    & .\gguf_test.exe "$modelPath"
} else {
    Write-Host "Model not found at: $modelPath" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To test manually, run:" -ForegroundColor Cyan
    Write-Host "  .\gguf_test.exe `"<path to model.gguf`">" -ForegroundColor White
}
