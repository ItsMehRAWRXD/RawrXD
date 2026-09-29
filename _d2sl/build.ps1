param(
    [string]$BuildDir = "build"
)

$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot
try {
    cmake -S . -B $BuildDir
    cmake --build $BuildDir --config Release

    $candidate1 = Join-Path $BuildDir "Release\deep2-serverless.exe"
    $candidate2 = Join-Path $BuildDir "deep2-serverless.exe"
    if (Test-Path $candidate1) {
        Write-Host "BUILT=$candidate1"
    } elseif (Test-Path $candidate2) {
        Write-Host "BUILT=$candidate2"
    } else {
        throw "deep2-serverless.exe was not produced"
    }

    Write-Host "GATE=DEEP2_SERVERLESS_BUILD_001"
    Write-Host "BUILD=PASS"
}
finally {
    Pop-Location
}
