param(
    [string]$Source = (Resolve-Path "$PSScriptRoot\.."),
    [string]$Build = "$PSScriptRoot\..\build",
    [string]$ReceiptDir = "$PSScriptRoot\..\receipts",
    [string]$BrowserUrl = "https://example.com"
)
$ErrorActionPreference = "Stop"

cmake -S $Source -B $Build -G Ninja -DCMAKE_BUILD_TYPE=Release
if ($LASTEXITCODE -ne 0) { throw "configure failed" }
cmake --build $Build
if ($LASTEXITCODE -ne 0) { throw "build failed" }
ctest --test-dir $Build --output-on-failure
if ($LASTEXITCODE -ne 0) { throw "core test failed" }

New-Item -ItemType Directory -Force -Path $ReceiptDir | Out-Null
$exe = Join-Path $Build "rawrxd-value-pack2.exe"
& $exe selftest $ReceiptDir
if ($LASTEXITCODE -ne 0) { throw "core selftest failed" }

& $exe browser-selftest $ReceiptDir $BrowserUrl
if ($LASTEXITCODE -ne 0) { throw "browser selftest failed" }

Write-Host "GATE=RAWRXD_VALUE_PACK2_WINDOWS_001"
Write-Host "CORE=PASS"
Write-Host "BROWSER=PASS"
Write-Host "VERDICT=PASS"
