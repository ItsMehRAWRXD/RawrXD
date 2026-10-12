param(
    [string]$BuildDir = "$PSScriptRoot\build"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

$src = Join-Path $PSScriptRoot "deep2_cert_main.cpp"
$exe = Join-Path $BuildDir "deep2_cert.exe"

$cl = Get-Command cl.exe -ErrorAction SilentlyContinue
if ($cl) {
    & cl.exe /nologo /std:c++20 /EHsc /W4 /permissive- /O2 `
        /I"$PSScriptRoot" $src /Fe:$exe
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
    $gxx = Get-Command g++.exe -ErrorAction SilentlyContinue
    if (-not $gxx) {
        throw "Neither cl.exe nor g++.exe is available in PATH."
    }
    & g++.exe -std=c++20 -O2 -Wall -Wextra -pedantic `
        -I"$PSScriptRoot" $src -o $exe
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

& $exe
exit $LASTEXITCODE
