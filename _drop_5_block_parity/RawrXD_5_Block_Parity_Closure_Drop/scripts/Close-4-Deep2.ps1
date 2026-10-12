param(
    [Parameter(Mandatory=$true)][string]$Deep2DumpDir,
    [Parameter(Mandatory=$true)][string]$ReferenceDumpDir,
    [double]$AbsEps = 1e-6,
    [string]$DropRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$BuildDir = ""
)

$ErrorActionPreference = "Stop"
if (-not $BuildDir) { $BuildDir = Join-Path $DropRoot "build-cert-tools" }

& cmake -S $DropRoot -B $BuildDir
if ($LASTEXITCODE -ne 0) { throw "BLOCK4_TOOL_CONFIGURE_FAIL" }

& cmake --build $BuildDir --target rawrxd_deep2_parity --config Release --parallel
if ($LASTEXITCODE -ne 0) { throw "BLOCK4_TOOL_BUILD_FAIL" }

$candidates = @(
    (Join-Path $BuildDir "rawrxd_deep2_parity.exe"),
    (Join-Path $BuildDir "Release\rawrxd_deep2_parity.exe"),
    (Join-Path $BuildDir "bin\rawrxd_deep2_parity.exe"),
    (Join-Path $BuildDir "bin\Release\rawrxd_deep2_parity.exe")
)
$exe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $exe) { throw "BLOCK4_TOOL_NOT_FOUND" }

& $exe $Deep2DumpDir $ReferenceDumpDir $AbsEps
if ($LASTEXITCODE -ne 0) { throw "BLOCK4_DEEP2_PARITY_FAIL" }

"BLOCK4_DEEP2_PARITY=PASS"
