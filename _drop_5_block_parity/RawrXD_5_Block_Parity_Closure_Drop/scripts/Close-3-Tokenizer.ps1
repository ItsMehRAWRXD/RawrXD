param(
    [Parameter(Mandatory=$true)][string]$Model,
    [Parameter(Mandatory=$true)][string]$PromptFile,
    [Parameter(Mandatory=$true)][string]$ReferenceIds,
    [string]$DropRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$BuildDir = ""
)

$ErrorActionPreference = "Stop"
if (-not $BuildDir) { $BuildDir = Join-Path $DropRoot "build-cert-tools" }

& cmake -S $DropRoot -B $BuildDir
if ($LASTEXITCODE -ne 0) { throw "BLOCK3_TOOL_CONFIGURE_FAIL" }

& cmake --build $BuildDir --target rawrxd_tokenizer_parity --config Release --parallel
if ($LASTEXITCODE -ne 0) { throw "BLOCK3_TOOL_BUILD_FAIL" }

$candidates = @(
    (Join-Path $BuildDir "rawrxd_tokenizer_parity.exe"),
    (Join-Path $BuildDir "Release\rawrxd_tokenizer_parity.exe"),
    (Join-Path $BuildDir "bin\rawrxd_tokenizer_parity.exe"),
    (Join-Path $BuildDir "bin\Release\rawrxd_tokenizer_parity.exe")
)
$exe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $exe) { throw "BLOCK3_TOOL_NOT_FOUND" }

& $exe $Model $PromptFile $ReferenceIds
if ($LASTEXITCODE -ne 0) { throw "BLOCK3_TOKENIZER_PARITY_FAIL" }

"BLOCK3_TOKENIZER_PARITY=PASS"
