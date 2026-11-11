[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Model,
    [Parameter(Mandatory)] [string] $Trace,
    [string] $ReferenceTrace,
    [string] $Oracle = "F:\rawrxd\~dev\build\Release\deep2_parity_oracle.exe",
    [string] $Prompt = "def",
    [int] $Tokens = 8,
    [int] $TimeoutSeconds = 900,
    [double] $Tolerance = 1e-6
)

$ErrorActionPreference = "Stop"

function Fail([string] $Message) {
    Write-Error $Message
    exit 2
}

if (-not (Test-Path -LiteralPath $Oracle -PathType Leaf)) {
    Fail "Parity producer not found: $Oracle"
}
if (-not (Test-Path -LiteralPath $Model -PathType Leaf)) {
    Fail "Model not found: $Model"
}
if ($Tokens -lt 1 -or $Tokens -gt 512) {
    Fail "Tokens must be between 1 and 512."
}
if ($TimeoutSeconds -lt 1) {
    Fail "TimeoutSeconds must be positive."
}

$tracePath = [IO.Path]::GetFullPath($Trace)
$traceParent = Split-Path -Parent $tracePath
if ($traceParent) {
    New-Item -ItemType Directory -Force -Path $traceParent | Out-Null
}
if (Test-Path -LiteralPath $tracePath) {
    Remove-Item -LiteralPath $tracePath -Force
}

Write-Host "SSM_TRACE_START model=$Model tokens=$Tokens"
$process = Start-Process -FilePath $Oracle `
    -ArgumentList @($Model, $Prompt, $tracePath, $Tokens) `
    -NoNewWindow -PassThru
if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    $process.Kill($true)
    Fail "Parity producer timed out after $TimeoutSeconds seconds."
}
if ($process.ExitCode -ne 0) {
    Fail "Parity producer failed with exit code $($process.ExitCode)."
}
if (-not (Test-Path -LiteralPath $tracePath -PathType Leaf)) {
    Fail "Parity producer exited successfully without creating a trace."
}

$traceInfo = Get-Item -LiteralPath $tracePath
if ($traceInfo.Length -eq 0) {
    Fail "Parity producer created an empty trace."
}
Write-Host "SSM_TRACE_READY path=$tracePath bytes=$($traceInfo.Length)"

if ($ReferenceTrace) {
    $referencePath = [IO.Path]::GetFullPath($ReferenceTrace)
    if ($referencePath -eq $tracePath) {
        Fail "ReferenceTrace must be independent from the captured candidate trace."
    }
    if (-not (Test-Path -LiteralPath $referencePath -PathType Leaf)) {
        Fail "Reference trace not found: $referencePath"
    }
    $comparator = Join-Path (Split-Path -Parent $PSScriptRoot) "tools\compare_deep2_trace.py"
    if (-not (Test-Path -LiteralPath $comparator -PathType Leaf)) {
        Fail "Trace comparator not found: $comparator"
    }
    & py $comparator $referencePath $tracePath --tolerance $Tolerance `
        --json "$tracePath.receipt.json"
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

exit 0
