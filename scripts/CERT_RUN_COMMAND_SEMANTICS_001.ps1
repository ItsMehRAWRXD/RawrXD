<#
.SYNOPSIS
  RUN_COMMAND_SEMANTICS_001 - certify run_command cwd/argv/exit/stdio + cmake build discovery.
#>
param(
    [string]$BuildBin = "F:\~dev\rawrxd\build-win32ide-fresh\bin",
    [string]$EvidenceRoot = "F:\~dev\rawrxd\evidence\RUN_COMMAND_SEMANTICS_001"
)

$ErrorActionPreference = "Stop"
$exe = Join-Path $BuildBin "RawrXD-Agentic.exe"
if (-not (Test-Path -LiteralPath $exe)) { throw "missing $exe - rebuild RawrXD-Agentic first" }

New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null
$bat = Join-Path $EvidenceRoot "run_cert.bat"
$console = Join-Path $EvidenceRoot "cert.console.txt"
$batBody = @(
    '@echo off'
    'call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1'
    ('"{0}" --run-command-cert --schema-cert-out "{1}" > "{2}" 2>&1' -f $exe, $EvidenceRoot, $console)
    'echo CERT_EXIT=%ERRORLEVEL%>> "' + $console + '"'
    'exit /b %ERRORLEVEL%'
) -join "`r`n"
[System.IO.File]::WriteAllText($bat, $batBody)

cmd /c $bat
$code = $LASTEXITCODE
Write-Host "RUN_COMMAND_SEMANTICS_001 exit=$code evidence=$EvidenceRoot"
if ($code -ne 0) { exit $code }
exit 0
