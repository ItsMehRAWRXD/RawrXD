#Requires -Version 5.1
<#
.SYNOPSIS
  Minimal coding-task stub: builds fixtures/agent_multierror_calc via real cl.exe.
  Broken fixture is expected FAIL until agent autofix; does not invent scores.
.NOTES
  PROMOTE=0 · NOT_RUN != PASS
#>
param(
    [string]$FixtureDir = (Join-Path $PSScriptRoot '..\..\..\fixtures\agent_multierror_calc'),
    [string]$VcVars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat',
    [string]$OutDir = (Join-Path $PSScriptRoot '..\logs')
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if (-not (Test-Path $FixtureDir)) {
    Write-Host "CODING_TASK=NOT_RUN missing_fixture=$FixtureDir"
    exit 2
}
if (-not (Test-Path $VcVars)) {
    Write-Host "CODING_TASK=NOT_RUN missing_vcvars=$VcVars"
    exit 2
}
$out = Join-Path $OutDir 'coding_task_build.out.txt'
$cmd = "call `"$VcVars`" >nul && cd /d `"$FixtureDir`" && cl /nologo /EHsc /std:c++20 add.cpp mul.cpp main.cpp /Fe:calc_ok.exe && calc_ok.exe"
cmd /c $cmd > $out 2>&1
$code = $LASTEXITCODE
Write-Host "COMMAND=cl /nologo /EHsc /std:c++20 add.cpp mul.cpp main.cpp /Fe:calc_ok.exe"
Write-Host "FIXTURE=$FixtureDir"
Write-Host "EXIT=$code"
Write-Host "NOTE=fixture intentionally multi-error; PASS only if calc_ok 14"
Get-Content $out -ErrorAction SilentlyContinue | Select-Object -First 40
exit $code
