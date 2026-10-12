#requires -Version 7.0
<#
  Fail-closed native ModelGenie IR completion gate.
  Source-only drop; no external modules or package installation.
  Usage: pwsh -NoProfile -File .\verify_ir_completion.ps1 -Apply
         pwsh -NoProfile -File .\verify_ir_completion.ps1 -Apply -Push
#>
[CmdletBinding()]
param(
    [string]$Repo = 'F:\rawrxd',
    [string]$Model = 'G:\~dev\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf',
    [string]$Evidence = 'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001',
    [switch]$Apply,
    [switch]$Push
)
$ErrorActionPreference = 'Stop'
$Branch = 'feat/hexmag-polymorphic-repeat-tuner-masm'
$Source = Join-Path $Repo 'tools\rawrxd_modelgenie_ir_executor.cpp'
$PatchScript = Join-Path $PSScriptRoot 'patch_modelgenie_ir.py'
$Compiler = Join-Path $Repo 'compile_ir_executor.bat'
$Exe = Join-Path $Repo 'tmp_build\modelgenie_ir_executor.exe'
$LogDir = Join-Path $Repo 'tmp_build\modelgenie_native_ir_validation'
$CompileLog = Join-Path $LogDir 'compile.log'
$RunLog = Join-Path $LogDir 'run.log'
$DiffFile = Join-Path $LogDir 'source.diff'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw "Missing source: $Source" }
if (-not (Test-Path -LiteralPath $PatchScript -PathType Leaf)) { throw "Missing source patch: $PatchScript" }
if ($Push -and -not $Apply) { throw '-Push requires -Apply.' }
if ($Push) {
    $currentBranch = (& git -C $Repo branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or $currentBranch -ne $Branch) {
        throw "Refusing push: branch must be $Branch, got $currentBranch"
    }
}
$patchArgs = @($PatchScript, '--source', $Source, '--diff', $DiffFile)
if ($Apply) { $patchArgs += '--apply' }
& python @patchArgs
if ($LASTEXITCODE -ne 0) { throw 'Source patch failed closed; no build was launched.' }
if (-not $Apply) {
    Write-Host "DRY_RUN_PASS=1; review $DiffFile, then rerun with -Apply."
    exit 0
}
if (-not (Test-Path -LiteralPath $Model -PathType Leaf)) { throw "Missing GGUF: $Model" }
if (-not (Test-Path -LiteralPath $Evidence -PathType Container)) { throw "Missing evidence: $Evidence" }
if (-not (Test-Path -LiteralPath $Compiler -PathType Leaf)) { throw "Missing compile script: $Compiler" }
Push-Location $Repo
try {
    & cmd.exe /d /c "call `"$Compiler`"" 2>&1 | Tee-Object -FilePath $CompileLog
    $compileExit = $LASTEXITCODE
    Write-Host "COMPILE_EXIT=$compileExit"
    if ($compileExit -ne 0) { throw "Build failed: $CompileLog" }
    if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { throw "Missing executable after build: $Exe" }
    & $Exe $Model $Evidence 2>&1 | Tee-Object -FilePath $RunLog
    $runExit = $LASTEXITCODE
} finally {
    Pop-Location
}
$run = Get-Content -LiteralPath $RunLog -Raw
$gates = [ordered]@{
    'IR_TABLE_AUTHORITY' = '1'
    'IR_SOURCE_OP_COUNT' = '300'
    'IR_OPS_VISITED' = '300'
    'IR_OPS_EXECUTED' = '300'
    'IR_OPS_SKIPPED' = '0'
    'LOGITS_FINITE' = '1'
    'EXPECTED_TOKEN' = '93633'
    'PREDICTED_TOKEN' = '93633'
    'TOKEN_PARITY' = '1'
    'VERDICT' = 'PASS'
}
$ok = $runExit -eq 0
Write-Host "RUN_EXIT=$runExit"
foreach ($gate in $gates.GetEnumerator()) {
    $rx = '(?m)^' + [regex]::Escape($gate.Key + '=' + $gate.Value) + '\r?$'
    $found = [regex]::IsMatch($run, $rx)
    Write-Host "CHECK_$($gate.Key)=$(if($found){'PASS'}else{'FAIL'})"
    if (-not $found) { $ok = $false }
}
if (-not $ok) {
    Write-Host 'NATIVE_IR_CERTIFICATE=FAIL'
    Write-Host "Log available: $RunLog"
    exit 1
}
$certificate = Join-Path $Evidence 'native_ir_300_pass.txt'
@(
    'RAWRXD_MODELGENIE_NATIVE_IR_EXECUTION_001',
    'IR_TABLE_AUTHORITY=1',
    'IR_SOURCE_OP_COUNT=300',
    'IR_OPS_VISITED=300',
    'IR_OPS_EXECUTED=300',
    'IR_OPS_SKIPPED=0',
    'LOGITS_FINITE=1',
    'PREDICTED_TOKEN=93633',
    'EXPECTED_TOKEN=93633',
    'TOKEN_PARITY=1',
    'COMPILE_EXIT=0',
    'RUN_EXIT=0',
    'VERDICT=PASS'
) | Set-Content -LiteralPath $certificate -Encoding utf8
Write-Host 'NATIVE_IR_CERTIFICATE=PASS'
Write-Host "CERTIFICATE=$certificate"
if ($Push) {
    & git -C $Repo add -- 'tools/rawrxd_modelgenie_ir_executor.cpp' 'evidence/NUGVERSE_ESTIMATOR_001/native_ir_300_pass.txt'
    if ($LASTEXITCODE -ne 0) { throw 'Git add failed' }
    & git -C $Repo commit -m 'fix(modelgenie): close full native IR execution and token parity gates'
    if ($LASTEXITCODE -ne 0) { throw 'Git commit failed' }
    & git -C $Repo push origin $Branch
    if ($LASTEXITCODE -ne 0) { throw 'Git push failed' }
    Write-Host 'PUSH_VERIFIED=1'
}
