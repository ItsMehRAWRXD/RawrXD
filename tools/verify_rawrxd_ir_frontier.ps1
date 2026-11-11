# Source-only verification harness for the ModelGenie native IR executor.
# Runs on the owner's Windows workstation; produces actual compiler/runtime logs.
param(
    [string]$Root = 'F:\rawrxd',
    [string]$Gguf = 'G:\~dev\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf',
    [string]$Evidence = 'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001'
)
$ErrorActionPreference = 'Stop'
$build = Join-Path $Root 'compile_ir_executor.bat'
$exe = Join-Path $Root 'tmp_build\modelgenie_ir_executor.exe'
$outDir = Join-Path $Root 'evidence\MODELGENIE_NATIVE_IR_FRONTIER_002'
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$compileLog = Join-Path $outDir 'compile.log'
$runLog = Join-Path $outDir 'run.log'
foreach ($file in @($build,$Gguf,$Evidence)) {
    if (!(Test-Path -LiteralPath $file)) { throw "MISSING_INPUT=$file" }
}
Push-Location $Root
try {
    & $build 2>&1 | Tee-Object -FilePath $compileLog
    $compileExit = $LASTEXITCODE
    if ($compileExit -ne 0) { throw "COMPILE_EXIT=$compileExit log=$compileLog" }
    if (!(Test-Path -LiteralPath $exe)) { throw "BINARY_MISSING=$exe" }
    & $exe $Gguf $Evidence 2>&1 | Tee-Object -FilePath $runLog
    $runExit = $LASTEXITCODE
    $log = Get-Content -LiteralPath $runLog -Raw
    $metrics = [ordered]@{ COMPILE_EXIT = $compileExit; RUN_EXIT = $runExit }
    foreach ($key in @('IR_SOURCE_OP_COUNT','IR_OPS_VISITED','IR_OPS_EXECUTED','IR_OPS_SKIPPED','LOGITS_FINITE','PREDICTED_TOKEN','EXPECTED_TOKEN','TOKEN_PARITY','VERDICT')) {
        $matches = [regex]::Matches($log, "(?m)^$key=(.*)$")
        $metrics[$key] = if ($matches.Count -gt 0) { $matches[$matches.Count-1].Groups[1].Value.Trim() } else { 'MISSING' }
    }
    $metrics | Format-Table -AutoSize | Out-String | Write-Host
    $pass = $runExit -eq 0 -and
            $metrics['IR_SOURCE_OP_COUNT'] -eq '300' -and
            $metrics['IR_OPS_VISITED'] -eq '300' -and
            $metrics['IR_OPS_EXECUTED'] -eq '300' -and
            $metrics['IR_OPS_SKIPPED'] -eq '0' -and
            $metrics['LOGITS_FINITE'] -eq '1' -and
            $metrics['EXPECTED_TOKEN'] -eq '93633' -and
            $metrics['PREDICTED_TOKEN'] -eq '93633' -and
            $metrics['TOKEN_PARITY'] -eq '1' -and
            $metrics['VERDICT'] -eq 'PASS'
    $metrics['EVIDENCE_VERDICT'] = if ($pass) { 'PASS' } else { 'FAIL' }
    $metrics.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value } |
        Set-Content -LiteralPath (Join-Path $outDir 'certificate.txt') -Encoding ascii
    if (!$pass) { exit 1 }
    exit 0
} finally {
    Pop-Location
}
