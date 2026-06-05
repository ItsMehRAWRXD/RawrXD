param(
    [string]$TargetModel = "d:\tinyllama_fresh.gguf",
    [int[]]$DraftLayers = @(4,6,8),
    [int]$SmokeTurns = 20,
    [int]$MaxTokens = 8,
    [double]$Temperature = 0.0,
    [double]$MinAcceptance = 0.30,
    [int]$MinProposed = 32
)

$ErrorActionPreference = 'Continue'

$cmake = 'C:\Program Files\CMake\bin\cmake.exe'
$trunc = 'd:\rawrxd\build_ggufplan\bin\RawrXD-GGUF-Truncator.exe'
$exe = 'd:\rawrxd\build_ggufplan\bin\RawrXD-InferenceEngine.exe'
$compare = 'd:\rawrxd\tools\spec_mode_compare.ps1'

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$baseLog = "d:\rawrxd\tmp\smoke_sweep_A_clean_$stamp.log"

& $cmake --build d:\rawrxd\build_ggufplan --config Release --target RawrXD-GGUF-Truncator RawrXD-InferenceEngine -j 8
if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code $LASTEXITCODE" }

& $exe --model $TargetModel --chat-smoke --smoke-turns $SmokeTurns --max-tokens $MaxTokens --temperature $Temperature --spec-shadow-off *> $baseLog
if ($LASTEXITCODE -ne 0) { throw "Baseline run failed with exit code $LASTEXITCODE" }

$rows = @()

foreach ($n in $DraftLayers) {
    $draftPath = "d:\rawrxd\tmp\tinyllama_${n}layer_$stamp.gguf"
    $dualLog = "d:\rawrxd\tmp\smoke_sweep_D_dual_${n}layer_$stamp.log"

    & $trunc --input $TargetModel --output $draftPath --layers $n
    if ($LASTEXITCODE -ne 0) { throw "Truncator failed for ${n} layers with exit code $LASTEXITCODE" }

    & $exe --model $TargetModel --spec-draft-model $draftPath --chat-smoke --smoke-turns $SmokeTurns --max-tokens $MaxTokens --temperature $Temperature --spec-active-depth1 --spec-min-acceptance $MinAcceptance --spec-min-proposed $MinProposed *> $dualLog
    if ($LASTEXITCODE -ne 0) { throw "Dual run failed for ${n} layers with exit code $LASTEXITCODE" }

    $json = powershell -NoProfile -ExecutionPolicy Bypass -File $compare -ModeA $baseLog -ModeB $baseLog -ModeC $baseLog -ModeD $dualLog -AsJson
    $arr = $json | ConvertFrom-Json
    $d = $arr | Where-Object { $_.mode -eq 'D_dual_model' }

    $rows += [PSCustomObject]@{
        draft_layers = $n
        log = $dualLog
        avg_total_ms = $d.avg_total_ms
        avg_tps = $d.avg_tps
        wall_speedup_vs_A_pct = $d.wall_speedup_vs_A_pct
        spec_acceptance = $d.spec_acceptance
        spec_auto_disabled = $d.spec_auto_disabled
        spec_auto_disabled_turn = $d.spec_auto_disabled_turn
        estimator_net_speedup_pct = $d.estimator_net_speedup_pct
    }
}

$rows | Sort-Object draft_layers | Format-Table -AutoSize
