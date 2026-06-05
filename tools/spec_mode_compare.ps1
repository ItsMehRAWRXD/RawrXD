param(
    [string]$ModeA,
    [string]$ModeB,
    [string]$ModeC,
    [string]$ModeD = "",
    [switch]$AsJson
)

$ErrorActionPreference = 'Stop'

function Get-SummaryObject {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Missing log file: $Path"
    }

    $line = Select-String -Path $Path -Pattern '\[ChatSmoke\] summary=' | Select-Object -Last 1
    if (-not $line) {
        throw "No ChatSmoke summary found in: $Path"
    }

    $text = $line.Line
    $marker = 'summary="'
    $idx = $text.IndexOf($marker)
    if ($idx -lt 0) {
        throw "Malformed summary line in: $Path"
    }

    $json = $text.Substring($idx + $marker.Length)
    if ($json.EndsWith('"')) {
        $json = $json.Substring(0, $json.Length - 1)
    }
    $json = $json -replace '\\"', '"'

    return $json | ConvertFrom-Json
}

function New-Row {
    param(
        [string]$Mode,
        [object]$S,
        [object]$Baseline
    )

    $deltaTotalPct = 0.0
    $deltaTpsPct = 0.0
    if ($null -ne $Baseline) {
        if ([double]$Baseline.avg_total_ms -gt 0.0) {
            $deltaTotalPct = (([double]$Baseline.avg_total_ms - [double]$S.avg_total_ms) / [double]$Baseline.avg_total_ms) * 100.0
        }
        if ([double]$Baseline.avg_tps -gt 0.0) {
            $deltaTpsPct = (([double]$S.avg_tps - [double]$Baseline.avg_tps) / [double]$Baseline.avg_tps) * 100.0
        }
    }

    [PSCustomObject]@{
        mode = $Mode
        status = $S.status
        turns = "$($S.turns)/$($S.requested_turns)"
        avg_total_ms = [math]::Round([double]$S.avg_total_ms, 2)
        avg_tps = [math]::Round([double]$S.avg_tps, 2)
        wall_speedup_vs_A_pct = [math]::Round($deltaTotalPct, 2)
        wall_tps_delta_vs_A_pct = [math]::Round($deltaTpsPct, 2)
        spec_acceptance = [math]::Round([double]$S.spec_acceptance, 6)
        spec_auto_disabled = $S.spec_auto_disabled
        spec_auto_disabled_turn = $S.spec_auto_disabled_turn
        fallback_total = $S.fallback_total
        mismatch_count = $S.n_past_mismatch_count
        proactive_rollover_count = $S.proactive_rollover_count
        estimator_net_speedup_pct = [math]::Round([double]$S.net_speedup_pct, 3)
    }
}

if (-not $ModeA -or -not $ModeB -or -not $ModeC) {
    throw "Usage: powershell -File tools/spec_mode_compare.ps1 -ModeA <log> -ModeB <log> -ModeC <log> [-ModeD <log>]"
}

$sa = Get-SummaryObject -Path $ModeA
$sb = Get-SummaryObject -Path $ModeB
$sc = Get-SummaryObject -Path $ModeC
$rows = @(
    New-Row -Mode 'A_clean_off' -S $sa -Baseline $sa
    New-Row -Mode 'B_ngram_active' -S $sb -Baseline $sa
    New-Row -Mode 'C_oracle_active' -S $sc -Baseline $sa
)

if ($ModeD -and (Test-Path -LiteralPath $ModeD)) {
    $sd = Get-SummaryObject -Path $ModeD
    $rows += New-Row -Mode 'D_dual_model' -S $sd -Baseline $sa
}

if ($AsJson) {
    $rows | ConvertTo-Json -Depth 4 -Compress
} else {
    $rows | Format-Table -AutoSize
}
