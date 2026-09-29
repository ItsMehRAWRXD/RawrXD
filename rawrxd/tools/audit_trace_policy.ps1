param(
    [string]$Root = "F:\~dev\rawrxd",
    [string]$Out = "F:\~dev\_trace_policy_audit.csv"
)

$ErrorActionPreference = "Stop"

$files = Get-ChildItem $Root -Recurse -Include *.cpp,*.h,*.hpp,*.cc,*.cxx -File |
    Where-Object { $_.FullName -notmatch "\\(build|build_|\.git|\.vs|x64|Release|Debug)\\" -and $_.FullName -notmatch "\.archpack" }

$traceWords = @(
    "fprintf(stderr",
    "std::fprintf(stderr",
    "std::cerr",
    "OutputDebugString",
    "LOGITS_SANITY",
    "SAMPLER_RESULT",
    "FINAL_NORM_ENTER",
    "COMPUTE_LOGITS_RETURNED",
    "LINEARW",
    "FWD_LAYER",
    "[DECODE]",
    "[STREAM]",
    "[GENERATE]",
    "[LOGITS]",
    "[SPEC]",
    "[EMBED]",
    "[ALLOC]",
    "[INIT]"
)

$gateWords = @(
    "RAWRXD_IDE_DIAG",
    "RAWRXD_VERBOSE",
    "RAWRXD_TRACE_TOKEN",
    "RAWRXD_LOGITS_SANITY_FULL",
    "RAWRXD_TRACE_PROFILE",
    "DEEP2_TRACE_FORWARD",
    "deep2ForwardTraceEnabled",
    "rawrxdIdeDiagEnabled",
    "rawrxdNoisyTokenTraceEnabled"
)

$rows = @()

foreach ($f in $files) {
    $lines = @(Get-Content -LiteralPath $f.FullName)
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = [string]$lines[$i]

        $hit = $false
        foreach ($w in $traceWords) {
            if ($line -like "*$w*") { $hit = $true; break }
        }
        if (-not $hit) { continue }

        $start = [Math]::Max(0, $i - 5)
        $end   = [Math]::Min($lines.Count - 1, $i + 2)
        $ctx   = ($lines[$start..$end] -join "`n")

        $gated = $false
        foreach ($g in $gateWords) {
            if ($ctx -like "*$g*") { $gated = $true; break }
        }

        $class = if ($gated) {
            "GATED_TRACE"
        } elseif ($line -match "LOGITS_SANITY|SAMPLER_RESULT|FINAL_NORM_ENTER|LINEARW|FWD_LAYER|\[DECODE\]|\[STREAM\]|\[GENERATE\]|\[LOGITS\]") {
            "UNCONDITIONAL_HOTPATH_SPAM"
        } else {
            "UNCONDITIONAL_TRACE_REVIEW"
        }

        $rows += [pscustomobject]@{
            File  = $f.FullName
            Line  = $i + 1
            Class = $class
            Text  = ($line.Trim() -replace "\s+", " ")
        }
    }
}

$rows | Export-Csv $Out -NoTypeInformation

"TRACE_POLICY_AUDIT=$Out"
"TOTAL_TRACE_HITS=$($rows.Count)"
"UNCONDITIONAL_HOTPATH_SPAM=$(@($rows | Where-Object Class -eq 'UNCONDITIONAL_HOTPATH_SPAM').Count)"
"UNCONDITIONAL_TRACE_REVIEW=$(@($rows | Where-Object Class -eq 'UNCONDITIONAL_TRACE_REVIEW').Count)"
"GATED_TRACE=$(@($rows | Where-Object Class -eq 'GATED_TRACE').Count)"
