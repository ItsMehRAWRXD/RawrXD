param(
    [string]$Repo = "G:\~dev\rawrxd",
    [string]$Exe = "",
    [string]$Model = "",
    [string]$Prompt = "Write one short sentence.",
    [int]$MaxTokens = 20,
    [double]$CollapseRatio = 0.20,
    [switch]$ContinueAfterSafeBypass,
    [switch]$RunRecert
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# CONTROL-PLANE AUTHORITY LAW:
# This script may sequence, compare, and classify receipts.
# It may NOT manufacture runtime evidence, mutate PROMOTE, or reinterpret missing
# runtime emission as observed ownership.

$gates = @(
    @{ Gate="G0_REFERENCE";         Child="" },
    @{ Gate="G1_GPU_QKV";           Child="QKV" },
    @{ Gate="G2_DEVICE_ATTENTION";  Child="DEVICE_ATTENTION" },
    @{ Gate="G3_FFN";               Child="FFN" },
    @{ Gate="G4_GEMV";              Child="GEMV" },
    @{ Gate="G5_OUTPUT_PROJECTION"; Child="OUTPUT_PROJECTION" },
    @{ Gate="G6_KV";                Child="KV" },
    @{ Gate="G7_SYNC";              Child="SYNC" },
    @{ Gate="G8_READBACK";          Child="READBACK" }
)

if (-not $Exe) {
    $candidates = @(
        "$Repo\build-fd\bin\deep2_streamer_parity.exe",
        "$Repo\build-fd\deep2_streamer_parity.exe",
        "$Repo\build\bin\deep2_streamer_parity.exe",
        "$Repo\build\deep2_streamer_parity.exe"
    )
    $Exe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Exe -or -not (Test-Path $Exe)) {
    throw "Streamer exe not found. Pass -Exe explicitly."
}
if (-not $Model) {
    throw "Pass -Model with the exact TinyLlama GGUF used by the sealed matrix."
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$evidence = Join-Path $Repo "evidence\GPU_FORWARD_CHILD_ONE_IGNORE\$stamp"
New-Item -ItemType Directory -Force -Path $evidence | Out-Null

function Parse-Kv([string[]]$Lines) {
    $m = @{}
    foreach ($line in $Lines) {
        if ($line -match '^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$') {
            $m[$matches[1]] = $matches[2]
        }
    }
    return $m
}
function Need([hashtable]$M,[string]$K) {
    if (-not $M.ContainsKey($K)) { throw "missing runtime emission: $K" }
    return $M[$K]
}
function Is-One([string]$v) { return $v -in @("1","YES","TRUE","PASS") }

$baseline = $null
$results = @()
$winner = $null

foreach ($g in $gates) {
    $gate = $g.Gate
    $child = $g.Child

    # Fresh environment for every process. Only diagnostic request is changed.
    $env:DEEP2_GPU_ISO_RUN = "1"
    $env:OLLAMA_HTTP = "0"
    $env:DEEP2_GPU_FORWARD_CHAIN_GATE = $gate
    $env:DEEP2_GPU_FORWARD_CHILD_IGNORE = $child
    $env:DEEP2_GPU_FORWARD_CHILD_IGNORE_GATE = $gate
    $env:DEEP2_FORCE_PROMOTE = "0"

    $stdout = Join-Path $evidence "$gate.stdout.txt"
    $stderr = Join-Path $evidence "$gate.stderr.txt"
    $receipt = Join-Path $evidence "$gate.receipt.txt"

    $args = @("--model", $Model, "--prompt", $Prompt, "--max-tokens", "$MaxTokens")
    $p = Start-Process -FilePath $Exe -ArgumentList $args -Wait -PassThru `
         -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr

    $all = @()
    if (Test-Path $stdout) { $all += Get-Content $stdout }
    if (Test-Path $stderr) { $all += Get-Content $stderr }
    $m = Parse-Kv $all

    # The chain header is controller evidence only. Values below it are copied
    # from runtime emissions and therefore remain attributable to runtime.
    @(
        "CHAIN_CONTROL=DEEP2_GPU_FORWARD_CHAIN_001"
        "CHAIN_GATE=$gate"
        "CHAIN_CHILD=$child"
        "PROCESS_EXIT=$($p.ExitCode)"
        "CONTROL_PROMOTE_AUTHORITY=0"
        "CONTROL_RUNTIME_AUTHORITY=0"
        "---- RUNTIME EMISSIONS ----"
        $all
    ) | Set-Content -Encoding UTF8 $receipt

    if ($p.ExitCode -ne 0) {
        throw "$gate process exit $($p.ExitCode); chain stopped"
    }

    $auth = Need $m "CLAIM_AUTHORITY"
    if ($auth -ne "OWN_RUNTIME_EMISSION_ONLY") { throw "$gate authority mismatch: $auth" }
    if (-not (Is-One (Need $m "RUNTIME_AUTHORITY"))) { throw "$gate RUNTIME_AUTHORITY != 1" }
    if (-not (Is-One (Need $m "MODEL_PROVENANCE_MATCH"))) { throw "$gate provenance mismatch" }
    if ((Need $m "PROMOTE") -ne "0") { throw "$gate illegally emitted PROMOTE != 0" }
    if ((Need $m "OLLAMA_HTTP") -ne "0") { throw "$gate OLLAMA_HTTP != 0" }
    if ([int](Need $m "TOKENS_COMMITTED") -ne $MaxTokens) { throw "$gate token count mismatch" }

    $fp = if ($m.ContainsKey("MODEL_FP")) { $m["MODEL_FP"] } else { Need $m "MODEL_FINGERPRINT" }
    $gpuMs = [double](Need $m "GPU_FORWARD_MS")
    $blocked = if ($m.ContainsKey("BLOCKED_AT")) { $m["BLOCKED_AT"] } else { "NONE" }

    if ($gate -eq "G0_REFERENCE") {
        $baseline = [pscustomobject]@{ Fingerprint=$fp; GpuMs=$gpuMs; Gate=$gate }
        $results += [pscustomobject]@{
            Gate=$gate; Child="NONE"; GpuMs=$gpuMs; DeltaMs=0.0; Ratio=0.0;
            IgnoreApplied=$false; ChildMs=0.0; ChildCalls=0; Candidate=$false; Blocked=$blocked
        }
        continue
    }

    if ($fp -ne $baseline.Fingerprint) { throw "$gate fingerprint differs from G0" }

    $appliedKey = "${child}_IGNORE_APPLIED"
    $callsKey   = "${child}_CALLS"
    $msKey      = "${child}_MS"

    $applied = $m.ContainsKey($appliedKey) -and (Is-One $m[$appliedKey])
    $calls = if ($m.ContainsKey($callsKey)) { [uint64]$m[$callsKey] } else { 0 }
    $childMs = if ($m.ContainsKey($msKey)) { [double]$m[$msKey] } else { -1.0 }

    if ($blocked -eq "SAFE_BYPASS" -and -not $applied) {
        $results += [pscustomobject]@{
            Gate=$gate; Child=$child; GpuMs=$gpuMs; DeltaMs=0.0; Ratio=0.0;
            IgnoreApplied=$false; ChildMs=$childMs; ChildCalls=$calls;
            Candidate=$false; Blocked=$blocked
        }
        if (-not $ContinueAfterSafeBypass) { break }
        continue
    }
    if ($blocked -ne "NONE" -and $blocked) { throw "$gate BLOCKED_AT=$blocked" }

    $delta = $baseline.GpuMs - $gpuMs
    $ratio = if ($baseline.GpuMs -gt 0) { $delta / $baseline.GpuMs } else { 0.0 }
    $agree = $false
    if ($delta -gt 0 -and $childMs -ge 0) {
        $den = [Math]::Max($delta, $childMs)
        $agree = ([Math]::Abs($delta-$childMs)/$den) -le 0.35
    }
    $candidate = $applied -and ($calls -gt 0) -and ($ratio -ge $CollapseRatio) -and $agree

    $row = [pscustomobject]@{
        Gate=$gate; Child=$child; GpuMs=$gpuMs; DeltaMs=$delta; Ratio=$ratio;
        IgnoreApplied=$applied; ChildMs=$childMs; ChildCalls=$calls;
        Candidate=$candidate; Blocked=$blocked
    }
    $results += $row

    # Do not stop at first numerical collapse. Complete the canonical ladder so
    # the winner is selected from comparable same-build observations.
}

$csv = Join-Path $evidence "CHAIN_RESULTS.csv"
$results | Export-Csv -NoTypeInformation -Encoding UTF8 $csv

$eligible = @($results | Where-Object Candidate | Sort-Object Ratio -Descending)
if ($eligible.Count -gt 0) { $winner = $eligible[0] }

$summary = @(
    "CHAIN=DEEP2_GPU_FORWARD_CHAIN_001"
    "CONTROL_RUNTIME_AUTHORITY=0"
    "CONTROL_PROMOTE_AUTHORITY=0"
    "CLAIM_INHERITANCE=0"
    "BASELINE_GATE=G0_REFERENCE"
    "BASELINE_MODEL_FP=$($baseline.Fingerprint)"
    "BASELINE_GPU_FORWARD_MS=$($baseline.GpuMs)"
    "GATES_ATTEMPTED=$($results.Count)"
    "WINNER_OBSERVED=$(if($winner){1}else{0})"
    "WINNER_GATE=$(if($winner){$winner.Gate}else{'NONE'})"
    "WINNER_CHILD=$(if($winner){$winner.Child}else{'NONE'})"
    "WINNER_RATIO=$(if($winner){'{0:R}' -f $winner.Ratio}else{'0'})"
    "NEXT=$(if($winner){'DECOMPOSE_WINNER_CHILD'}else{'RETAIN_GPU_FORWARD_OWNER'})"
    "PROMOTE=0"
)
$summaryPath = Join-Path $evidence "CHAIN_SUMMARY.txt"
$summary | Set-Content -Encoding UTF8 $summaryPath

$results | Format-Table -AutoSize
$summary | ForEach-Object { Write-Host $_ }

if ($RunRecert) {
    if (-not $winner) {
        throw "Re-cert refused: no observed child winner."
    }
    $recert = Join-Path $PSScriptRoot "Invoke-GpuForwardRecert.ps1"
    & $recert -Repo $Repo -Exe $Exe -Model $Model -Prompt $Prompt
}

Write-Host "EVIDENCE=$evidence"
