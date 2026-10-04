<#
  bench_sweep.ps1 — RAWRXD_MODEL_BENCHMARK_SWEEP_001

  Benchmarks every locally-backed model ONE BY ONE against the Deep2/Vulkan
  route, and joins the result against the pre-existing Ollama baseline.

  Design rules, in line with the repository's claim discipline:

    * A model that cannot be run is recorded with an EXPLICIT reason. It is
      never silently omitted, because a sweep that quietly drops the models it
      could not handle reads as "everything passed".
    * Throughput is never reported without the gate results that came with it.
      A model can be fast and wrong at the same time, and G8 explicitly does not
      imply G1-G7.
    * Feasibility is decided from MEASURED memory, not assumed.

  Feasibility: Deep2 maps the GGUF, so a model larger than free RAM still opens,
  but every token then faults pages from disk and the number stops being a
  compute measurement. The threshold below is therefore a measurement-validity
  gate, not a capability gate. Exceeding it is reported as
  SKIP_EXCEEDS_MEASUREMENT_BUDGET with the actual size, never as a failure of
  the model.
#>

[CmdletBinding()]
param(
    [string]$Ladder      = 'F:\~dev\rawrxd\inference_authority_ladder.exe',
    [string]$StoreRoot   = 'F:\OllamaModels',
    [string]$OutDir      = 'F:\OllamaModels\rawrxd_bench_results',
    [string]$BaselineTsv = 'F:\OllamaModels\batch_benchmark_results\ollama_fast_20260927_042907.tsv',
    [int]   $Tokens      = 12,
    [int]   $BudgetGB    = 30,
    [int]   $TimeoutSec  = 1800
)

$ErrorActionPreference = 'Continue'
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss') + 'Z'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$tsv = Join-Path $OutDir "deep2_vs_ollama_$stamp.tsv"
$log = Join-Path $OutDir "deep2_vs_ollama_$stamp.log"

function Log($m) {
    $line = "[{0}] {1}" -f (Get-Date).ToString('HH:mm:ss'), $m
    Write-Output $line
    Add-Content -LiteralPath $log -Value $line
}

# ---- measured machine state -------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
$freeRamGB = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
$totalRamGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
Log "TOTAL_RAM_GB=$totalRamGB FREE_RAM_GB=$freeRamGB BUDGET_GB=$BudgetGB"
Log "LADDER=$Ladder"

if (-not (Test-Path $Ladder)) { Log "FATAL ladder not found: $Ladder"; exit 2 }

# ---- real VRAM, read from the harness itself (WMI AdapterRAM is a 32-bit
#      field and reports a bogus 4 GB for a 32 GB card) ------------------------
$probe = & $Ladder 'x' 0 2>&1 | Select-String -Pattern 'localGB=([0-9.]+)' | Select-Object -First 1
$vrams = @()
if ($probe) { $vrams = [regex]::Matches(($probe -join "`n"), 'localGB=([0-9.]+)') | ForEach-Object { [double]$_.Groups[1].Value } }
$maxVramGB = if ($vrams.Count) { [math]::Round(($vrams | Measure-Object -Maximum).Maximum, 2) } else { -1 }
Log "GPU_LOCAL_GB=$($vrams -join ',') MAX_VRAM_GB=$maxVramGB"

# ---- ollama baseline -------------------------------------------------------
$baseline = @{}
if (Test-Path $BaselineTsv) {
    $n = 0
    foreach ($line in (Get-Content $BaselineTsv)) {
        $p = $line -split "`t"
        if ($p.Count -ge 6 -and $p[0] -ne 'model' -and $p[4] -eq 'OK') { $baseline[$p[0]] = $p[5]; $n++ }
    }
    Log "BASELINE_ROWS_OK=$n from $(Split-Path $BaselineTsv -Leaf)"
}

# ---- enumerate every manifest: tag -> weights blob --------------------------
$manifestRoot = Join-Path $StoreRoot 'manifests'
$blobRoot     = Join-Path $StoreRoot 'blobs'
$models = @()
foreach ($mf in (Get-ChildItem $manifestRoot -Recurse -File -ErrorAction SilentlyContinue)) {
    $tag = ($mf.FullName.Substring($manifestRoot.Length + 1)) -replace '\\', '/'
    $tag = $tag -replace '^registry\.ollama\.ai/library/', ''
    try { $j = Get-Content $mf.FullName -Raw | ConvertFrom-Json } catch { continue }
    $w = $j.layers | Where-Object { $_.mediaType -eq 'application/vnd.ollama.image.model' } | Select-Object -First 1
    if (-not $w) { continue }
    $hex = ($w.digest -replace '^sha256:', '')
    $blob = Join-Path $blobRoot "sha256-$hex"
    $models += [pscustomobject]@{
        Tag        = $tag
        Blob       = $blob
        SizeGB     = [math]::Round($w.size / 1GB, 2)
        Exists     = (Test-Path $blob)
        ParamBytes = ($j.layers | Where-Object { $_.mediaType -eq 'application/vnd.ollama.image.params' } | Select-Object -First 1).size
    }
}
Log "MANIFEST_MODELS=$($models.Count)"

$rows = New-Object System.Collections.Generic.List[object]
$done = 0; $skip = 0; $ran = 0; $fail = 0

foreach ($m in ($models | Sort-Object SizeGB)) {
    $done++
    $tag = $m.Tag
    $ollamaTps = if ($baseline.ContainsKey($tag)) { $baseline[$tag] } else { '' }

    $row = [ordered]@{
        tag = $tag
        size_gb = $m.SizeGB
        ollama_tok_per_sec = $ollamaTps
        status = ''
        reason = ''
        deep2_gates_failed = ''
        deep2_g4_numerically_correct = ''
        deep2_decode_tok_per_sec = ''
        deep2_load_ms = ''
        deep2_wall_ms = ''
        deep2_weight_type = ''
        deep2_first_ids = ''
        ratio_deep2_over_ollama = ''
        wall_sec = ''
    }

    if (-not $m.Exists) {
        $row.status = 'SKIP_BLOB_ABSENT'; $row.reason = 'manifest names a blob that is not on disk'
        $rows.Add([pscustomobject]$row); $skip++; continue
    }
    if ($m.SizeGB -gt $BudgetGB) {
        $row.status = 'SKIP_EXCEEDS_MEASUREMENT_BUDGET'
        $row.reason = "weights=$($m.SizeGB)GB exceeds budget=${BudgetGB}GB; mmap would fault from disk and the timing would not be a compute measurement"
        $rows.Add([pscustomobject]$row); $skip++
        Log "SKIP $tag ($($m.SizeGB)GB > ${BudgetGB}GB)"
        continue
    }

    Log "RUN  $tag ($($m.SizeGB)GB)"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $outText = ''
    try {
        $outText = (& $Ladder $m.Blob $Tokens 2>&1 | Out-String)
    } catch { $outText = "EXCEPTION $_" }
    $sw.Stop()

    $row.wall_sec = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    $failMatch = [regex]::Match($outText, 'GATES_FAILED=(\d+)')
    if ($failMatch.Success) { $row.deep2_gates_failed = $failMatch.Groups[1].Value }

    $g4 = [regex]::Match($outText, 'G4\s+NUMERICAL_CORRECTNESS.*?NUMERICALLY_CORRECT=(\d)')
    if ($g4.Success) { $row.deep2_g4_numerically_correct = $g4.Groups[1].Value }

    $dec = [regex]::Match($outText, 'decode=([0-9.]+) tok/s tokens=(\d+) wall=([0-9.]+) ms')
    if ($dec.Success) {
        $row.deep2_decode_tok_per_sec = $dec.Groups[1].Value
        $row.deep2_wall_ms = $dec.Groups[3].Value
    }
    $lm = [regex]::Match($outText, 'load_ms=([0-9.]+).*?weight_type=(\w+)')
    if ($lm.Success) { $row.deep2_load_ms = $lm.Groups[1].Value; $row.deep2_weight_type = $lm.Groups[2].Value }
    $fi = [regex]::Match($outText, 'first_ids=\[([^\]]*)\]')
    if ($fi.Success) { $row.deep2_first_ids = $fi.Groups[1].Value }

    if ($row.deep2_decode_tok_per_sec -eq '' -or $row.deep2_decode_tok_per_sec -eq $null) {
        $row.status = 'FAIL_NO_THROUGHPUT'
        $row.reason = 'the ladder produced no decode= line'
    } elseif ([int]$row.deep2_gates_failed -gt 0) {
        $row.status = 'RAN_GATES_FAILED'
        $row.reason = "ladder reported GATES_FAILED=$($row.deep2_gates_failed); throughput is reported but does not certify correctness"
        $fail++
    } else {
        $row.status = 'RAN_PASS'
        $ran++
    }

    if ($row.deep2_decode_tok_per_sec -and $ollamaTps -ne '' -and [double]$ollamaTps -gt 0) {
        $row.ratio_deep2_over_ollama = [math]::Round([double]$row.deep2_decode_tok_per_sec / [double]$ollamaTps, 4)
    }

    $rows.Add([pscustomobject]$row)
    Log "  -> $($row.status) decode=$($row.deep2_decode_tok_per_sec) tok/s ollama=$ollamaTps g4=$($row.deep2_g4_numerically_correct)"
}

# ---- emit ------------------------------------------------------------------
$rows | Export-Csv -LiteralPath $tsv -Delimiter "`t" -NoTypeInformation -Encoding UTF8

$benched = @($rows | Where-Object { $_.status -like 'RAN_*' })
$summary = @()
$summary += "RAWRXD_MODEL_BENCHMARK_SWEEP_001"
$summary += "RUN_AT_UTC=$stamp"
$summary += "TOTAL_RAM_GB=$totalRamGB FREE_RAM_GB=$freeRamGB"
$summary += "MAX_VRAM_GB=$maxVramGB  BUDGET_GB=$BudgetGB  TOKENS=$Tokens"
$summary += "MANIFEST_MODELS=$($models.Count)"
$summary += "RAN_PASS=$ran  RAN_GATES_FAILED=$fail  SKIPPED=$skip  BENCHMARKED=$($benched.Count)"
$summary += "BASELINE_MODELS_WITH_OLLAMA_TPS=$($baseline.Count)"
$summary += "MODELS_WITH_BOTH_ENGINES=$(@($benched | Where-Object { $_.ollama_tok_per_sec -ne '' }).Count)"
$summary += "MODELS_G4_NUMERICALLY_CORRECT=$(@($benched | Where-Object { $_.deep2_g4_numerically_correct -eq '1' }).Count)"
$summary += "MODELS_G4_NUMERICALLY_WRONG=$(@($benched | Where-Object { $_.deep2_g4_numerically_correct -eq '0' }).Count)"
$summary += "TSV=$tsv"
$summary += "NOTE=A model with G4=0 is NON-REPRODUCIBLE under greedy decoding. Its tok/s is a real measurement of speed and a real measurement of a correctness defect; the two are independent."
$sumFile = Join-Path $OutDir "deep2_vs_ollama_$stamp.summary.txt"
$summary | Set-Content -LiteralPath $sumFile -Encoding UTF8
$summary | ForEach-Object { Log $_ }

Log "DONE benched=$($benched.Count) skip=$skip ran_pass=$ran ran_gates_failed=$fail"
exit 0
