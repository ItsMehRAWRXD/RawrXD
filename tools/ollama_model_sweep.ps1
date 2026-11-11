# ============================================================================
# ollama_model_sweep.ps1  --  RAWRXD_DEEP2_OLLAMA_MODEL_SWEEP_001
# ============================================================================
# Runs the Deep2 runtime dispatch tool against every LOCAL GGUF blob in the
# ollama store (as resolved by tools\resolve_ollama_models.ps1), smallest
# first, and writes a per-model receipt plus a summary table.
#
# Each model runs in the full certification mode (GPU forward vs independent
# CPU reference), so the report carries VERDICT, GPU_ONLY_VERDICT,
# PARITY_VERDICT, gate counts, dispatch counters and the arch/tensor census.
#
# Blobs are de-duplicated: several ollama names can point at the same file
# (llama3.2:latest = llama3.2:3b, gpt-oss:latest = gpt-oss:20b).
#
# Usage:
#   powershell -File tools\ollama_model_sweep.ps1 [-Tokens 3] [-ReportDir F:\rawrxd\sweep]
# ============================================================================
param(
    [int]$Tokens = 3,
    [string]$ReportDir = "F:\rawrxd\sweep",
    [string]$JsonIn = "F:\rawrxd\ollama_model_blobs.json",
    [string]$Exe = "F:\rawrxd\build_rt\deep2_runtime_dispatch.exe",
    [string]$Prompt = "def add(a, b):"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }
$models = Get-Content -LiteralPath $JsonIn -Raw | ConvertFrom-Json
$local = @($models | Where-Object { $_.state -eq "LOCAL_GGUF" } | Sort-Object blobSize)

# De-duplicate by blob path.
$seen = @{}
$queue = @()
foreach ($m in $local) {
    if ($seen.ContainsKey($m.blob)) {
        Write-Host "skip duplicate: $($m.name) == $($seen[$m.blob])"
        continue
    }
    $seen[$m.blob] = $m.name
    $queue += $m
}
Write-Host "models to sweep: $($queue.Count) (of $($models.Count) listed)"

$rows = @()
foreach ($m in $queue) {
    $slug = ($m.name -replace '[^A-Za-z0-9._-]', '_')
    $log = Join-Path $ReportDir "$slug.log"
    # Scale the timeout with size: SHA-256 over a 100 GB blob plus a cold
    # upload dominates small models' cost.
    $minutes = [math]::Max(6, [math]::Ceiling($m.blobSize / 1GB) * 2 + 6)
    Write-Host "=== [$($rows.Count + 1)/$($queue.Count)] $($m.name)  blob=$([math]::Round($m.blobSize/1GB,1))GB  timeout=${minutes}m ==="
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $rc = -1
    try {
        $p = Start-Process -FilePath $Exe `
            -ArgumentList "--model `"$($m.blob)`" --tokens $Tokens --prompt `"$Prompt`"" `
            -RedirectStandardOutput $log -RedirectStandardError "$log.stderr" -PassThru -NoNewWindow
        if (-not $p.WaitForExit($minutes * 60 * 1000)) {
            Write-Warning "  TIMEOUT after $minutes min"
            try { Stop-Process -Id $p.Id -Force } catch {}
            $rc = -99
        } else {
            $rc = $p.ExitCode
        }
    } catch {
        Write-Warning "  launch failed: $_"
        $rc = -98
    }
    $sw.Stop()
    $row = [pscustomobject]@{
        name = $m.name; blob = $m.blob; blobGB = [math]::Round($m.blobSize / 1GB, 1)
        wallSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); exitCode = $rc
        verdict = "?"; gpuOnly = "?"; parity = "?"; cert = "?"; gates = "?"
        arch = "?"; tensors = "?"; gpuCalls = "?"; cpuCalls = "?"; fallback = "?"
        decodeTps = "?"; generated = ""
    }
    if (Test-Path -LiteralPath $log) {
        $text = Get-Content -LiteralPath $log -Raw -ErrorAction SilentlyContinue
        foreach ($kv in @(
            @{ k = "verdict";   p = '(?m)^VERDICT=(\S+)' },
            @{ k = "gpuOnly";   p = 'GPU_ONLY_VERDICT=(\S+)' },
            @{ k = "parity";    p = 'PARITY_VERDICT=(\S+)' },
            @{ k = "cert";      p = 'GPU_CERTIFICATION_VERDICT=(\S+)' },
            @{ k = "gates";     p = '===\s*(\d+ passed, \d+ failed)\s*===' },
            @{ k = "arch";      p = '(?m)^\s+architecture: (\S+)' },
            @{ k = "tensors";   p = '(?m)^\s+tensor_count: (\d+)' },
            @{ k = "gpuCalls";  p = 'GPU_TARGET_FORWARD: gpu_calls=(\d+)' },
            @{ k = "cpuCalls";  p = 'GPU_TARGET_FORWARD: gpu_calls=\d+ cpu_calls=(\d+)' },
            @{ k = "fallback";  p = "GPU_TARGET_FORWARD: gpu_calls=\d+ cpu_calls=\d+ fallback='([^']*)'" },
            @{ k = "decodeTps"; p = 'throughput_decode_tps=(\S+)' })) {
            if ($text -match $kv.p) { $row.$($kv.k) = $matches[1] }
        }
        if ($text -match '(?m)^\s+generated text: "(.*)"') { $row.generated = $matches[1] }
    }
    $rows += $row
    $row | Format-List | Out-String | Write-Host
    $rows | Export-Csv -LiteralPath (Join-Path $ReportDir "sweep_results.csv") -NoTypeInformation -Force
}

# ---- summary ----------------------------------------------------------------
Write-Host "`n===== SWEEP SUMMARY ====="
$rows | Select-Object name, blobGB, wallSeconds, exitCode, verdict, gpuOnly, parity, cert, gates, decodeTps |
    Format-Table -AutoSize
$pass = @($rows | Where-Object { $_.verdict -eq "PASS" }).Count
Write-Host "PASS=$pass FAIL=$($rows.Count - $pass) of $($rows.Count)"

$md = @()
$md += "# Deep2 Ollama Model Sweep"
$md += ""
$md += "- date (UTC): $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm'))"
$md += "- tokens per model: $Tokens"
$md += "- prompt: ``$Prompt``"
$md += "- tool: ``$Exe``"
$md += ""
$md += "| Model | GB | wall s | exit | VERDICT | GPU_ONLY | PARITY | CERT | gates | TPS |"
$md += "|---|---|---|---|---|---|---|---|---|---|"
foreach ($r in $rows) {
    $md += "| $($r.name) | $($r.blobGB) | $($r.wallSeconds) | $($r.exitCode) | $($r.verdict) | $($r.gpuOnly) | $($r.parity) | $($r.cert) | $($r.gates) | $($r.decodeTps) |"
}
$md += ""
$md += "Models that resolve to no local blob (cloud-only in `ollama list`): $((@($models | Where-Object { $_.state -ne 'LOCAL_GGUF' })).Count)"
foreach ($m in @($models | Where-Object { $_.state -ne "LOCAL_GGUF" })) { $md += "- $($m.name)" }
$md | Set-Content -LiteralPath (Join-Path $ReportDir "sweep_report.md") -Encoding utf8
Write-Host "wrote $(Join-Path $ReportDir 'sweep_report.md')"
Write-Host "SWEEP_DONE pass=$pass total=$($rows.Count)"
