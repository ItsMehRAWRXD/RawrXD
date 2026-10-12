<#
.SYNOPSIS
    Agentic + autonomous local-model sweep for the RawrXD / Deep2 workspace.

    Drives every LOCAL model reported by `ollama list` through an autonomous
    agent loop (plan -> act -> observe -> record) against the local Ollama API.
    No interactive input; the loop self-selects its tier order (smallest first
    so early failures are cheap), keeps a per-model evidence JSON under
    evidence/, and continues through the whole list unless -OnlyLocal tiering
    is restricted.

.NOTES
    Storage note: many named blobs are 20-100 GB; the sweep only RUNS models,
    it never re-pulls. Cloud-only entries (SIZE '-') are excluded automatically.
#>
param(
    [string[]]$Models,             # optional explicit allow-list; default = auto
    [int]$MaxModels = 4,           # per invocation budget (keeps each run reviewable)
    [int]$NumPredict = 256,
    [double]$Temperature = 0.2,
    [string]$AgentTask = ''
)

$ErrorActionPreference = 'Stop'
$root = Convert-Path (Join-Path $PSScriptRoot '..')
$evidenceDir = Join-Path $root ('evidence\AGENT_LOCAL_MODEL_SWEEP_{0}' -f (Get-Date -Format 'yyyy-MM-dd'))

# ---------- autonomous agent state ----------
$state = [ordered]@{
    StartedAt  = (Get-Date).ToString('o')
    Root       = $root
    Task       = if ($AgentTask) { $AgentTask } else { 'generate a 3-step plan for benchmarking a GPU inference engine' }
    ModelsDone = @()
    Results    = @()
}

Write-Output ("AUTONOMOUS MODEL SWEEP :: task='{0}' budget={1}" -f $state.Task, $MaxModels)
New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null

# ---------- discovery ----------
if (-not $Models) {
    $sizes = @{}
    foreach ($line in (& ollama list 2>$null)) {
        if ($line -match '^(\S+)\s+[0-9a-f]+\s+([\d\.]+)\s*(GB|MB)') {
            $unit = $Matches[3]
            $val  = [double]$Matches[2]
            if ($unit -eq 'MB') { $val = $val / 1024 }
            $sizes[$Matches[1]] = [math]::Round($val, 2)
        }
    }
    $Models = $sizes.Keys | Sort-Object { $sizes[$_] }
    Write-Output ("DISCOVERED local models: {0} (smallest-first tier order ready)" -f $Models.Count)
}

$Models = @($Models | Select-Object -First $MaxModels)

foreach ($model in $Models) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $rec = [ordered]@{
        Model      = $model
        StartedAt  = (Get-Date).ToString('o')
        Plan       = 'load-on-demand check -> short self-directed generation -> parse -> evidence write'
        Status     = 'pending'
    }

    # --- act: check the blob is present locally (ollama does not need pulling) ---
    $show = & ollama show $model --modelfile 2>$null
    if (-not $show) {
        $rec.Status = 'skipped (no local blob)'
        $state.Results += ([pscustomobject]$rec); continue
    }

    # --- act: one generation through the chat API ---
    $body = @{
        model    = $model
        stream   = $false
        messages = @(
            @{ role = 'system'; content = 'You are an autonomous benchmark agent. Be terse and factual.' }
            @{ role = 'user';   content = $state.Task }
        )
        options  = @{ temperature = $Temperature; num_predict = $NumPredict }
    } | ConvertTo-Json -Depth 6 -Compress

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $resp = Invoke-RestMethod -Uri 'http://localhost:11434/api/chat' -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 900
        $sw.Stop()
        $rec.Status = 'ok'
        $rec.LatencySec = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        $rec.EvalCount  = $resp.eval_count
        $rec.Tps        = if ($sw.Elapsed.TotalSeconds -gt 0) { [math]::Round($resp.eval_count / $sw.Elapsed.TotalSeconds, 1) } else { $null }
        $rec.Preview    = ($resp.message.content -replace '\s+', ' ').Trim().Substring(0, [Math]::Min(400, ($resp.message.content -replace '\s+',' ').Length))
    } catch {
        $sw.Stop()
        $rec.Status = "error: $($_.Exception.Message)"
    }

    # --- observe: write per-model evidence ---
    $file = Join-Path $evidenceDir ("{0}-{1}.json" -f ($model -replace '[:/\\]','_'), $stamp)
    $rec | ConvertTo-Json -Depth 6 | Set-Content -Path $file -Encoding UTF8
    $state.ModelsDone += $model
    $state.Results += ([pscustomobject]$rec)
    Write-Output ("  {0,-52} {1}" -f $model, $rec.Status)
}

# ---------- autonomous summary ----------
$summary = Join-Path $evidenceDir 'SUMMARY.json'
$state | ConvertTo-Json -Depth 6 | Set-Content $summary -Encoding UTF8
Write-Output ''
Write-Output "SWEEP SUMMARY -> $summary"
$state.Results | ForEach-Object { "{0,-52} {1,-8} {2,6}s {3,7} tps" -f $_.Model, $_.Status, $_.LatencySec, $_.Tps }
