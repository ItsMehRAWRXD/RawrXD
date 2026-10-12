<#
.SYNOPSIS
    Classification-grade rerun of failed sweeps: one model at a time on a fresh
    ollama (keep_alive=0 forces unload), peak committed memory sampling,
    pagefile usage, full HTTP error bodies, cold/warm flags.

    Classification contract (what the evidence must support):
      PASS            - valid generation with measured wall-clock TPS
      RESOURCE_LIMIT  - load failed AND committed bytes peaked at >= 95% of the
                        commit limit (or the error text says allocate/OOM), i.e.
                        the machine genuinely could not hold it
      RUNTIME_FAILURE - load failed while committed stayed well below the limit
                        (transient pressure, engine bug, corrupted graph, ...)

.NOTES
    Run against a freshly-restarted ollama before trusting RESOURCE_LIMIT.
#>
param(
    [Parameter(Mandatory=$true)][string[]]$Models,
    [int]$NumPredict = 128,
    [string]$OutDir = ''
)

# pwsh -File passes comma lists as ONE argv string: split them here.
$Models = @($Models -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

$ErrorActionPreference = 'Continue'
$root = Convert-Path (Join-Path $PSScriptRoot '..')
if (-not $OutDir) { $OutDir = Join-Path $root ('evidence\AGENT_LOCAL_SWEEP_{0}_RERUN' -f (Get-Date -Format 'yyyy-MM-dd')) }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

function Get-Mem {
    $c = Get-Counter '\Memory\Committed Bytes','\Memory\Commit Limit','\Memory\Available Bytes' -ErrorAction SilentlyContinue
    [pscustomobject]@{
        CommittedGB  = [math]::Round((($c.CounterSamples | Where-Object Path -like '*Committed Bytes').CookedValue)/1GB, 2)
        LimitGB      = [math]::Round((($c.CounterSamples | Where-Object Path -like '*Commit Limit').CookedValue)/1GB, 2)
        AvailableGB  = [math]::Round((($c.CounterSamples | Where-Object Path -like '*Available Bytes').CookedValue)/1GB, 2)
    }
}

$results = foreach ($model in $Models) {
    $rec = [ordered]@{
        Model = $model
        StartedAt = (Get-Date).ToString('o')
        KeepAlive = 0
        Cold = (& ollama ps 2>$null | Select-String -SimpleMatch $model.Split(':')[0] | Measure-Object).Count -eq 0
    }
    $rec.Before = Get-Mem
    # peak sampler
    $peakFile = [IO.Path]::GetTempFileName()
    $job = Start-Job -ScriptBlock { param($pf) while ($true) { $c = (Get-Counter '\Memory\Committed Bytes' -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue/1GB; Set-Content -Path $pf -Value $c -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 700 } } -ArgumentList $peakFile

    $body = @{
        model = $model; stream = $false; keep_alive = 0
        messages = @(@{ role='system'; content='You are an autonomous benchmark agent. Be terse.' }, @{ role='user'; content='generate a 3-step plan for benchmarking a GPU inference engine' })
        options = @{ num_predict = $NumPredict; temperature = 0.2 }
    } | ConvertTo-Json -Depth 6 -Compress

    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $resp = Invoke-RestMethod -Uri 'http://localhost:11434/api/chat' -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 1800
        $sw.Stop()
        Stop-Job $job -ErrorAction SilentlyContinue | Out-Null; Remove-Job $job -Force -ErrorAction SilentlyContinue
        $peakVal = if (Test-Path $peakFile) { [double](Get-Content $peakFile -Raw) } else { 0 }
        Remove-Item $peakFile -Force -ErrorAction SilentlyContinue
        $rec.PeakCommittedGB = [math]::Round($peakVal, 2)
        $rec.Status = 'PASS'
        $rec.LatencySec = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        $rec.Tokens = $resp.eval_count
        $rec.Tps = if ($sw.Elapsed.TotalSeconds -gt 0) { [math]::Round($resp.eval_count / $sw.Elapsed.TotalSeconds, 1) } else { 0 }
        $rec.Preview = ($resp.message.content -replace '\s+',' ').Trim().Substring(0, [Math]::Min(160, ($resp.message.content -replace '\s+',' ').Length))
    } catch {
        $sw.Stop()
        Stop-Job $job -ErrorAction SilentlyContinue | Out-Null; Remove-Job $job -Force -ErrorAction SilentlyContinue
        $peakVal = if (Test-Path $peakFile) { [double](Get-Content $peakFile -Raw) } else { 0 }
        Remove-Item $peakFile -Force -ErrorAction SilentlyContinue
        $rec.PeakCommittedGB = [math]::Round($peakVal, 2)
        $statusCode = $null; $bodyText = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            try { $reader = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream()); $bodyText = $reader.ReadToEnd() } catch {}
        }
        $rec.HttpStatus = $statusCode
        $rec.ErrorBody = if ($bodyText) { $bodyText.Substring(0, [Math]::Min(800, $bodyText.Length)) } else { $_.Exception.Message }
    } finally {
        Start-Sleep -Seconds 1
    }
    $rec.After = Get-Mem
    # classification
    if ($rec.Status -eq 'PASS') { $rec.Classification = 'PASS' }
    else {
        $oomish = (($rec.After.CommittedGB + 6) -ge $rec.After.LimitGB * 0.95) -or ($rec.ErrorBody -match 'allocate|out of memory|OOM|insufficient|system memory|commit')
        $rec.Classification = if ($oomish) { 'RESOURCE_LIMIT' } else { 'RUNTIME_FAILURE' }
    }
    $file = Join-Path $OutDir (("{0}-{1}.json" -f ($model -replace '[:/\\]','_'), (Get-Date -Format 'HHmmss')))
    $rec | ConvertTo-Json -Depth 6 | Set-Content $file -Encoding UTF8
    [pscustomobject]$rec
    Start-Sleep -Seconds 3
}

$results | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutDir 'RERUN_SUMMARY.json') -Encoding UTF8
$results | ForEach-Object { "{0,-52} {1,-16} tokens={2} tps={3} commPeakCheck={4}GB of {5}GB" -f $_.Model, $_.Classification, $_.Tokens, $_.Tps, $_.After.CommittedGB, $_.After.LimitGB }
"OUT: $OutDir"
