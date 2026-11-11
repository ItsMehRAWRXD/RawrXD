param(
    [int]$DurationSeconds = 60,
    [double]$Drop = 0.05,
    [double]$Jitter = 0.02,
    [double]$Corrupt = 0.01
)

$ErrorActionPreference = 'Stop'
$root = 'd:\rawrxd-ci-bootstrap'
Set-Location $root
$tracePath = Join-Path $root 'headless_trace.log'

Write-Host "[Soak] Cleaning old soak logs..."
Get-ChildItem -Path $root -Filter 'soak_log_*.csv' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
Remove-Item $tracePath -Force -ErrorAction SilentlyContinue

$argA = "--headless-soak=$DurationSeconds --local-port=7777 --remote-port=7778 --stress-on --drop=$Drop --jitter=$Jitter --corrupt=$Corrupt"
$argB = "--headless-soak=$DurationSeconds --peer-b --stress-on --drop=$Drop --jitter=$Jitter --corrupt=$Corrupt"

Write-Host "[Soak] Launching peer A: $argA"
$a = Start-Process -FilePath "$root\IDE_Integration.exe" -ArgumentList $argA -PassThru
Write-Host "[Soak] Launching peer B: $argB"
$b = Start-Process -FilePath "$root\IDE_Integration.exe" -ArgumentList $argB -PassThru

Write-Host "[Soak] Waiting for headless peers to finish..."
$remaining = $DurationSeconds + 20
while ($remaining -gt 0) {
    $slice = [Math]::Min($remaining, 32000)
    Wait-Process -Id $a.Id, $b.Id -Timeout $slice -ErrorAction SilentlyContinue

    $aAlive = ($null -ne (Get-Process -Id $a.Id -ErrorAction SilentlyContinue))
    $bAlive = ($null -ne (Get-Process -Id $b.Id -ErrorAction SilentlyContinue))
    if (-not $aAlive -and -not $bAlive) {
        break
    }

    $remaining -= $slice
}

Write-Host "[Soak] Ensuring peers are stopped..."
foreach ($p in @($a, $b)) {
    if ($null -ne $p -and (Get-Process -Id $p.Id -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $p.Id -Force
    }
}

$exitA = $null
$exitB = $null
try { $exitA = (Get-Process -Id $a.Id -ErrorAction SilentlyContinue).ExitCode } catch {}
try { $exitB = (Get-Process -Id $b.Id -ErrorAction SilentlyContinue).ExitCode } catch {}
if ($null -eq $exitA) { try { $exitA = $a.ExitCode } catch {} }
if ($null -eq $exitB) { try { $exitB = $b.ExitCode } catch {} }

$logs = Get-ChildItem -Path $root -Filter 'soak_log_*.csv' -ErrorAction SilentlyContinue
if (!$logs) {
    Write-Host "[Soak] No logs found."
    exit 1
}

function Get-Report([string]$path) {
    $rows = Import-Csv -Path $path
    if (!$rows -or $rows.Count -lt 2) {
        return [pscustomobject]@{
            File = [IO.Path]::GetFileName($path)
            Samples = ($rows.Count)
            DesyncEvents = 0
            MTBDms = -1
            MaxTickDelta = 0
            FinalTick = 0
        }
    }

    $prev = [int64]$rows[0].DesyncCount
    $eventTimes = @()
    $maxAbsTickDelta = 0
    foreach ($r in $rows) {
        $dc = [int64]$r.DesyncCount
        $wm = [int64]$r.WallMs
        $td = [int]$r.TickDelta
        if ([math]::Abs($td) -gt $maxAbsTickDelta) { $maxAbsTickDelta = [math]::Abs($td) }
        if ($dc -gt $prev) {
            for ($i = 0; $i -lt ($dc - $prev); $i++) { $eventTimes += $wm }
        }
        $prev = $dc
    }

    $mtbd = -1
    if ($eventTimes.Count -ge 2) {
        $sum = 0.0
        for ($i = 1; $i -lt $eventTimes.Count; $i++) {
            $sum += ($eventTimes[$i] - $eventTimes[$i-1])
        }
        $mtbd = [math]::Round($sum / ($eventTimes.Count - 1), 2)
    }

    return [pscustomobject]@{
        File = [IO.Path]::GetFileName($path)
        Samples = $rows.Count
        DesyncEvents = $eventTimes.Count
        MTBDms = $mtbd
        MaxTickDelta = $maxAbsTickDelta
        FinalTick = [int64]$rows[-1].Tick
    }
}

$reports = @()
foreach ($log in $logs) {
    $reports += Get-Report -path $log.FullName
}

$reportPath = Join-Path $root 'mtbd_report.txt'
"Sovereign Soak MTBD Report" | Out-File -FilePath $reportPath -Encoding ASCII
"Generated: $(Get-Date -Format o)" | Out-File -FilePath $reportPath -Append -Encoding ASCII
"DurationSeconds: $DurationSeconds  Drop: $Drop  Jitter: $Jitter  Corrupt: $Corrupt" | Out-File -FilePath $reportPath -Append -Encoding ASCII
"PeerAExitCode: $exitA  PeerBExitCode: $exitB" | Out-File -FilePath $reportPath -Append -Encoding ASCII
"" | Out-File -FilePath $reportPath -Append -Encoding ASCII
$reports | Format-Table -AutoSize | Out-String | Out-File -FilePath $reportPath -Append -Encoding ASCII

if (Test-Path $tracePath) {
    "" | Out-File -FilePath $reportPath -Append -Encoding ASCII
    "Headless Trace Tail:" | Out-File -FilePath $reportPath -Append -Encoding ASCII
    Get-Content $tracePath -Tail 20 | Out-File -FilePath $reportPath -Append -Encoding ASCII
}

Write-Host "[Soak] Reports:"
$reports | Format-Table -AutoSize
Write-Host "[Soak] Exit codes: A=$exitA B=$exitB"
Write-Host "[Soak] Wrote $reportPath"
