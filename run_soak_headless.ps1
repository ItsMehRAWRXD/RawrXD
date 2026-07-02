param(
    [int]$DurationSec = 1800,
    [double]$DropRate = 0.05,
    [double]$JitterRate = 0.02,
    [double]$CorruptRate = 0.01
)

$ErrorActionPreference = 'Stop'
$root = 'd:\rawrxd-ci-bootstrap'
$exe = Join-Path $root 'IDE_Integration.exe'
$csvA = Join-Path $root 'soak_log_7777.csv'
$csvB = Join-Path $root 'soak_log_7778.csv'
$report = Join-Path $root 'soak_report.txt'

if (-not (Test-Path $exe)) {
    throw "IDE_Integration.exe not found at $exe"
}

Remove-Item $csvA,$csvB,$report -Force -ErrorAction SilentlyContinue

$argsA = "--local-port=7777 --remote-port=7778 --stress-on --drop=$DropRate --jitter=$JitterRate --corrupt=$CorruptRate"
$argsB = "--peer-b --stress-on --drop=$DropRate --jitter=$JitterRate --corrupt=$CorruptRate"

Write-Output "[Soak] Starting peers for $DurationSec seconds"
$pA = Start-Process -FilePath $exe -ArgumentList $argsA -PassThru
$pB = Start-Process -FilePath $exe -ArgumentList $argsB -PassThru

try {
    Start-Sleep -Seconds $DurationSec
} finally {
    if (Get-Process -Id $pA.Id -ErrorAction SilentlyContinue) { Stop-Process -Id $pA.Id -Force }
    if (Get-Process -Id $pB.Id -ErrorAction SilentlyContinue) { Stop-Process -Id $pB.Id -Force }
}

function Analyze-Csv($path, $durationSec) {
    if (-not (Test-Path $path)) {
        return [pscustomobject]@{
            Path = $path
            Rows = 0
            TickStart = 0
            TickEnd = 0
            DesyncStart = 0
            DesyncEnd = 0
            DesyncEvents = 0
            MTBDSeconds = -1
            HardStall = $true
        }
    }

    $rows = Import-Csv $path
    if ($rows.Count -eq 0) {
        return [pscustomobject]@{
            Path = $path
            Rows = 0
            TickStart = 0
            TickEnd = 0
            DesyncStart = 0
            DesyncEnd = 0
            DesyncEvents = 0
            MTBDSeconds = -1
            HardStall = $true
        }
    }

    $tickStart = [int64]$rows[0].Tick
    $tickEnd = [int64]$rows[-1].Tick
    $desyncStart = [int64]$rows[0].DesyncCount
    $desyncEnd = [int64]$rows[-1].DesyncCount
    $desyncEvents = [math]::Max(0, $desyncEnd - $desyncStart)

    $mtbd = if ($desyncEvents -gt 0) { [double]$durationSec / [double]$desyncEvents } else { [double]::PositiveInfinity }
    $hardStall = (($tickEnd - $tickStart) -le 0)

    return [pscustomobject]@{
        Path = $path
        Rows = $rows.Count
        TickStart = $tickStart
        TickEnd = $tickEnd
        DesyncStart = $desyncStart
        DesyncEnd = $desyncEnd
        DesyncEvents = $desyncEvents
        MTBDSeconds = $mtbd
        HardStall = $hardStall
    }
}

$a = Analyze-Csv -path $csvA -durationSec $DurationSec
$b = Analyze-Csv -path $csvB -durationSec $DurationSec

$summary = @()
$summary += "Sovereign Soak Report"
$summary += "DurationSec=$DurationSec DropRate=$DropRate JitterRate=$JitterRate CorruptRate=$CorruptRate"
$summary += ""
$summary += "PeerA: $($a.Path)"
$summary += "  Rows=$($a.Rows) TickStart=$($a.TickStart) TickEnd=$($a.TickEnd)"
$summary += "  DesyncStart=$($a.DesyncStart) DesyncEnd=$($a.DesyncEnd) Events=$($a.DesyncEvents)"
$summary += "  MTBDSeconds=$($a.MTBDSeconds) HardStall=$($a.HardStall)"
$summary += ""
$summary += "PeerB: $($b.Path)"
$summary += "  Rows=$($b.Rows) TickStart=$($b.TickStart) TickEnd=$($b.TickEnd)"
$summary += "  DesyncStart=$($b.DesyncStart) DesyncEnd=$($b.DesyncEnd) Events=$($b.DesyncEvents)"
$summary += "  MTBDSeconds=$($b.MTBDSeconds) HardStall=$($b.HardStall)"

$summary | Set-Content -Path $report -Encoding ASCII
$summary | ForEach-Object { Write-Output $_ }
Write-Output "[Soak] Report written to $report"
