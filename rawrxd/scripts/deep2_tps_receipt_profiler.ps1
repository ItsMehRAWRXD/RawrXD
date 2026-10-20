[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Paths,
    [string]$OutputPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-ReportPaths([string[]]$InputPaths) {
    $found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($inputPath in $InputPaths) {
        $full = [System.IO.Path]::GetFullPath($inputPath)
        if (Test-Path -LiteralPath $full -PathType Leaf) {
            if ([System.IO.Path]::GetFileName($full) -ieq 'flight_recorder_report.json') { $found.Add($full) | Out-Null }
            continue
        }
        if (Test-Path -LiteralPath $full -PathType Container) {
            Get-ChildItem -LiteralPath $full -Filter 'flight_recorder_report.json' -File -Recurse | ForEach-Object { $found.Add($_.FullName) | Out-Null }
        }
    }
    return @($found | Sort-Object)
}

function Get-Median([double[]]$Values) {
    $ordered = @($Values | Sort-Object)
    if ($ordered.Count -eq 0) { return $null }
    $middle = [int][Math]::Floor($ordered.Count / 2)
    if (($ordered.Count % 2) -eq 1) { return [double]$ordered[$middle] }
    return ([double]$ordered[$middle - 1] + [double]$ordered[$middle]) / 2.0
}

function Get-Number([string]$Text, [string]$Name) {
    $match = [regex]::Match($Text, "(?:^|\s)$Name=([0-9]+)")
    if (-not $match.Success) { return $null }
    return [double]$match.Groups[1].Value
}

function Get-PropertyValue($Object, [string]$Name, $Default = $null) {
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}

function Get-TimingSamples([string]$Root) {
    $samples = [System.Collections.Generic.List[object]]::new()
    $logs = @(Get-ChildItem -LiteralPath $Root -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in @('.txt', '.log') })
    foreach ($log in $logs) {
        foreach ($line in (Get-Content -LiteralPath $log.FullName -ErrorAction SilentlyContinue)) {
            if ($line -notmatch 'GPUFWD_TIMING') { continue }
            $samples.Add([pscustomobject]@{
                source = $log.FullName
                upload_ns = Get-Number $line 'upload_ns'
                prime_ns = Get-Number $line 'prime_ns'
                range0_ns = Get-Number $line 'range0_ns'
                range0_gpu_ns = Get-Number $line 'range0_gpu_ns'
                range1_ns = Get-Number $line 'range1_ns'
                range1_gpu_ns = Get-Number $line 'range1_gpu_ns'
                handoff_ns = Get-Number $line 'handoff_ns'
                final_ns = Get-Number $line 'final_ns'
                submits = Get-Number $line 'submits'
                waits = Get-Number $line 'waits'
            })
        }
    }
    return @($samples)
}

$expandedPaths = @($Paths | ForEach-Object { $_ -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } })
$reportPaths = @(Resolve-ReportPaths $expandedPaths)
if ($reportPaths.Count -eq 0) { throw 'No flight_recorder_report.json files were found.' }
$reports = [System.Collections.Generic.List[object]]::new()
$allTiming = [System.Collections.Generic.List[object]]::new()
foreach ($reportPath in $reportPaths) {
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    $passed = @($report.results | Where-Object { $_.pass -and $null -ne $_.decode_tps })
    $tps = @($passed | ForEach-Object { [double]$_.decode_tps })
    $median = Get-Median $tps
    $reports.Add([pscustomobject]@{
        report = $reportPath
        verdict = $report.verdict
        runs = Get-PropertyValue $report 'runs'
        pass_count = $passed.Count
        tokens = Get-PropertyValue $report 'tokens'
        primary_only = Get-PropertyValue $report 'primary_only' $false
        dense_exec = Get-PropertyValue $report 'dense_exec' 'unknown'
        q4_tile = Get-PropertyValue $report 'q4_tile' 'unknown'
        q6_hot = Get-PropertyValue $report 'q6_hot' $false
        median_tps = $median
        min_tps = if ($tps.Count -gt 0) { ($tps | Measure-Object -Minimum).Minimum } else { $null }
        max_tps = if ($tps.Count -gt 0) { ($tps | Measure-Object -Maximum).Maximum } else { $null }
        token_latency_ms = if ($null -ne $median -and $median -gt 0) { 1000.0 / $median } else { $null }
        run_tps = @($tps)
    })
    foreach ($sample in (Get-TimingSamples (Split-Path -Parent $reportPath))) { $allTiming.Add($sample) }
}

$timingSummary = $null
if ($allTiming.Count -gt 0) {
    $fields = @('upload_ns', 'prime_ns', 'range0_ns', 'range0_gpu_ns', 'range1_ns', 'range1_gpu_ns', 'handoff_ns', 'final_ns', 'submits', 'waits')
    $averages = [ordered]@{}
    foreach ($field in $fields) {
        $values = @($allTiming | ForEach-Object { $_.$field } | Where-Object { $null -ne $_ })
        $averages[$field] = if ($values.Count -gt 0) { ($values | Measure-Object -Average).Average } else { $null }
    }
    $timedFields = @('upload_ns', 'prime_ns', 'range0_ns', 'range1_ns', 'handoff_ns', 'final_ns')
    $dominant = $timedFields |
        ForEach-Object { [pscustomobject]@{ name = $_; value = $averages[$_] } } |
        Where-Object { $null -ne $_.value } |
        Sort-Object value -Descending |
        Select-Object -First 1
    $timingSummary = [pscustomobject]@{
        sample_count = $allTiming.Count
        averages = $averages
        dominant_host_interval = if ($null -ne $dominant) { $dominant.name } else { $null }
        samples = @($allTiming)
    }
}

$targets = [ordered]@{}
foreach ($target in @(50, 75, 100, 150)) {
    $current = @($reports | Where-Object { $null -ne $_.median_tps } | Sort-Object median_tps -Descending | Select-Object -First 1)
    $bestTps = if ($current.Count -eq 1) { [double]$current[0].median_tps } else { $null }
    $targets["$target"] = if ($null -ne $bestTps -and $bestTps -gt 0) {
        [ordered]@{ required_ms = 1000.0 / $target; current_best_tps = $bestTps; speedup_needed = $target / $bestTps }
    } else { $null }
}

$result = [ordered]@{
    schema = 'RAWRXD_DEEP2_TPS_RECEIPT_PROFILER_001'
    read_only = $true
    reports = @($reports)
    timing = $timingSummary
    targets = $targets
    generated_utc = [DateTime]::UtcNow.ToString('o')
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path (Get-Location) 'deep2_tps_receipt_profile.json'
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null
$result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Output ("REPORTS={0} TIMING_SAMPLES={1}" -f $reports.Count, $allTiming.Count)
Write-Output "OUTPUT=$OutputPath"
if ($null -ne $timingSummary) { Write-Output "DOMINANT_HOST_INTERVAL=$($timingSummary.dominant_host_interval)" }
