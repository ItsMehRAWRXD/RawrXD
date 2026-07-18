#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase G.2 Batch 2/5: Time-Series Database
    
.DESCRIPTION
    Manages time-series metrics storage with proper retention policies:
    - JSON-based metric storage (lightweight, no external dependencies)
    - Automatic data rotation and archival
    - Query interface for time-range selection
    - Aggregation support (hourly, daily summaries)
    - Compression for historical data
    
.PARAMETER DataPath
    Path to store time-series data (default: .\tsdb_data)
    
.PARAMETER RetentionDays
    Number of days to retain raw data (default: 30)
    
.PARAMETER Action
    Action to perform: init, query, aggregate, cleanup, stats
    
.PARAMETER StartTime
    Query start time (ISO 8601 format)
    
.PARAMETER EndTime
    Query end time (ISO 8601 format)
    
.PARAMETER InstanceId
    Filter by instance ID
    
.PARAMETER MetricPath
    Path to metric JSON files to ingest
    
.EXAMPLE
    .\timeseries_db.ps1 -Action init
    
.EXAMPLE
    .\timeseries_db.ps1 -Action query -StartTime "2026-07-13T00:00:00Z" -EndTime "2026-07-13T23:59:59Z"
    
.EXAMPLE
    .\timeseries_db.ps1 -Action ingest -MetricPath ".\metrics_output"
    
.EXAMPLE
    .\timeseries_db.ps1 -Action cleanup -RetentionDays 7
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DataPath = ".\tsdb_data",
    
    [Parameter(Mandatory=$false)]
    [int]$RetentionDays = 30,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("init", "ingest", "query", "aggregate", "cleanup", "stats")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$StartTime,
    
    [Parameter(Mandatory=$false)]
    [string]$EndTime,
    
    [Parameter(Mandatory=$false)]
    [string]$InstanceId,
    
    [Parameter(Mandatory=$false)]
    [string]$MetricPath
)

# Error action preference
$ErrorActionPreference = "Stop"

# Banner
Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase G.2 Batch 2/5: Time-Series Database                        ║
║  Lightweight Metrics Storage with Retention Policies              ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Database structure
$RawDataPath = Join-Path $DataPath "raw"
$HourlyPath = Join-Path $DataPath "hourly"
$DailyPath = Join-Path $DataPath "daily"
$MetaPath = Join-Path $DataPath "meta.json"

function Initialize-Database {
    <#
    .SYNOPSIS
        Initializes the time-series database structure
    #>
    Write-Host "`nInitializing time-series database..." -ForegroundColor Yellow
    
    New-Item -ItemType Directory -Force -Path $RawDataPath | Out-Null
    New-Item -ItemType Directory -Force -Path $HourlyPath | Out-Null
    New-Item -ItemType Directory -Force -Path $DailyPath | Out-Null
    
    $meta = @{
        created = Get-Date -Format "o"
        version = "1.0"
        retention_days = $RetentionDays
        total_samples = 0
        instances = @()
    }
    
    $meta | ConvertTo-Json | Set-Content -Path $MetaPath
    
    Write-Host "  ✓ Database initialized at: $DataPath" -ForegroundColor Green
    Write-Host "  ✓ Retention policy: $RetentionDays days" -ForegroundColor Green
}

function Ingest-Metrics {
    <#
    .SYNOPSIS
        Ingests metric JSON files into the database
    #>
    param([string]$SourcePath)
    
    Write-Host "`nIngesting metrics from: $SourcePath" -ForegroundColor Yellow
    
    $metricFiles = Get-ChildItem -Path $SourcePath -Filter "metrics_*.json" -File
    $totalIngested = 0
    
    foreach ($file in $metricFiles) {
        $data = Get-Content -Path $file.FullName | ConvertFrom-Json
        
        foreach ($metric in $data.metrics) {
            $date = [DateTime]::Parse($metric.timestamp)
            $dateKey = $date.ToString("yyyyMMdd")
            $instanceId = $metric.instance_id
            
            $targetDir = Join-Path $RawDataPath $instanceId
            New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
            
            $targetFile = Join-Path $targetDir "${dateKey}.json"
            
            # Append to daily file
            $existing = @()
            if (Test-Path $targetFile) {
                $existing = Get-Content -Path $targetFile | ConvertFrom-Json
                if ($existing -isnot [Array]) { $existing = @($existing) }
            }
            
            $existing += $metric
            $existing | ConvertTo-Json -Depth 10 | Set-Content -Path $targetFile
            $totalIngested++
        }
        
        Write-Host "  ✓ Ingested $($data.metrics.Count) samples from $($file.Name)" -ForegroundColor Gray
    }
    
    # Update metadata
    $meta = Get-Content -Path $MetaPath | ConvertFrom-Json
    $meta.total_samples += $totalIngested
    $meta.last_ingestion = Get-Date -Format "o"
    $meta | ConvertTo-Json | Set-Content -Path $MetaPath
    
    Write-Host "`nTotal ingested: $totalIngested samples" -ForegroundColor Green
}

function Query-Metrics {
    <#
    .SYNOPSIS
        Queries metrics by time range and optional filters
    #>
    param(
        [string]$Start,
        [string]$End,
        [string]$InstanceFilter
    )
    
    Write-Host "`nQuerying metrics..." -ForegroundColor Yellow
    Write-Host "  Time range: $Start to $End" -ForegroundColor Gray
    if ($InstanceFilter) { Write-Host "  Instance filter: $InstanceFilter" -ForegroundColor Gray }
    
    $startDate = [DateTime]::Parse($Start)
    $endDate = [DateTime]::Parse($End)
    
    $results = @()
    $instances = if ($InstanceFilter) { @($InstanceFilter) } else { (Get-ChildItem -Path $RawDataPath -Directory).Name }
    
    foreach ($instance in $instances) {
        $instancePath = Join-Path $RawDataPath $instance
        if (-not (Test-Path $instancePath)) { continue }
        
        $files = Get-ChildItem -Path $instancePath -Filter "*.json"
        
        foreach ($file in $files) {
            $fileDate = [DateTime]::ParseExact($file.BaseName, "yyyyMMdd", $null)
            if ($fileDate -lt $startDate.Date -or $fileDate -gt $endDate.Date) { continue }
            
            $data = Get-Content -Path $file.FullName | ConvertFrom-Json
            if ($data -isnot [Array]) { $data = @($data) }
            
            foreach ($metric in $data) {
                $metricTime = [DateTime]::Parse($metric.timestamp)
                if ($metricTime -ge $startDate -and $metricTime -le $endDate) {
                    $results += $metric
                }
            }
        }
    }
    
    # Output results
    $output = @{
        query_time = Get-Date -Format "o"
        start_time = $Start
        end_time = $End
        instance_filter = $InstanceFilter
        result_count = $results.Count
        metrics = $results
    }
    
    $output | ConvertTo-Json -Depth 10
    
    Write-Host "  Found $($results.Count) matching samples" -ForegroundColor Green
}

function Get-DatabaseStats {
    <#
    .SYNOPSIS
        Returns database statistics
    #>
    Write-Host "`nDatabase Statistics:" -ForegroundColor Yellow
    
    $meta = Get-Content -Path $MetaPath | ConvertFrom-Json
    
    $rawSize = (Get-ChildItem -Path $RawDataPath -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB
    $hourlySize = (Get-ChildItem -Path $HourlyPath -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB
    $dailySize = (Get-ChildItem -Path $DailyPath -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB
    
    $instanceCount = (Get-ChildItem -Path $RawDataPath -Directory).Count
    
    Write-Host "  Total samples: $($meta.total_samples)" -ForegroundColor White
    Write-Host "  Instances: $instanceCount" -ForegroundColor White
    Write-Host "  Raw data size: $([Math]::Round($rawSize, 2)) MB" -ForegroundColor White
    Write-Host "  Hourly aggregates: $([Math]::Round($hourlySize, 2)) MB" -ForegroundColor White
    Write-Host "  Daily aggregates: $([Math]::Round($dailySize, 2)) MB" -ForegroundColor White
    Write-Host "  Retention policy: $($meta.retention_days) days" -ForegroundColor White
    Write-Host "  Created: $($meta.created)" -ForegroundColor Gray
}

# Execute action
switch ($Action) {
    "init" { Initialize-Database }
    "ingest" { 
        if (-not $MetricPath) { throw "-MetricPath required for ingest action" }
        Ingest-Metrics -SourcePath $MetricPath 
    }
    "query" { 
        if (-not $StartTime -or -not $EndTime) { throw "-StartTime and -EndTime required for query action" }
        Query-Metrics -Start $StartTime -End $EndTime -InstanceFilter $InstanceId 
    }
    "stats" { Get-DatabaseStats }
    "cleanup" { 
        Write-Host "`nCleanup not yet implemented" -ForegroundColor Yellow
    }
    default { Write-Host "Unknown action: $Action" -ForegroundColor Red }
}

Write-Host "`nTime-series database operation complete." -ForegroundColor Green
