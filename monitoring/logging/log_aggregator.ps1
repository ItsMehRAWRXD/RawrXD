# log_aggregator.ps1
# Phase H.5 Batch 4/5: Centralized Log Aggregation

param(
    [string]$LogSourceDir = "${env:ProgramData}\RawrXD\logs",
    [string]$OutputDir = "${env:ProgramData}\RawrXD\logs\aggregated",
    [string]$ElasticsearchUrl = $null,
    [string]$LokiUrl = $null,
    [int]$RetentionDays = 30,
    [switch]$CompressOld
)

$ErrorActionPreference = "Continue"

function Write-Log($Message, $Level = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message"
}

function Get-LogFiles($SourceDir) {
    $logFiles = @()
    
    if (Test-Path $SourceDir) {
        $logFiles += Get-ChildItem -Path $SourceDir -Filter "*.log" -Recurse -ErrorAction SilentlyContinue
        $logFiles += Get-ChildItem -Path $SourceDir -Filter "*.json" -Recurse -ErrorAction SilentlyContinue
    }
    
    return $logFiles
}

function Parse-LogEntry($Line, $Format = "auto") {
    $entry = @{}
    
    switch ($Format) {
        "json" {
            try {
                $entry = $Line | ConvertFrom-Json
            }
            catch {
                $entry.Raw = $Line
            }
        }
        "auto" {
            # Try JSON first
            if ($Line.StartsWith("{")) {
                try {
                    $entry = $Line | ConvertFrom-Json
                }
                catch {
                    # Fall through to text parsing
                }
            }
            
            # Text log parsing (timestamp [LEVEL] message)
            if ($entry.Count -eq 0) {
                if ($Line -match "^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(.+)$") {
                    $entry = @{
                        Timestamp = $matches[1]
                        Level = $matches[2]
                        Message = $matches[3]
                        Source = "text"
                    }
                }
                else {
                    $entry = @{
                        Timestamp = Get-Date -Format "o"
                        Level = "UNKNOWN"
                        Message = $Line
                        Source = "raw"
                    }
                }
            }
        }
    }
    
    return $entry
}

function Send-ToElasticsearch($LogEntry, $Index = "rawrxd-logs") {
    if (-not $ElasticsearchUrl) {
        return
    }
    
    try {
        $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        $indexName = "$index-$(Get-Date -Format 'yyyy.MM.dd')"
        
        $document = @{
            '@timestamp' = $timestamp
            message = $LogEntry.Message
            level = $LogEntry.Level
            source = $LogEntry.Source
            hostname = $env:COMPUTERNAME
        } + $LogEntry
        
        $uri = "$ElasticsearchUrl/$indexName/_doc"
        Invoke-RestMethod -Uri $uri -Method Post -Body ($document | ConvertTo-Json -Depth 5) -ContentType "application/json" -TimeoutSec 10 | Out-Null
    }
    catch {
        Write-Log "Failed to send to Elasticsearch: $_" "WARNING"
    }
}

function Send-ToLoki($LogEntry) {
    if (-not $LokiUrl) {
        return
    }
    
    try {
        $timestampNs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() * 1000000
        
        $payload = @{
            streams = @(
                @{
                    stream = @{
                        job = "rawrxd"
                        hostname = $env:COMPUTERNAME
                        level = $LogEntry.Level
                    }
                    values = @(
                        @($timestampNs.ToString(), $LogEntry.Message)
                    )
                }
            )
        }
        
        $uri = "$LokiUrl/loki/api/v1/push"
        Invoke-RestMethod -Uri $uri -Method Post -Body ($payload | ConvertTo-Json -Depth 5) -ContentType "application/json" -TimeoutSec 10 | Out-Null
    }
    catch {
        Write-Log "Failed to send to Loki: $_" "WARNING"
    }
}

function Invoke-LogAggregation {
    Write-Log "Starting log aggregation..."
    
    $logFiles = Get-LogFiles -SourceDir $LogSourceDir
    Write-Log "Found $($logFiles.Count) log files"
    
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    
    $aggregatedLogs = @()
    $processedCount = 0
    
    foreach ($logFile in $logFiles) {
        Write-Log "Processing: $($logFile.Name)"
        
        $lines = Get-Content $logFile.FullName -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }
            
            $entry = Parse-LogEntry -Line $line
            $entry.File = $logFile.Name
            $entry.Hostname = $env:COMPUTERNAME
            
            $aggregatedLogs += $entry
            
            # Send to external systems
            Send-ToElasticsearch -LogEntry $entry
            Send-ToLoki -LogEntry $entry
            
            $processedCount++
        }
    }
    
    # Save aggregated logs
    $outputFile = Join-Path $OutputDir "aggregated_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $aggregatedLogs | ConvertTo-Json -Depth 5 | Out-File $outputFile
    
    Write-Log "Aggregation complete: $processedCount entries processed"
    Write-Log "Output: $outputFile"
    
    # Cleanup old logs
    Invoke-LogCleanup
}

function Invoke-LogCleanup {
    Write-Log "Cleaning up old logs (retention: $RetentionDays days)..."
    
    $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
    
    $oldFiles = Get-ChildItem -Path $LogSourceDir -File -Recurse | Where-Object { $_.LastWriteTime -lt $cutoffDate }
    
    foreach ($file in $oldFiles) {
        if ($CompressOld -and -not $file.Name.EndsWith(".gz")) {
            # Compress file
            $compressedPath = "$($file.FullName).gz"
            $inputStream = [System.IO.File]::OpenRead($file.FullName)
            $outputStream = [System.IO.File]::Create($compressedPath)
            $gzipStream = New-Object System.IO.Compression.GzipStream($outputStream, [System.IO.Compression.CompressionMode]::Compress)
            $inputStream.CopyTo($gzipStream)
            $gzipStream.Close()
            $outputStream.Close()
            $inputStream.Close()
            
            Remove-Item $file.FullName -Force
            Write-Log "Compressed: $($file.Name)"
        }
        else {
            # Delete old compressed files
            Remove-Item $file.FullName -Force
            Write-Log "Deleted: $($file.Name)"
        }
    }
    
    Write-Log "Cleanup complete"
}

function Start-LogAggregationService {
    Write-Log "Starting RawrXD Log Aggregation Service"
    Write-Log "Source: $LogSourceDir"
    Write-Log "Output: $OutputDir"
    Write-Log "Elasticsearch: $(if ($ElasticsearchUrl) { 'Enabled' } else { 'Disabled' })"
    Write-Log "Loki: $(if ($LokiUrl) { 'Enabled' } else { 'Disabled' })"
    Write-Log ""
    
    while ($true) {
        Invoke-LogAggregation
        Write-Log "Sleeping for 5 minutes..."
        Start-Sleep -Seconds 300
    }
}

# Main execution
Start-LogAggregationService
