# RawrXD Log Aggregator
# Aggregates and centralizes logs from multiple sources

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Collect", "Search", "Analyze", "Export", "Tail")]
    [string]$Action = "Collect",
    
    [string]$Source = "",
    [string]$Query = "",
    [string]$StartTime = "",
    [string]$EndTime = "",
    [string]$ExportPath = "",
    [int]$Lines = 100
)

$ErrorActionPreference = "Stop"

$script:LogDir = "logs"
$script:AggregateDir = "logs/aggregated"

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Initialize-LogAggregator {
    if (-not (Test-Path $script:AggregateDir)) {
        New-Item -ItemType Directory -Path $script:AggregateDir -Force | Out-Null
    }
    
    Write-Status "Log Aggregator initialized"
}

function Get-LogSources {
    return @(
        @{ Name = "api"; Path = "logs/api.log"; Type = "application" }
        @{ Name = "model"; Path = "logs/model.log"; Type = "application" }
        @{ Name = "gateway"; Path = "logs/gateway.log"; Type = "application" }
        @{ Name = "system"; Path = "logs/system.log"; Type = "system" }
        @{ Name = "error"; Path = "logs/error.log"; Type = "error" }
        @{ Name = "access"; Path = "logs/access.log"; Type = "access" }
    )
}

function Collect-AllLogs {
    Write-Status "Collecting logs from all sources..."
    
    $sources = Get-LogSources
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $aggregateFile = "$script:AggregateDir/aggregate-$timestamp.log"
    
    $collected = 0
    $totalLines = 0
    
    foreach ($source in $sources) {
        if (Test-Path $source.Path) {
            $lines = Get-Content $source.Path -ErrorAction SilentlyContinue
            if ($lines) {
                $lines | ForEach-Object { "[$($source.Name)] $_" } | Out-File $aggregateFile -Append
                $totalLines += $lines.Count
                $collected++
                Write-Success "Collected from $($source.Name): $($lines.Count) lines"
            }
        }
    }
    
    Write-Host ""
    Write-Success "Aggregation complete: $collected sources, $totalLines lines"
    Write-Host "  Output: $aggregateFile"
}

function Search-LogEntries {
    param([string]$SearchQuery, [string]$SourceFilter)
    
    Write-Status "Searching for: $SearchQuery"
    
    $sources = Get-LogSources
    if ($SourceFilter) {
        $sources = $sources | Where-Object { $_.Name -eq $SourceFilter }
    }
    
    $results = @()
    foreach ($src in $sources) {
        if (Test-Path $src.Path) {
            $matches = Select-String -Path $src.Path -Pattern $SearchQuery
            foreach ($match in $matches) {
                $results += [PSCustomObject]@{
                    Source = $src.Name
                    Line = $match.LineNumber
                    Content = $match.Line
                    File = $src.Path
                }
            }
        }
    }
    
    Write-Host ""
    Write-Host "Search Results" -ForegroundColor Cyan
    Write-Host "==============" -ForegroundColor Cyan
    Write-Host "  Found: $($results.Count) matches"
    Write-Host ""
    
    if ($results.Count -gt 0) {
        foreach ($result in $results | Select-Object -First 20) {
            Write-Host "  [$($result.Source)] Line $($result.Line):" -ForegroundColor Yellow
            Write-Host "    $($result.Content.Substring(0, [Math]::Min(100, $result.Content.Length)))"
        }
        
        if ($results.Count -gt 20) {
            Write-Host "  ... and $($results.Count - 20) more matches"
        }
    }
}

function Analyze-LogPatterns {
    Write-Status "Analyzing log patterns..."
    
    $sources = Get-LogSources
    $analysis = @{
        TotalLines = 0
        ErrorCount = 0
        WarningCount = 0
        InfoCount = 0
        Sources = @{}
    }
    
    foreach ($src in $sources) {
        if (Test-Path $src.Path) {
            $lines = Get-Content $src.Path -ErrorAction SilentlyContinue
            if ($lines) {
                $analysis.TotalLines += $lines.Count
                $analysis.Sources[$src.Name] = $lines.Count
                
                foreach ($line in $lines) {
                    if ($line -match "ERROR|error|Error") { $analysis.ErrorCount++ }
                    if ($line -match "WARN|warning|Warning") { $analysis.WarningCount++ }
                    if ($line -match "INFO|info|Info") { $analysis.InfoCount++ }
                }
            }
        }
    }
    
    Write-Host ""
    Write-Host "Log Analysis" -ForegroundColor Cyan
    Write-Host "============" -ForegroundColor Cyan
    Write-Host "  Total Lines: $($analysis.TotalLines)"
    Write-Host "  Errors: $($analysis.ErrorCount)" -ForegroundColor Red
    Write-Host "  Warnings: $($analysis.WarningCount)" -ForegroundColor Yellow
    Write-Host "  Info: $($analysis.InfoCount)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  By Source:" -ForegroundColor Yellow
    foreach ($src in $analysis.Sources.GetEnumerator()) {
        Write-Host "    $($src.Key): $($src.Value) lines"
    }
}

function Export-LogData {
    param([string]$Path)
    
    if (-not $Path) {
        $Path = "logs-export-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    }
    
    Write-Status "Exporting logs to: $Path"
    
    $data = @{
        exportTime = Get-Date -Format "o"
        sources = @()
    }
    
    $sources = Get-LogSources
    foreach ($src in $sources) {
        if (Test-Path $src.Path) {
            $content = Get-Content $src.Path -Raw -ErrorAction SilentlyContinue
            $data.sources += @{
                name = $src.Name
                type = $src.Type
                path = $src.Path
                content = $content
            }
        }
    }
    
    $data | ConvertTo-Json -Depth 5 | Out-File $Path
    Write-Success "Exported to: $Path"
}

function Watch-LogTail {
    param([string]$SourceName, [int]$LineCount)
    
    $sources = Get-LogSources
    $source = $sources | Where-Object { $_.Name -eq $SourceName } | Select-Object -First 1
    
    if (-not $source) {
        Write-Error "Source not found: $SourceName"
        return
    }
    
    if (-not (Test-Path $source.Path)) {
        Write-Error "Log file not found: $($source.Path)"
        return
    }
    
    Write-Status "Tailing $($source.Name) log (last $LineCount lines)..."
    Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
    Write-Host ""
    
    Get-Content $source.Path -Tail $LineCount -Wait | ForEach-Object {
        Write-Host "[$($source.Name)] $_"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Log Aggregator" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-LogAggregator
    
    switch ($Action) {
        "Collect" { Collect-AllLogs }
        "Search" { Search-LogEntries -SearchQuery $Query -SourceFilter $Source }
        "Analyze" { Analyze-LogPatterns }
        "Export" { Export-LogData -Path $ExportPath }
        "Tail" { Watch-LogTail -SourceName $Source -LineCount $Lines }
    }
    
    Write-Host ""
}

Main
