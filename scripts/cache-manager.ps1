# RawrXD Cache Manager
# Manages application cache for improved performance

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Clear", "Warm", "Status", "Configure", "Analyze")]
    [string]$Action = "Status",
    
    [string]$CachePath = "cache",
    [int]$MaxSizeMB = 1024,
    [int]$MaxAgeHours = 24,
    [string[]]$WarmPaths = @(),
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$script:Stats = @{
    FilesCleared = 0
    SpaceReclaimedMB = 0
    CacheHits = 0
    CacheMisses = 0
}

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

function Initialize-CacheManager {
    Write-Status "Cache Manager initialized"
    Write-Status "Cache Path: $CachePath"
    Write-Status "Max Size: $MaxSizeMB MB"
    Write-Status "Max Age: $MaxAgeHours hours"
    
    if (-not (Test-Path $CachePath)) {
        New-Item -ItemType Directory -Path $CachePath -Force | Out-Null
        Write-Status "Created cache directory: $CachePath"
    }
}

function Get-CacheStats {
    if (-not (Test-Path $CachePath)) {
        return @{ Size = 0; Files = 0; OldestFile = $null; NewestFile = $null }
    }
    
    $files = Get-ChildItem -Path $CachePath -File -Recurse -ErrorAction SilentlyContinue
    $totalSize = ($files | Measure-Object -Property Length -Sum).Sum
    $oldest = $files | Sort-Object LastWriteTime | Select-Object -First 1
    $newest = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    
    return @{
        Size = [math]::Round($totalSize / 1MB, 2)
        Files = $files.Count
        OldestFile = $oldest
        NewestFile = $newest
    }
}

function Clear-Cache {
    Write-Status "Clearing cache..."
    
    if (-not (Test-Path $CachePath)) {
        Write-Warning "Cache directory does not exist"
        return
    }
    
    $cutoffTime = (Get-Date).AddHours(-$MaxAgeHours)
    $files = Get-ChildItem -Path $CachePath -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoffTime }
    
    foreach ($file in $files) {
        $sizeMB = [math]::Round($file.Length / 1MB, 2)
        
        if ($DryRun) {
            Write-Status "Would delete: $($file.FullName) ($sizeMB MB)"
        } else {
            try {
                Remove-Item $file.FullName -Force
                $script:Stats.FilesCleared++
                $script:Stats.SpaceReclaimedMB += $sizeMB
                Write-Success "Deleted: $($file.Name)"
            }
            catch {
                Write-Error "Failed to delete $($file.Name): $_"
            }
        }
    }
    
    # Clean empty directories
    $dirs = Get-ChildItem -Path $CachePath -Directory -Recurse |
        Where-Object { $_.GetFiles().Count -eq 0 -and $_.GetDirectories().Count -eq 0 }
    
    foreach ($dir in $dirs) {
        if (-not $DryRun) {
            Remove-Item $dir.FullName -Force
        }
    }
    
    Write-Success "Cache cleared. Files removed: $($script:Stats.FilesCleared), Space reclaimed: $([math]::Round($script:Stats.SpaceReclaimedMB, 2)) MB"
}

function Warm-Cache {
    Write-Status "Warming cache..."
    
    if ($WarmPaths.Count -eq 0) {
        # Default warm paths
        $WarmPaths = @(
            "models/*.gguf"
            "config/*.json"
            "data/*.db"
        )
    }
    
    foreach ($pattern in $WarmPaths) {
        Write-Status "Warming: $pattern"
        
        $files = Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue
        
        foreach ($file in $files) {
            $cacheKey = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($file.FullName))
            $cacheFile = Join-Path $CachePath "$cacheKey.cache"
            
            if (-not (Test-Path $cacheFile) -or $Force) {
                try {
                    # Read file to warm filesystem cache
                    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                    
                    # Store metadata in cache
                    $metadata = @{
                        Path = $file.FullName
                        Size = $file.Length
                        Modified = $file.LastWriteTime
                        Cached = Get-Date -Format "o"
                    } | ConvertTo-Json
                    
                    $metadata | Out-File $cacheFile
                    Write-Success "Cached: $($file.Name)"
                }
                catch {
                    Write-Error "Failed to cache $($file.Name): $_"
                }
            }
        }
    }
}

function Show-CacheStatus {
    Write-Host ""
    Write-Host "Cache Status" -ForegroundColor Cyan
    Write-Host "============" -ForegroundColor Cyan
    
    $stats = Get-CacheStats
    
    Write-Host "Cache Path: $CachePath"
    Write-Host "Total Size: $($stats.Size) MB / $MaxSizeMB MB"
    Write-Host "Files: $($stats.Files)"
    
    if ($stats.OldestFile) {
        Write-Host "Oldest File: $($stats.OldestFile.Name) ($($stats.OldestFile.LastWriteTime))"
    }
    
    if ($stats.NewestFile) {
        Write-Host "Newest File: $($stats.NewestFile.Name) ($($stats.NewestFile.LastWriteTime))"
    }
    
    # Show usage bar
    $percentUsed = [math]::Min(100, ($stats.Size / $MaxSizeMB) * 100)
    $barLength = 50
    $filled = [math]::Round($barLength * $percentUsed / 100)
    $empty = $barLength - $filled
    
    $bar = "[" + ("█" * $filled) + ("░" * $empty) + "]"
    Write-Host "Usage: $bar $([math]::Round($percentUsed, 1))%"
    
    if ($percentUsed -gt 90) {
        Write-Warning "Cache is nearly full. Consider clearing or increasing limit."
    }
}

function Export-CacheConfig {
    $config = @{
        CachePath = $CachePath
        MaxSizeMB = $MaxSizeMB
        MaxAgeHours = $MaxAgeHours
        Timestamp = Get-Date -Format "o"
    }
    
    $config | ConvertTo-Json -Depth 3 | Out-File "cache-config.json"
    Write-Success "Cache configuration exported to cache-config.json"
}

function Analyze-Cache {
    Write-Status "Analyzing cache..."
    
    if (-not (Test-Path $CachePath)) {
        Write-Warning "Cache directory does not exist"
        return
    }
    
    $files = Get-ChildItem -Path $CachePath -File -Recurse -ErrorAction SilentlyContinue
    
    # Group by extension
    $byExtension = $files | Group-Object Extension | Sort-Object Count -Descending
    
    Write-Host ""
    Write-Host "Cache Analysis" -ForegroundColor Cyan
    Write-Host "==============" -ForegroundColor Cyan
    
    Write-Host "Files by Extension:"
    foreach ($group in $byExtension | Select-Object -First 10) {
        $size = ($group.Group | Measure-Object -Property Length -Sum).Sum
        $sizeMB = [math]::Round($size / 1MB, 2)
        Write-Host "  $($group.Name): $($group.Count) files ($sizeMB MB)"
    }
    
    # Find largest files
    Write-Host ""
    Write-Host "Largest Files:"
    $largest = $files | Sort-Object Length -Descending | Select-Object -First 10
    foreach ($file in $largest) {
        $sizeMB = [math]::Round($file.Length / 1MB, 2)
        Write-Host "  $($file.Name): $sizeMB MB"
    }
    
    # Find old files
    $oldFiles = $files | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) }
    if ($oldFiles.Count -gt 0) {
        Write-Host ""
        Write-Warning "Found $($oldFiles.Count) files older than 7 days"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Cache Manager" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-CacheManager
    
    switch ($Action) {
        "Clear" { Clear-Cache }
        "Warm" { Warm-Cache }
        "Status" { Show-CacheStatus }
        "Configure" { Export-CacheConfig }
        "Analyze" { Analyze-Cache }
    }
    
    Write-Host ""
}

Main
