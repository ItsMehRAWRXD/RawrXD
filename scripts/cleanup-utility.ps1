# RawrXD Cleanup Utility
# Cleans up temporary files, build artifacts, and cache

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Temp", "Build", "Cache", "Logs", "All", "Aggressive")]
    [string]$CleanupType = "Temp",
    
    [string[]]$AdditionalPaths = @(),
    [int]$MaxAgeDays = 7,
    [switch]$DryRun,
    [switch]$Force,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

$script:Stats = @{
    FilesDeleted = 0
    DirectoriesDeleted = 0
    SpaceReclaimedMB = 0
    Errors = 0
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

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Initialize-Cleanup {
    Write-Status "RawrXD Cleanup Utility"
    Write-Status "Cleanup Type: $CleanupType"
    Write-Status "Max Age: $MaxAgeDays days"
    
    if ($DryRun) {
        Write-Warning "DRY RUN MODE - No files will be deleted"
    }
    
    if ($CleanupType -eq "Aggressive" -and -not $Force) {
        throw "Aggressive cleanup requires -Force flag"
    }
}

function Remove-ItemsSafely {
    param(
        [string[]]$Paths,
        [string]$Description
    )
    
    foreach ($path in $Paths) {
        if (-not (Test-Path $path)) {
            continue
        }
        
        $item = Get-Item $path
        $size = 0
        
        if ($item.PSIsContainer) {
            try {
                $size = (Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue | 
                    Measure-Object -Property Length -Sum).Sum
            }
            catch {
                $size = 0
            }
        } else {
            $size = $item.Length
        }
        
        $sizeMB = [math]::Round($size / 1MB, 2)
        
        if ($DryRun) {
            Write-Status "Would delete $Description`: $path ($sizeMB MB)"
        } else {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-Success "Deleted $Description`: $path ($sizeMB MB)"
                
                if ($item.PSIsContainer) {
                    $script:Stats.DirectoriesDeleted++
                } else {
                    $script:Stats.FilesDeleted++
                }
                $script:Stats.SpaceReclaimedMB += $sizeMB
            }
            catch {
                Write-Error "Failed to delete $path`: $_"
                $script:Stats.Errors++
            }
        }
    }
}

function Clear-TempFiles {
    Write-Status "Cleaning temporary files..."
    
    $tempPaths = @(
        $env:TEMP
        "$env:LOCALAPPDATA\Temp"
        "C:\Windows\Temp"
    )
    
    $cutoffDate = (Get-Date).AddDays(-$MaxAgeDays)
    
    foreach ($tempPath in $tempPaths) {
        if (-not (Test-Path $tempPath)) {
            continue
        }
        
        Write-Status "Scanning: $tempPath"
        
        $oldFiles = Get-ChildItem -Path $tempPath -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoffDate -and $_.Name -like "*rawrxd*" -or $_.Name -like "*tmp*" -or $_.Name -like "*temp*" }
        
        Remove-ItemsSafely -Paths $oldFiles.FullName -Description "temp file"
    }
}

function Clear-BuildArtifacts {
    Write-Status "Cleaning build artifacts..."
    
    $buildPaths = @(
        "build"
        "out"
        "bin\Debug"
        "bin\Release"
        "obj"
        "CMakeFiles"
        "CMakeCache.txt"
        "*.obj"
        "*.pdb"
        "*.ilk"
        "*.exe"
        "*.dll"
        "*.lib"
    )
    
    foreach ($pattern in $buildPaths) {
        $items = Get-ChildItem -Path "." -Filter $pattern -Recurse -ErrorAction SilentlyContinue
        Remove-ItemsSafely -Paths $items.FullName -Description "build artifact"
    }
}

function Clear-Cache {
    Write-Status "Cleaning cache directories..."
    
    $cachePaths = @(
        ".cache"
        "cache"
        "node_modules"
        ".pytest_cache"
        "__pycache__"
        "*.pyc"
        ".mypy_cache"
        ".tox"
        ".eggs"
        "*.egg-info"
    )
    
    foreach ($pattern in $cachePaths) {
        $items = Get-ChildItem -Path "." -Filter $pattern -Recurse -ErrorAction SilentlyContinue
        Remove-ItemsSafely -Paths $items.FullName -Description "cache"
    }
}

function Clear-OldLogs {
    Write-Status "Cleaning old log files..."
    
    if (-not (Test-Path "logs")) {
        return
    }
    
    $cutoffDate = (Get-Date).AddDays(-$MaxAgeDays)
    
    $oldLogs = Get-ChildItem -Path "logs" -Filter "*.log" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoffDate }
    
    Remove-ItemsSafely -Paths $oldLogs.FullName -Description "old log"
}

function Clear-Aggressive {
    Write-Status "Performing aggressive cleanup..."
    
    # This is the aggressive mode - be very careful
    $aggressivePaths = @(
        "downloads\*.tmp"
        "downloads\*.partial"
        "models\*.tmp"
        "*.log.old"
        "*.bak"
        "*.backup"
    )
    
    foreach ($pattern in $aggressivePaths) {
        $items = Get-ChildItem -Path "." -Filter $pattern -Recurse -ErrorAction SilentlyContinue
        Remove-ItemsSafely -Paths $items.FullName -Description "aggressive cleanup"
    }
    
    # Clean NuGet cache
    $nugetCache = "$env:USERPROFILE\.nuget\packages"
    if (Test-Path $nugetCache) {
        $oldPackages = Get-ChildItem $nugetCache -Directory |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) }
        Remove-ItemsSafely -Paths $oldPackages.FullName -Description "old NuGet package"
    }
    
    # Clean npm cache
    $npmCache = "$env:APPDATA\npm-cache"
    if (Test-Path $npmCache) {
        Remove-ItemsSafely -Paths $npmCache -Description "npm cache"
    }
}

function Clear-AdditionalPaths {
    if ($AdditionalPaths.Count -eq 0) {
        return
    }
    
    Write-Status "Cleaning additional paths..."
    
    foreach ($path in $AdditionalPaths) {
        if (Test-Path $path) {
            Remove-ItemsSafely -Paths $path -Description "custom path"
        }
    }
}

function Show-Summary {
    Write-Host ""
    Write-Host "Cleanup Summary" -ForegroundColor Cyan
    Write-Host "===============" -ForegroundColor Cyan
    Write-Host "Files deleted: $($script:Stats.FilesDeleted)"
    Write-Host "Directories deleted: $($script:Stats.DirectoriesDeleted)"
    Write-Host "Space reclaimed: $([math]::Round($script:Stats.SpaceReclaimedMB, 2)) MB"
    
    if ($script:Stats.Errors -gt 0) {
        Write-Host "Errors encountered: $($script:Stats.Errors)" -ForegroundColor Red
    }
    
    if ($DryRun) {
        Write-Host ""
        Write-Warning "This was a dry run. No files were actually deleted."
        Write-Status "Run without -DryRun to perform actual cleanup."
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Cleanup Utility" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Cleanup
    
    switch ($CleanupType) {
        "Temp" { Clear-TempFiles }
        "Build" { Clear-BuildArtifacts }
        "Cache" { Clear-Cache }
        "Logs" { Clear-OldLogs }
        "All" {
            Clear-TempFiles
            Clear-BuildArtifacts
            Clear-Cache
            Clear-OldLogs
        }
        "Aggressive" {
            Clear-TempFiles
            Clear-BuildArtifacts
            Clear-Cache
            Clear-OldLogs
            Clear-Aggressive
        }
    }
    
    Clear-AdditionalPaths
    Show-Summary
    
    Write-Host ""
}

Main
