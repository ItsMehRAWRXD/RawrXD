# RawrXD Sync Replicator
# Real-time replication to secondary/standby systems

param(
    [string]$PrimaryPath = ".",
    [string]$ReplicaPath,
    [string]$SyncMode = "RealTime",  # RealTime, Scheduled, Manual
    [int]$SyncIntervalSeconds = 60,
    [string[]]$ExcludePaths = @("*.tmp", "logs/*", "backups/*"),
    [switch]$AsService,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# Replication state
$script:ReplicationState = @{
    replicator_id = [Guid]::NewGuid().ToString()
    started_at = Get-Date -Format "o"
    sync_count = 0
    last_sync = $null
    errors = @()
    is_running = $true
}

# File watcher for real-time sync
$script:FileWatcher = $null
$script:SyncQueue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()

function Initialize-Replicator {
    Write-Host "Initializing Sync Replicator..." -ForegroundColor Cyan
    
    # Validate paths
    if (-not (Test-Path $PrimaryPath)) {
        throw "Primary path not found: $PrimaryPath"
    }
    
    if (-not $ReplicaPath) {
        throw "Replica path not specified"
    }
    
    if (-not (Test-Path $ReplicaPath)) {
        New-Item -ItemType Directory -Path $ReplicaPath -Force | Out-Null
        Write-Host "  Created replica directory: $ReplicaPath" -ForegroundColor Gray
    }
    
    # Initial sync
    Write-Host "  Performing initial sync..." -ForegroundColor Gray
    Sync-Directories -Source $PrimaryPath -Dest $ReplicaPath
    
    Write-Host "  Replicator initialized" -ForegroundColor Green
}

function Sync-Directories {
    param([string]$Source, [string]$Dest)
    
    $syncStart = Get-Date
    $filesSynced = 0
    $filesDeleted = 0
    
    # Get all files from source
    $sourceFiles = Get-ChildItem -Path $Source -Recurse -File | 
        Where-Object { 
            $relativePath = $_.FullName.Substring($Source.Length + 1)
            $shouldExclude = $false
            foreach ($exclude in $ExcludePaths) {
                if ($relativePath -like $exclude) {
                    $shouldExclude = $true
                    break
                }
            }
            -not $shouldExclude
        }
    
    foreach ($file in $sourceFiles) {
        $relativePath = $file.FullName.Substring($Source.Length + 1)
        $destPath = Join-Path $Dest $relativePath
        $destDir = Split-Path $destPath -Parent
        
        # Create directory if needed
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }
        
        # Check if file needs syncing
        $needsSync = $true
        if (Test-Path $destPath) {
            $destFile = Get-Item $destPath
            if ($file.LastWriteTime -le $destFile.LastWriteTime -and 
                $file.Length -eq $destFile.Length) {
                $needsSync = $false
            }
        }
        
        if ($needsSync) {
            if ($DryRun) {
                Write-Host "    [DRY RUN] Would sync: $relativePath" -ForegroundColor Yellow
            } else {
                Copy-Item $file.FullName $destPath -Force
            }
            $filesSynced++
        }
    }
    
    # Remove files from replica that don't exist in source
    $replicaFiles = Get-ChildItem -Path $Dest -Recurse -File
    foreach ($file in $replicaFiles) {
        $relativePath = $file.FullName.Substring($Dest.Length + 1)
        $sourcePath = Join-Path $Source $relativePath
        
        if (-not (Test-Path $sourcePath)) {
            if ($DryRun) {
                Write-Host "    [DRY RUN] Would delete: $relativePath" -ForegroundColor Yellow
            } else {
                Remove-Item $file.FullName -Force
            }
            $filesDeleted++
        }
    }
    
    $syncDuration = (Get-Date) - $syncStart
    
    $script:ReplicationState.sync_count++
    $script:ReplicationState.last_sync = Get-Date -Format "o"
    
    return @{
        files_synced = $filesSynced
        files_deleted = $filesDeleted
        duration_seconds = $syncDuration.TotalSeconds
    }
}

function Start-RealTimeSync {
    Write-Host "Starting real-time synchronization..." -ForegroundColor Cyan
    
    # Create file system watcher
    $script:FileWatcher = New-Object System.IO.FileSystemWatcher
    $script:FileWatcher.Path = $PrimaryPath
    $script:FileWatcher.IncludeSubdirectories = $true
    $script:FileWatcher.EnableRaisingEvents = $true
    
    # Register events
    Register-ObjectEvent -InputObject $script:FileWatcher -EventName "Created" -Action {
        $path = $Event.SourceEventArgs.FullPath
        $script:SyncQueue.Enqueue($path)
    } | Out-Null
    
    Register-ObjectEvent -InputObject $script:FileWatcher -EventName "Changed" -Action {
        $path = $Event.SourceEventArgs.FullPath
        $script:SyncQueue.Enqueue($path)
    } | Out-Null
    
    Register-ObjectEvent -InputObject $script:FileWatcher -EventName "Deleted" -Action {
        $path = $Event.SourceEventArgs.FullPath
        $script:SyncQueue.Enqueue("DELETE:$path")
    } | Out-Null
    
    Write-Host "  File watcher registered" -ForegroundColor Green
    Write-Host "  Press Ctrl+C to stop..." -ForegroundColor Yellow
    
    # Process queue
    while ($script:ReplicationState.is_running) {
        $item = $null
        if ($script:SyncQueue.TryDequeue([ref]$item)) {
            Process-SyncItem -Item $item
        }
        Start-Sleep -Milliseconds 100
    }
}

function Process-SyncItem {
    param([string]$Item)
    
    if ($Item.StartsWith("DELETE:")) {
        $path = $Item.Substring(7)
        $relativePath = $path.Substring($PrimaryPath.Length + 1)
        $replicaPath = Join-Path $ReplicaPath $relativePath
        
        if (Test-Path $replicaPath) {
            Remove-Item $replicaPath -Force
            Write-Host "  Deleted: $relativePath" -ForegroundColor Gray
        }
    } else {
        $relativePath = $Item.Substring($PrimaryPath.Length + 1)
        $replicaPath = Join-Path $ReplicaPath $relativePath
        $replicaDir = Split-Path $replicaPath -Parent
        
        if (-not (Test-Path $replicaDir)) {
            New-Item -ItemType Directory -Path $replicaDir -Force | Out-Null
        }
        
        Copy-Item $Item $replicaPath -Force
        Write-Host "  Synced: $relativePath" -ForegroundColor Gray
    }
}

function Start-ScheduledSync {
    Write-Host "Starting scheduled synchronization (every $SyncIntervalSeconds seconds)..." -ForegroundColor Cyan
    
    while ($script:ReplicationState.is_running) {
        $result = Sync-Directories -Source $PrimaryPath -Dest $ReplicaPath
        Write-Host "  Sync completed: $($result.files_synced) files synced, $($result.files_deleted) deleted" -ForegroundColor Gray
        
        Start-Sleep -Seconds $SyncIntervalSeconds
    }
}

function Test-ReplicationHealth {
    Write-Host "Testing replication health..." -ForegroundColor Cyan
    
    $health = @{
        primary_accessible = Test-Path $PrimaryPath
        replica_accessible = Test-Path $ReplicaPath
        sync_lag_seconds = $null
        file_count_match = $false
    }
    
    if ($health.primary_accessible -and $health.replica_accessible) {
        $primaryFiles = (Get-ChildItem -Path $PrimaryPath -Recurse -File).Count
        $replicaFiles = (Get-ChildItem -Path $ReplicaPath -Recurse -File).Count
        
        $health.file_count_match = ($primaryFiles -eq $replicaFiles)
        $health.primary_file_count = $primaryFiles
        $health.replica_file_count = $replicaFiles
        
        if ($script:ReplicationState.last_sync) {
            $lastSync = [DateTime]::Parse($script:ReplicationState.last_sync)
            $health.sync_lag_seconds = ([DateTime]::Now - $lastSync).TotalSeconds
        }
    }
    
    return $health
}

function Save-ReplicationState {
    $statePath = Join-Path $ReplicaPath ".replication-state.json"
    $script:ReplicationState | ConvertTo-Json -Depth 5 | Out-File $statePath
}

# Main execution
function Invoke-SyncReplicator {
    Write-Host "RawrXD Sync Replicator" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host "Mode: $SyncMode" -ForegroundColor Yellow
    Write-Host "Primary: $PrimaryPath" -ForegroundColor Yellow
    Write-Host "Replica: $ReplicaPath" -ForegroundColor Yellow
    if ($DryRun) { Write-Host "*** DRY RUN MODE ***" -ForegroundColor Magenta }
    Write-Host ""
    
    try {
        Initialize-Replicator
        
        switch ($SyncMode) {
            "RealTime" { Start-RealTimeSync }
            "Scheduled" { Start-ScheduledSync }
            "Manual" { 
                $result = Sync-Directories -Source $PrimaryPath -Dest $ReplicaPath
                Write-Host "`nSync complete: $($result.files_synced) files synced" -ForegroundColor Green
            }
        }
        
        Save-ReplicationState
    }
    catch {
        Write-Error "Replication failed: $_"
        exit 1
    }
}

# Handle Ctrl+C
$null = Register-EngineEvent -SourceIdentifier "PowerShell.Exiting" -Action {
    $script:ReplicationState.is_running = $false
    if ($script:FileWatcher) {
        $script:FileWatcher.EnableRaisingEvents = $false
        $script:FileWatcher.Dispose()
    }
    Save-ReplicationState
}

# Run replicator
Invoke-SyncReplicator
