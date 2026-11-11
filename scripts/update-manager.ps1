# RawrXD Update Manager
# Manages software updates and version migrations

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Check", "Download", "Install", "Rollback", "Status", "History")]
    [string]$Action = "Check",
    
    [string]$Version = "",
    [string]$Channel = "stable",
    [switch]$Force,
    [switch]$BackupBeforeUpdate
)

$ErrorActionPreference = "Stop"

$script:UpdateServer = "https://updates.rawrxd.io"
$script:LocalVersionFile = ".version"
$script:UpdateHistoryFile = ".update-history.json"

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

function Initialize-UpdateManager {
    Write-Status "Update Manager initialized"
    Write-Status "Action: $Action"
    Write-Status "Channel: $Channel"
}

function Get-CurrentVersion {
    if (Test-Path $script:LocalVersionFile) {
        return Get-Content $script:LocalVersionFile
    }
    return "0.0.0"
}

function Get-AvailableUpdates {
    Write-Status "Checking for updates..."
    
    $currentVersion = Get-CurrentVersion
    Write-Status "Current version: $currentVersion"
    
    try {
        $url = "$script:UpdateServer/versions/$Channel.json"
        $response = Invoke-RestMethod -Uri $url -Method Get -ErrorAction SilentlyContinue
        
        $updates = @()
        foreach ($version in $response.versions) {
            if ([version]$version -gt [version]$currentVersion) {
                $updates += $version
            }
        }
        
        return $updates | Sort-Object { [version]$_ }
    }
    catch {
        Write-Warning "Could not check for updates: $_"
        return @()
    }
}

function Show-UpdateStatus {
    $currentVersion = Get-CurrentVersion
    $availableUpdates = Get-AvailableUpdates
    
    Write-Host ""
    Write-Host "Update Status" -ForegroundColor Cyan
    Write-Host "=============" -ForegroundColor Cyan
    Write-Host "Current Version: $currentVersion"
    Write-Host "Channel: $Channel"
    
    if ($availableUpdates.Count -eq 0) {
        Write-Success "You are up to date!"
    } else {
        Write-Host ""
        Write-Host "Available Updates:" -ForegroundColor Yellow
        foreach ($update in $availableUpdates) {
            Write-Host "  • $update"
        }
        Write-Host ""
        Write-Host "Latest: $($availableUpdates[-1])"
    }
}

function Download-Update {
    param([string]$TargetVersion)
    
    if (-not $TargetVersion) {
        $available = Get-AvailableUpdates
        if ($available.Count -eq 0) {
            Write-Success "No updates available"
            return
        }
        $TargetVersion = $available[-1]
    }
    
    Write-Status "Downloading update: $TargetVersion"
    
    try {
        $downloadUrl = "$script:UpdateServer/download/$Channel/$TargetVersion.zip"
        $tempPath = "$env:TEMP/rawrxd-update-$TargetVersion.zip"
        
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempPath
        Write-Success "Downloaded to: $tempPath"
        
        return $tempPath
    }
    catch {
        Write-Error "Download failed: $_"
        return $null
    }
}

function Install-UpdatePackage {
    param([string]$UpdateFile, [string]$TargetVersion)
    
    if (-not $TargetVersion) {
        Write-Error "Target version required"
        return
    }
    
    Write-Status "Installing update: $TargetVersion"
    
    if ($BackupBeforeUpdate) {
        Backup-CurrentVersion
    }
    
    try {
        # Extract update
        $extractPath = "$env:TEMP/rawrxd-update-$TargetVersion"
        if (Test-Path $extractPath) {
            Remove-Item $extractPath -Recurse -Force
        }
        
        Expand-Archive -Path $UpdateFile -DestinationPath $extractPath -Force
        
        # Run pre-update script if exists
        $preUpdateScript = "$extractPath/pre-update.ps1"
        if (Test-Path $preUpdateScript) {
            Write-Status "Running pre-update script..."
            & $preUpdateScript
        }
        
        # Copy files
        Write-Status "Applying update..."
        Copy-Item -Path "$extractPath/*" -Destination "." -Recurse -Force
        
        # Update version file
        $TargetVersion | Out-File $script:LocalVersionFile
        
        # Record update in history
        Record-Update -Version $TargetVersion -Status "Success"
        
        # Cleanup
        Remove-Item $extractPath -Recurse -Force
        Remove-Item $UpdateFile -Force
        
        Write-Success "Update to $TargetVersion completed successfully"
        Write-Warning "Please restart RawrXD to apply changes"
    }
    catch {
        Write-Error "Installation failed: $_"
        Record-Update -Version $TargetVersion -Status "Failed" -Error $_.Exception.Message
    }
}

function Backup-CurrentVersion {
    Write-Status "Creating backup..."
    
    $currentVersion = Get-CurrentVersion
    $backupDir = "backups/version-$currentVersion-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    
    if (-not (Test-Path "backups")) {
        New-Item -ItemType Directory -Path "backups" -Force | Out-Null
    }
    
    # Backup key files
    $itemsToBackup = @(
        "bin"
        "config.json"
        "models"
    )
    
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    
    foreach ($item in $itemsToBackup) {
        if (Test-Path $item) {
            Copy-Item -Path $item -Destination $backupDir -Recurse -Force
        }
    }
    
    Write-Success "Backup created: $backupDir"
}

function Invoke-UpdateRollback {
    Write-Status "Rolling back to previous version..."
    
    $history = Get-UpdateHistory
    if ($history.Count -lt 2) {
        Write-Error "No previous version to rollback to"
        return
    }
    
    $previousVersion = $history[-2].version
    Write-Status "Rolling back to version: $previousVersion"
    
    # Find backup
    $backups = Get-ChildItem -Path "backups" -Directory | Sort-Object LastWriteTime -Descending
    if ($backups.Count -eq 0) {
        Write-Error "No backups found for rollback"
        return
    }
    
    $latestBackup = $backups[0]
    Write-Status "Using backup: $($latestBackup.Name)"
    
    # Restore from backup
    try {
        Copy-Item -Path "$($latestBackup.FullName)/*" -Destination "." -Recurse -Force
        $previousVersion | Out-File $script:LocalVersionFile
        Write-Success "Rollback completed"
    }
    catch {
        Write-Error "Rollback failed: $_"
    }
}

function Record-Update {
    param([string]$Version, [string]$Status, [string]$Error = "")
    
    $history = @()
    if (Test-Path $script:UpdateHistoryFile) {
        $history = Get-Content $script:UpdateHistoryFile | ConvertFrom-Json
    }
    
    $history += @{
        version = $Version
        timestamp = Get-Date -Format "o"
        status = $Status
        error = $Error
    }
    
    $history | ConvertTo-Json -Depth 3 | Out-File $script:UpdateHistoryFile
}

function Get-UpdateHistory {
    if (Test-Path $script:UpdateHistoryFile) {
        return Get-Content $script:UpdateHistoryFile | ConvertFrom-Json
    }
    return @()
}

function Show-UpdateHistory {
    $history = Get-UpdateHistory
    
    Write-Host ""
    Write-Host "Update History" -ForegroundColor Cyan
    Write-Host "==============" -ForegroundColor Cyan
    
    if ($history.Count -eq 0) {
        Write-Warning "No update history found"
        return
    }
    
    foreach ($entry in $history) {
        $color = switch ($entry.status) {
            "Success" { "Green" }
            "Failed" { "Red" }
            default { "White" }
        }
        
        Write-Host "  Version: $($entry.version)" -ForegroundColor $color
        Write-Host "    Date: $($entry.timestamp)"
        Write-Host "    Status: $($entry.status)"
        if ($entry.error) {
            Write-Host "    Error: $($entry.error)" -ForegroundColor Red
        }
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Update Manager" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-UpdateManager
    
    switch ($Action) {
        "Check" { Show-UpdateStatus }
        "Download" {
            $file = Download-Update -TargetVersion $Version
            if ($file) {
                Write-Success "Update ready for installation: $file"
            }
        }
        "Install" {
            if (-not $Version) {
                $available = Get-AvailableUpdates
                if ($available.Count -eq 0) {
                    Write-Success "No updates available"
                    return
                }
                $Version = $available[-1]
            }
            
            $updateFile = Download-Update -TargetVersion $Version
            if ($updateFile) {
                Install-UpdatePackage -UpdateFile $updateFile -TargetVersion $Version
            }
        }
        "Rollback" { Invoke-UpdateRollback }
        "Status" { Show-UpdateStatus }
        "History" { Show-UpdateHistory }
    }
    
    Write-Host ""
}

Main
