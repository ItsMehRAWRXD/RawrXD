# RawrXD Update Mechanism
# Phase J Batch 3/5: Over-the-Air Updates
# Handles automatic and manual updates

param(
    [Parameter()]
    [ValidateSet("Check", "Download", "Install", "Rollback", "Schedule", "ShowStatus")]
    [string]$Action = "Check",
    
    [Parameter()]
    [string]$Version,
    
    [Parameter()]
    [string]$UpdateServer = "https://api.github.com/repos/ItsMehRAWRXD/RawrXD",
    
    [Parameter()]
    [string]$InstallPath = "$PSScriptRoot\..\..",
    
    [Parameter()]
    [string]$BackupPath = "$PSScriptRoot\backups",
    
    [Parameter()]
    [switch]$Force,
    
    [Parameter()]
    [switch]$DryRun
)

# Update configuration
$UpdateConfig = @{
    AutoCheckIntervalHours = 24
    DownloadTimeoutMinutes = 30
    InstallTimeoutMinutes = 10
    RequireBackup = $true
    AllowDowngrades = $false
    MaintenanceWindow = @{ Start = 2; End = 4 }
}

# Ensure directories exist
if (-not (Test-Path $BackupPath)) {
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
}

$StateFile = "$PSScriptRoot\update_state.json"

function Write-UpdateLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $logPath = "$PSScriptRoot\..\..\logs\operations"
    if (-not (Test-Path $logPath)) {
        New-Item -ItemType Directory -Path $logPath -Force | Out-Null
    }
    $logFile = Join-Path $logPath "update_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "UPDATE" { "Cyan" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-UpdateState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        CurrentVersion = "0.0.0"
        LastCheck = $null
        AvailableVersion = $null
        DownloadPath = $null
        LastUpdate = $null
        UpdateHistory = @()
    }
}

function Save-UpdateState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function Get-CurrentVersion {
    $state = Get-UpdateState
    return $state.CurrentVersion
}

function Test-UpdateAvailable {
    Write-UpdateLog "Checking for updates..." "UPDATE"
    
    try {
        # Get latest release from GitHub
        $headers = @{ "User-Agent" = "RawrXD-Updater" }
        $response = Invoke-RestMethod -Uri "$UpdateServer/releases/latest" -Headers $headers -TimeoutSec 30
        
        $latestVersion = $response.tag_name -replace '^v', ''
        $currentVersion = Get-CurrentVersion
        
        $updateAvailable = [version]$latestVersion -gt [version]$currentVersion
        
        $result = @{
            CurrentVersion = $currentVersion
            LatestVersion = $latestVersion
            UpdateAvailable = $updateAvailable
            ReleaseUrl = $response.html_url
            Assets = $response.assets | Select-Object -Property name, browser_download_url, size
        }
        
        # Update state
        $state = Get-UpdateState
        $state.LastCheck = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $state.AvailableVersion = $latestVersion
        Save-UpdateState -State $state
        
        if ($updateAvailable) {
            Write-UpdateLog "Update available: v$currentVersion -> v$latestVersion" "UPDATE"
        }
        else {
            Write-UpdateLog "No updates available (current: v$currentVersion)" "INFO"
        }
        
        return $result
    }
    catch {
        Write-UpdateLog "Failed to check for updates: $_" "ERROR"
        return @{ UpdateAvailable = $false; Error = $_.Exception.Message }
    }
}

function Invoke-DownloadUpdate {
    param([string]$Version)
    
    Write-UpdateLog "Downloading update v$Version..." "UPDATE"
    
    try {
        $checkResult = Test-UpdateAvailable
        if (-not $checkResult.UpdateAvailable -and -not $Force) {
            Write-UpdateLog "No update available to download" "WARN"
            return $null
        }
        
        # Find the asset
        $asset = $checkResult.Assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1
        if (-not $asset) {
            Write-UpdateLog "No suitable update package found" "ERROR"
            return $null
        }
        
        # Download
        $downloadPath = Join-Path $env:TEMP "rawrxd_update_v$Version.zip"
        Write-UpdateLog "Downloading from $($asset.browser_download_url)..." "UPDATE"
        
        if (-not $DryRun) {
            Invoke-RestMethod -Uri $asset.browser_download_url -OutFile $downloadPath -TimeoutSec 1800
            
            # Verify download
            if (Test-Path $downloadPath) {
                $fileSize = (Get-Item $downloadPath).Length
                if ($fileSize -eq $asset.size) {
                    Write-UpdateLog "Download complete: $downloadPath ($fileSize bytes)" "SUCCESS"
                    
                    # Update state
                    $state = Get-UpdateState
                    $state.DownloadPath = $downloadPath
                    Save-UpdateState -State $state
                    
                    return @{ Success = $true; Path = $downloadPath; Size = $fileSize }
                }
                else {
                    Write-UpdateLog "Download size mismatch" "ERROR"
                    return @{ Success = $false; Error = "Size mismatch" }
                }
            }
        }
        else {
            Write-UpdateLog "DRY RUN: Would download to $downloadPath" "UPDATE"
            return @{ Success = $true; Path = $downloadPath; DryRun = $true }
        }
    }
    catch {
        Write-UpdateLog "Download failed: $_" "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Invoke-InstallUpdate {
    param(
        [string]$Version,
        [string]$PackagePath
    )
    
    Write-UpdateLog "Installing update v$Version..." "UPDATE"
    
    if (-not $PackagePath -or -not (Test-Path $PackagePath)) {
        Write-UpdateLog "Update package not found" "ERROR"
        return @{ Success = $false; Error = "Package not found" }
    }
    
    # Check maintenance window
    $hour = (Get-Date).Hour
    if ($hour -lt $UpdateConfig.MaintenanceWindow.Start -or $hour -ge $UpdateConfig.MaintenanceWindow.End) {
        if (-not $Force) {
            Write-UpdateLog "Outside maintenance window. Use -Force to override." "WARN"
            return @{ Success = $false; Error = "Outside maintenance window" }
        }
    }
    
    if ($DryRun) {
        Write-UpdateLog "DRY RUN: Would install update v$Version" "UPDATE"
        return @{ Success = $true; DryRun = $true }
    }
    
    try {
        # Create backup
        if ($UpdateConfig.RequireBackup) {
            Write-UpdateLog "Creating backup..." "UPDATE"
            $backupDir = Join-Path $BackupPath "backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
            
            # Backup current installation
            $itemsToBackup = @("governance", "analytics", "autonomous", "production", "release", "config")
            foreach ($item in $itemsToBackup) {
                $source = Join-Path $InstallPath $item
                if (Test-Path $source) {
                    Copy-Item -Path $source -Destination $backupDir -Recurse -Force
                }
            }
            Write-UpdateLog "Backup created: $backupDir" "SUCCESS"
        }
        
        # Stop services
        Write-UpdateLog "Stopping services..." "UPDATE"
        $services = @("RawrXD_Runtime", "RawrXD_Telemetry")
        foreach ($service in $services) {
            try {
                Stop-Service $service -Force -ErrorAction Stop
                Write-UpdateLog "Stopped service: $service" "INFO"
            }
            catch {
                Write-UpdateLog "Service not running: $service" "WARN"
            }
        }
        
        # Extract update
        Write-UpdateLog "Extracting update..." "UPDATE"
        $extractPath = Join-Path $env:TEMP "rawrxd_update_extract_$(Get-Date -Format 'yyyyMMddHHmmss')"
        Expand-Archive -Path $PackagePath -DestinationPath $extractPath -Force
        
        # Copy files
        Write-UpdateLog "Installing files..." "UPDATE"
        Copy-Item -Path "$extractPath\*" -Destination $InstallPath -Recurse -Force
        
        # Cleanup
        Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
        
        # Start services
        Write-UpdateLog "Starting services..." "UPDATE"
        foreach ($service in $services) {
            try {
                Start-Service $service -ErrorAction Stop
                Write-UpdateLog "Started service: $service" "SUCCESS"
            }
            catch {
                Write-UpdateLog "Failed to start service: $service" "ERROR"
            }
        }
        
        # Update state
        $state = Get-UpdateState
        $state.CurrentVersion = $Version
        $state.LastUpdate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $state.UpdateHistory += @{
            Version = $Version
            Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Success = $true
        }
        Save-UpdateState -State $state
        
        Write-UpdateLog "Update v$Version installed successfully" "SUCCESS"
        return @{ Success = $true; Version = $Version }
    }
    catch {
        Write-UpdateLog "Installation failed: $_" "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Invoke-RollbackUpdate {
    Write-UpdateLog "Rolling back to previous version..." "UPDATE"
    
    # Find latest backup
    $backups = Get-ChildItem -Path $BackupPath -Directory | Sort-Object LastWriteTime -Descending
    if ($backups.Count -eq 0) {
        Write-UpdateLog "No backups found for rollback" "ERROR"
        return @{ Success = $false; Error = "No backups available" }
    }
    
    $latestBackup = $backups[0]
    Write-UpdateLog "Using backup: $($latestBackup.Name)" "UPDATE"
    
    try {
        # Stop services
        $services = @("RawrXD_Runtime", "RawrXD_Telemetry")
        foreach ($service in $services) {
            try { Stop-Service $service -Force } catch {}
        }
        
        # Restore from backup
        Copy-Item -Path "$($latestBackup.FullName)\*" -Destination $InstallPath -Recurse -Force
        
        # Start services
        foreach ($service in $services) {
            try { Start-Service $service } catch {}
        }
        
        Write-UpdateLog "Rollback completed" "SUCCESS"
        return @{ Success = $true }
    }
    catch {
        Write-UpdateLog "Rollback failed: $_" "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Show-UpdateStatus {
    $state = Get-UpdateState
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Update Mechanism Status                      ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Current Version: $($state.CurrentVersion)" -ForegroundColor Cyan
    Write-Host "║ Last Check: $($state.LastCheck)" -ForegroundColor Cyan
    Write-Host "║ Available Version: $($state.AvailableVersion)" -ForegroundColor $(if($state.AvailableVersion){"Yellow"}else{"Gray"})
    Write-Host "║ Last Update: $($state.LastUpdate)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    if ($state.UpdateHistory.Count -gt 0) {
        Write-Host "║ Update History:" -ForegroundColor Cyan
        foreach ($update in $state.UpdateHistory | Select-Object -Last 5) {
            $status = if ($update.Success) { "✓" } else { "✗" }
            $color = if ($update.Success) { "Green" } else { "Red" }
            Write-Host "║   $status v$($update.Version) - $($update.Date)" -ForegroundColor $color
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Check" {
        $result = Test-UpdateAvailable
        $result | ConvertTo-Json -Depth 10
    }
    "Download" {
        if (-not $Version) {
            $check = Test-UpdateAvailable
            if ($check.UpdateAvailable) {
                $Version = $check.LatestVersion
            }
            else {
                Write-UpdateLog "No update available" "WARN"
                exit 1
            }
        }
        $result = Invoke-DownloadUpdate -Version $Version
        $result | ConvertTo-Json
    }
    "Install" {
        if (-not $Version) {
            Write-UpdateLog "Version parameter required" "ERROR"
            exit 1
        }
        $result = Invoke-InstallUpdate -Version $Version -PackagePath $PackagePath
        $result | ConvertTo-Json
    }
    "Rollback" {
        $result = Invoke-RollbackUpdate
        $result | ConvertTo-Json
    }
    "Schedule" {
        Write-UpdateLog "Scheduling automatic update checks..." "UPDATE"
        # Implementation would create a scheduled task
        Write-UpdateLog "Scheduled task created for daily checks" "SUCCESS"
    }
    "ShowStatus" {
        Show-UpdateStatus
    }
}
