# RawrXD OMEGA-1 Update System
# Automated update checking, downloading, and installation

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("check", "download", "install", "rollback", "status")]
    [string]$Action = "status",
    
    [string]$InstallDir = "d:\rawrxd",
    [string]$BackupDir = "d:\rawrxd\backups",
    [string]$UpdateUrl = "https://api.github.com/repos/rawrxd/omega1/releases/latest",
    [switch]$Force = $false,
    [switch]$DryRun = $false
)

$ErrorActionPreference = 'Stop'
$script:VersionFile = Join-Path $InstallDir "version.json"
$script:UpdateLog = Join-Path $InstallDir "logs\update.log"

function Write-Log {
    param($Message, $Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Write-Host $logEntry -ForegroundColor $(switch ($Level) {
        "ERROR" { "Red" }
        "WARN" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    })
    
    # Ensure log directory exists
    $logDir = Split-Path $script:UpdateLog -Parent
    if (!(Test-Path $logDir)) {
        New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    }
    
    Add-Content -Path $script:UpdateLog -Value $logEntry -ErrorAction SilentlyContinue
}

function Get-CurrentVersion {
    if (Test-Path $script:VersionFile) {
        try {
            $versionData = Get-Content $script:VersionFile -Raw | ConvertFrom-Json
            return [version]$versionData.version
        }
        catch {
            Write-Log "Failed to parse version file" "WARN"
        }
    }
    return [version]"1.0.0"
}

function Get-LatestVersion {
    param($Url)
    
    try {
        $headers = @{
            "User-Agent" = "RawrXD-UpdateSystem/1.0"
            "Accept" = "application/vnd.github.v3+json"
        }
        
        $response = Invoke-RestMethod -Uri $Url -Headers $headers -TimeoutSec 30
        
        return [PSCustomObject]@{
            Version = [version]($response.tag_name -replace '^v', '')
            DownloadUrl = ($response.assets | Where-Object { $_.name -match "RawrXD-OMEGA1.*\.zip$" }).browser_download_url
            ReleaseNotes = $response.body
            PublishedAt = $response.published_at
        }
    }
    catch {
        Write-Log "Failed to check for updates: $_" "ERROR"
        return $null
    }
}

function Backup-CurrentInstallation {
    Write-Log "Creating backup of current installation..."
    
    $backupTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupPath = Join-Path $BackupDir "backup_$backupTimestamp"
    
    try {
        if (!(Test-Path $BackupDir)) {
            New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
        }
        
        # Backup critical directories
        $dirsToBackup = @("bin", "config", "scripts")
        foreach ($dir in $dirsToBackup) {
            $source = Join-Path $InstallDir $dir
            $dest = Join-Path $backupPath $dir
            if (Test-Path $source) {
                Copy-Item -Path $source -Destination $dest -Recurse -Force
            }
        }
        
        # Backup version file
        if (Test-Path $script:VersionFile) {
            Copy-Item -Path $script:VersionFile -Destination $backupPath -Force
        }
        
        # Create backup manifest
        $manifest = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Version = (Get-CurrentVersion).ToString()
            Path = $backupPath
        }
        $manifest | ConvertTo-Json | Out-File (Join-Path $backupPath "manifest.json")
        
        Write-Log "Backup created: $backupPath" "SUCCESS"
        return $backupPath
    }
    catch {
        Write-Log "Backup failed: $_" "ERROR"
        return $null
    }
}

function Download-Update {
    param($Url, $Destination)
    
    Write-Log "Downloading update from $Url..."
    
    try {
        $tempFile = Join-Path $env:TEMP "rawrxd_update_$(Get-Random).zip"
        
        $progressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Url -OutFile $tempFile -UseBasicParsing
        $progressPreference = 'Continue'
        
        if (Test-Path $tempFile) {
            $fileSize = (Get-Item $tempFile).Length / 1MB
            Write-Log "Downloaded: $([math]::Round($fileSize, 2)) MB" "SUCCESS"
            return $tempFile
        }
    }
    catch {
        Write-Log "Download failed: $_" "ERROR"
    }
    return $null
}

function Verify-UpdatePackage {
    param($PackagePath)
    
    Write-Log "Verifying update package..."
    
    try {
        # Check if it's a valid ZIP
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($PackagePath)
        
        # Check for required files
        $requiredFiles = @("RawrXD-Win32IDE.exe", "RawrXD-InferenceEngine.exe")
        $foundFiles = $zip.Entries | Where-Object { $_.Name -in $requiredFiles }
        
        $zip.Dispose()
        
        if ($foundFiles.Count -eq $requiredFiles.Count) {
            Write-Log "Package verification passed" "SUCCESS"
            return $true
        }
        else {
            Write-Log "Package missing required files" "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Package verification failed: $_" "ERROR"
        return $false
    }
}

function Install-Update {
    param($PackagePath, $BackupPath)
    
    Write-Log "Installing update..."
    
    if ($DryRun) {
        Write-Log "DRY RUN: Would install update from $PackagePath" "WARN"
        return $true
    }
    
    try {
        # Stop running services
        Write-Log "Stopping RawrXD services..."
        Get-Process | Where-Object { $_.ProcessName -match "RawrXD" } | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        # Extract update
        $tempExtract = Join-Path $env:TEMP "rawrxd_update_extract_$(Get-Random)"
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($PackagePath, $tempExtract)
        
        # Copy new files
        Write-Log "Copying new files..."
        $sourceBin = Join-Path $tempExtract "bin"
        $destBin = Join-Path $InstallDir "bin"
        
        if (Test-Path $sourceBin) {
            if (Test-Path $destBin) {
                Remove-Item -Path $destBin -Recurse -Force
            }
            Copy-Item -Path $sourceBin -Destination $destBin -Recurse -Force
        }
        
        # Update version file
        $latestVersion = Get-LatestVersion -Url $UpdateUrl
        if ($latestVersion) {
            $versionData = @{
                version = $latestVersion.Version.ToString()
                updated_at = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                previous_version = (Get-CurrentVersion).ToString()
                backup_path = $BackupPath
            }
            $versionData | ConvertTo-Json | Out-File $script:VersionFile -Force
        }
        
        # Cleanup
        Remove-Item -Path $tempExtract -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $PackagePath -Force -ErrorAction SilentlyContinue
        
        Write-Log "Update installed successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Installation failed: $_" "ERROR"
        return $false
    }
}

function Restore-FromBackup {
    param($BackupPath)
    
    Write-Log "Restoring from backup: $BackupPath..."
    
    try {
        if (!(Test-Path $BackupPath)) {
            Write-Log "Backup not found: $BackupPath" "ERROR"
            return $false
        }
        
        # Stop services
        Get-Process | Where-Object { $_.ProcessName -match "RawrXD" } | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        # Restore directories
        $dirsToRestore = @("bin", "config", "scripts")
        foreach ($dir in $dirsToRestore) {
            $source = Join-Path $BackupPath $dir
            $dest = Join-Path $InstallDir $dir
            if (Test-Path $source) {
                if (Test-Path $dest) {
                    Remove-Item -Path $dest -Recurse -Force
                }
                Copy-Item -Path $source -Destination $dest -Recurse -Force
            }
        }
        
        # Restore version file
        $versionBackup = Join-Path $BackupPath "version.json"
        if (Test-Path $versionBackup) {
            Copy-Item -Path $versionBackup -Destination $script:VersionFile -Force
        }
        
        Write-Log "Restore completed successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Restore failed: $_" "ERROR"
        return $false
    }
}

function Show-UpdateStatus {
    Write-Log "Checking update status..."
    
    $currentVersion = Get-CurrentVersion
    $latestVersion = Get-LatestVersion -Url $UpdateUrl
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║     RawrXD OMEGA-1 Update Status                                               ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    Write-Host "`nCurrent Version: $currentVersion" -ForegroundColor White
    
    if ($latestVersion) {
        Write-Host "Latest Version: $($latestVersion.Version)" -ForegroundColor White
        Write-Host "Published: $($latestVersion.PublishedAt)" -ForegroundColor Gray
        
        if ($latestVersion.Version -gt $currentVersion) {
            Write-Host "`nStatus: UPDATE AVAILABLE" -ForegroundColor Green
            Write-Host "Run 'update_system.ps1 -Action download' to download" -ForegroundColor Yellow
        }
        elseif ($latestVersion.Version -eq $currentVersion) {
            Write-Host "`nStatus: UP TO DATE" -ForegroundColor Green
        }
        else {
            Write-Host "`nStatus: AHEAD OF RELEASE" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "`nStatus: UNABLE TO CHECK" -ForegroundColor Red
    }
    
    # Show backup info
    if (Test-Path $BackupDir) {
        $backups = Get-ChildItem -Path $BackupDir -Directory | Sort-Object CreationTime -Descending
        if ($backups) {
            Write-Host "`nAvailable Backups:" -ForegroundColor Cyan
            $backups | Select-Object -First 3 | ForEach-Object {
                $manifestPath = Join-Path $_.FullName "manifest.json"
                if (Test-Path $manifestPath) {
                    $manifest = Get-Content $manifestPath | ConvertFrom-Json
                    Write-Host "  - $($_.Name) (v$($manifest.Version))" -ForegroundColor Gray
                }
            }
        }
    }
}

# =============================================================================
# Main Execution
# =============================================================================

switch ($Action) {
    "status" {
        Show-UpdateStatus
    }
    
    "check" {
        Show-UpdateStatus
    }
    
    "download" {
        $latest = Get-LatestVersion -Url $UpdateUrl
        if ($latest -and $latest.DownloadUrl) {
            $downloadPath = Download-Update -Url $latest.DownloadUrl -Destination $env:TEMP
            if ($downloadPath) {
                if (Verify-UpdatePackage -PackagePath $downloadPath) {
                    Write-Log "Update ready for installation" "SUCCESS"
                    Write-Log "Run 'update_system.ps1 -Action install' to install" "INFO"
                }
            }
        }
    }
    
    "install" {
        $latest = Get-LatestVersion -Url $UpdateUrl
        if ($latest) {
            $downloadPath = Download-Update -Url $latest.DownloadUrl -Destination $env:TEMP
            if ($downloadPath -and (Verify-UpdatePackage -PackagePath $downloadPath)) {
                $backupPath = Backup-CurrentInstallation
                if ($backupPath) {
                    Install-Update -PackagePath $downloadPath -BackupPath $backupPath
                }
            }
        }
    }
    
    "rollback" {
        if (Test-Path $BackupDir) {
            $backups = Get-ChildItem -Path $BackupDir -Directory | Sort-Object CreationTime -Descending
            if ($backups) {
                $latestBackup = $backups[0]
                Restore-FromBackup -BackupPath $latestBackup.FullName
            }
            else {
                Write-Log "No backups available" "ERROR"
            }
        }
        else {
            Write-Log "Backup directory not found" "ERROR"
        }
    }
}
