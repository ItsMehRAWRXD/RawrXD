# update_checker.ps1
# Phase H.3 Batch 2/5: Update Checker and Auto-Update System

param(
    [string]$CurrentVersion = "1.0.0",
    [string]$UpdateEndpoint = "https://api.rawrxd.ai/v1/updates",
    [switch]$AutoInstall,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$UpdateState = @{
    CurrentVersion = $CurrentVersion
    CheckTime = Get-Date -Format "o"
    UpdateAvailable = $false
    LatestVersion = $null
    DownloadUrl = $null
    ReleaseNotes = $null
    UpdateSize = 0
}

function Write-Log($Message, $Level = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message"
}

function Get-LatestVersion {
    Write-Log "Checking for updates at $UpdateEndpoint..."
    
    try {
        $headers = @{
            "User-Agent" = "RawrXD-Updater/$CurrentVersion"
            "X-Platform" = "Windows"
            "X-Arch" = "x64"
        }
        
        $response = Invoke-RestMethod -Uri $UpdateEndpoint -Headers $headers -TimeoutSec 30
        
        return @{
            Version = $response.version
            DownloadUrl = $response.download_url
            ReleaseNotes = $response.release_notes
            Size = $response.size
            Critical = $response.critical
            Hash = $response.sha256
        }
    }
    catch {
        Write-Log "Failed to check for updates: $_" "ERROR"
        return $null
    }
}

function Compare-Versions($v1, $v2) {
    $ver1 = [System.Version]$v1
    $ver2 = [System.Version]$v2
    
    if ($ver1 -lt $ver2) { return -1 }
    if ($ver1 -gt $ver2) { return 1 }
    return 0
}

function Test-Update {
    Write-Log "Current version: $CurrentVersion"
    
    $latest = Get-LatestVersion
    if (-not $latest) {
        Write-Log "Could not retrieve latest version information" "WARNING"
        return $null
    }
    
    $UpdateState.LatestVersion = $latest.Version
    $UpdateState.DownloadUrl = $latest.DownloadUrl
    $UpdateState.ReleaseNotes = $latest.ReleaseNotes
    $UpdateState.UpdateSize = $latest.Size
    
    $comparison = Compare-Versions $CurrentVersion $latest.Version
    
    if ($comparison -lt 0) {
        $UpdateState.UpdateAvailable = $true
        Write-Log "Update available: v$($latest.Version)" "SUCCESS"
        Write-Log "Release notes: $($latest.ReleaseNotes)"
        Write-Log "Download size: $([math]::Round($latest.Size / 1MB, 2)) MB"
        
        if ($latest.Critical) {
            Write-Log "CRITICAL UPDATE - Security patch included" "WARNING"
        }
    }
    else {
        Write-Log "No updates available. Running latest version."
    }
    
    return $UpdateState
}

function Install-Update {
    param($UpdateInfo)
    
    if ($DryRun) {
        Write-Log "DRY RUN: Would download from $($UpdateInfo.DownloadUrl)"
        Write-Log "DRY RUN: Would install version $($UpdateInfo.LatestVersion)"
        return $true
    }
    
    Write-Log "Downloading update..."
    $tempFile = "$env:TEMP\RawrXD_Update_$($UpdateInfo.LatestVersion).exe"
    
    try {
        Invoke-WebRequest -Uri $UpdateInfo.DownloadUrl -OutFile $tempFile -TimeoutSec 300
        Write-Log "Download complete: $tempFile"
        
        # Verify hash if available
        if ($UpdateInfo.Hash) {
            Write-Log "Verifying download..."
            $fileHash = (Get-FileHash -Path $tempFile -Algorithm SHA256).Hash
            if ($fileHash -ne $UpdateInfo.Hash) {
                throw "Hash verification failed! Expected: $($UpdateInfo.Hash), Got: $fileHash"
            }
            Write-Log "Hash verification passed"
        }
        
        # Stop service
        Write-Log "Stopping RawrXD service..."
        Stop-Service -Name "RawrXD" -ErrorAction SilentlyContinue
        
        # Run installer
        Write-Log "Installing update..."
        $process = Start-Process -FilePath $tempFile -ArgumentList "/S" -Wait -PassThru
        
        if ($process.ExitCode -ne 0) {
            throw "Installation failed with exit code $($process.ExitCode)"
        }
        
        # Start service
        Write-Log "Starting RawrXD service..."
        Start-Service -Name "RawrXD" -ErrorAction SilentlyContinue
        
        # Cleanup
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        
        Write-Log "Update installed successfully!" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Update installation failed: $_" "ERROR"
        return $false
    }
}

# Main execution
Write-Log "RawrXD Update Checker v1.0"
Write-Log "Checking for updates..."

$updateInfo = Test-Update

if ($updateInfo -and $updateInfo.UpdateAvailable) {
    if ($AutoInstall) {
        Write-Log "Auto-install enabled, proceeding with update..."
        $success = Install-Update -UpdateInfo $updateInfo
        
        if ($success) {
            exit 0
        }
        else {
            exit 1
        }
    }
    else {
        Write-Log "Update available but auto-install disabled"
        Write-Log "Run with -AutoInstall to automatically install"
        exit 0
    }
}
else {
    Write-Log "No action required"
    exit 0
}
