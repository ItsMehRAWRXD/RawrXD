# RawrXD Update Checker
# Checks for updates and manages version upgrades

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Check", "Download", "Install", "List", "Rollback")]
    [string]$Action = "Check",
    
    [string]$Version = "",
    [string]$Channel = "stable",  # stable, beta, nightly
    [switch]$Force,
    [switch]$Backup,
    [string]$InstallPath = "C:\Program Files\RawrXD"
)

$ErrorActionPreference = "Stop"

# Update sources
$UpdateSources = @{
    Stable = "https://api.github.com/repos/ItsMehRAWRXD/RawrXD/releases/latest"
    Beta = "https://api.github.com/repos/ItsMehRAWRXD/RawrXD/releases"
    Nightly = "https://nightly.rawrxd.ai/latest"
}

$script:CurrentVersion = $null
$script:LatestVersion = $null
$script:UpdateAvailable = $false

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

function Get-CurrentVersion {
    $exePath = "$InstallPath\rawrxd.exe"
    
    if (Test-Path $exePath) {
        try {
            $versionInfo = (Get-Item $exePath).VersionInfo
            $script:CurrentVersion = $versionInfo.ProductVersion
            Write-Success "Current version: $script:CurrentVersion"
        }
        catch {
            Write-Warning "Could not determine current version"
            $script:CurrentVersion = "0.0.0"
        }
    } else {
        Write-Warning "RawrXD not found at $InstallPath"
        $script:CurrentVersion = "0.0.0"
    }
}

function Get-LatestVersion {
    Write-Status "Checking for updates ($Channel channel)..."
    
    try {
        $source = $UpdateSources[$Channel]
        $response = Invoke-RestMethod -Uri $source -Method GET -TimeoutSec 30
        
        if ($Channel -eq "Stable") {
            $script:LatestVersion = $response.tag_name -replace '^v', ''
            $script:DownloadUrl = $response.assets | Where-Object { $_.name -like "*win64*.zip" } | Select-Object -ExpandProperty browser_download_url -First 1
        } else {
            # Beta channel - get first pre-release
            $release = $response | Where-Object { $_.prerelease -eq $true } | Select-Object -First 1
            $script:LatestVersion = $release.tag_name -replace '^v', ''
            $script:DownloadUrl = $release.assets | Where-Object { $_.name -like "*win64*.zip" } | Select-Object -ExpandProperty browser_download_url -First 1
        }
        
        Write-Success "Latest version: $script:LatestVersion"
        
        # Compare versions
        $current = [Version]$script:CurrentVersion
        $latest = [Version]$script:LatestVersion
        
        if ($latest -gt $current) {
            $script:UpdateAvailable = $true
            Write-Warning "Update available: $script:CurrentVersion → $script:LatestVersion"
        } else {
            Write-Success "You are running the latest version"
        }
    }
    catch {
        Write-Error "Failed to check for updates: $_"
    }
}

function Show-VersionInfo {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Version Information" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Current Version: $script:CurrentVersion" -ForegroundColor White
    Write-Host "Latest Version:  $script:LatestVersion" -ForegroundColor White
    Write-Host "Channel:         $Channel" -ForegroundColor White
    Write-Host ""
    
    if ($script:UpdateAvailable) {
        Write-Host "Status: " -NoNewline
        Write-Host "Update Available" -ForegroundColor Yellow
        Write-Host "Download URL: $script:DownloadUrl" -ForegroundColor Gray
    } else {
        Write-Host "Status: " -NoNewline
        Write-Host "Up to Date" -ForegroundColor Green
    }
    
    Write-Host ""
}

function Invoke-Download {
    if (-not $script:UpdateAvailable -and -not $Force) {
        Write-Warning "No update available. Use -Force to download anyway."
        return
    }
    
    if (-not $script:DownloadUrl) {
        Write-Error "No download URL available"
        return
    }
    
    Write-Status "Downloading update..."
    
    $downloadPath = "$env:TEMP\rawrxd-update-$script:LatestVersion.zip"
    
    try {
        Invoke-WebRequest -Uri $script:DownloadUrl -OutFile $downloadPath -UseBasicParsing
        Write-Success "Downloaded to: $downloadPath"
        return $downloadPath
    }
    catch {
        Write-Error "Download failed: $_"
        return $null
    }
}

function Invoke-Install {
    param([string]$PackagePath)
    
    if (-not $PackagePath) {
        $PackagePath = Invoke-Download
        if (-not $PackagePath) { return }
    }
    
    if ($Backup) {
        Write-Status "Creating backup..."
        $backupDir = "$env:TEMP\rawrxd-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Copy-Item -Recurse $InstallPath $backupDir -ErrorAction SilentlyContinue
        Write-Success "Backup created: $backupDir"
    }
    
    Write-Status "Installing update..."
    
    try {
        # Stop services
        Write-Status "Stopping services..."
        Stop-Service -Name "RawrXD" -ErrorAction SilentlyContinue
        
        # Extract update
        $extractPath = "$env:TEMP\rawrxd-update-extract"
        if (Test-Path $extractPath) {
            Remove-Item -Recurse -Force $extractPath
        }
        
        Expand-Archive -Path $PackagePath -DestinationPath $extractPath -Force
        
        # Copy files
        Write-Status "Updating files..."
        Copy-Item -Path "$extractPath\*" -Destination $InstallPath -Recurse -Force
        
        # Start services
        Write-Status "Starting services..."
        Start-Service -Name "RawrXD" -ErrorAction SilentlyContinue
        
        # Cleanup
        Remove-Item -Recurse -Force $extractPath -ErrorAction SilentlyContinue
        Remove-Item -Force $PackagePath -ErrorAction SilentlyContinue
        
        Write-Success "Update installed successfully!"
        Write-Host "Version: $script:LatestVersion" -ForegroundColor Green
    }
    catch {
        Write-Error "Installation failed: $_"
        Write-Warning "You may need to restore from backup"
    }
}

function Get-VersionHistory {
    Write-Status "Fetching version history..."
    
    try {
        $releases = Invoke-RestMethod -Uri "https://api.github.com/repos/ItsMehRAWRXD/RawrXD/releases" -Method GET
        
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "Version History" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        
        foreach ($release in $releases | Select-Object -First 10) {
            $version = $release.tag_name
            $date = [DateTime]$release.published_at
            $prerelease = if ($release.prerelease) { " (Beta)" } else { "" }
            
            Write-Host "$version$prerelease" -ForegroundColor White -NoNewline
            Write-Host " - $($date.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
            
            if ($release.body) {
                $summary = $release.body.Split("`n") | Select-Object -First 3
                foreach ($line in $summary) {
                    if ($line.Trim()) {
                        Write-Host "  $line" -ForegroundColor DarkGray
                    }
                }
            }
            
            Write-Host ""
        }
    }
    catch {
        Write-Error "Failed to fetch version history: $_"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Update Checker" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    Get-CurrentVersion
    
    switch ($Action) {
        "Check" {
            Get-LatestVersion
            Show-VersionInfo
        }
        "Download" {
            Get-LatestVersion
            Invoke-Download
        }
        "Install" {
            Get-LatestVersion
            Invoke-Install
        }
        "List" {
            Get-VersionHistory
        }
        "Rollback" {
            Write-Warning "Rollback functionality not yet implemented"
            Write-Status "Please restore from backup manually if needed"
        }
    }
    
    Write-Host ""
}

Main
