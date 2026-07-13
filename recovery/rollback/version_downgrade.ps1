# version_downgrade.ps1
# Phase H.4 Batch 1/5: Emergency Version Downgrade System

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetVersion,
    
    [string]$InstallDir = "${env:ProgramFiles}\RawrXD",
    [string]$BackupDir = "${env:ProgramData}\RawrXD\Backups",
    [switch]$Force,
    [switch]$PreserveData
)

$ErrorActionPreference = "Stop"

function Write-Log($Message, $Level = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Get-CurrentVersion {
    $exePath = Join-Path $InstallDir "RawrXD.exe"
    if (Test-Path $exePath) {
        $versionInfo = (Get-Item $exePath).VersionInfo
        return $versionInfo.ProductVersion
    }
    return $null
}

function Test-VersionCompatibility($FromVersion, $ToVersion) {
    Write-Log "Checking compatibility between v$FromVersion and v$TargetVersion..."
    
    # Parse versions
    $from = [System.Version]$FromVersion
    $to = [System.Version]$ToVersion
    
    # Major version downgrade requires data migration
    if ($to.Major -lt $from.Major) {
        Write-Log "Major version downgrade detected - data migration required" "WARNING"
        return @{ Compatible = $false; RequiresMigration = $true }
    }
    
    # Minor version downgrade - usually safe
    if ($to.Minor -lt $from.Minor) {
        Write-Log "Minor version downgrade - configuration compatibility check needed" "WARNING"
        return @{ Compatible = $true; RequiresMigration = $false; Warning = "Minor version change" }
    }
    
    return @{ Compatible = $true; RequiresMigration = $false }
}

function Invoke-VersionDowngrade {
    Write-Log "Starting emergency version downgrade..."
    Write-Log "Current: $(Get-CurrentVersion)"
    Write-Log "Target: $TargetVersion"
    
    # Check if target version backup exists
    $targetBackup = Join-Path $BackupDir "v$TargetVersion"
    if (-not (Test-Path $targetBackup)) {
        Write-Log "No backup found for v$TargetVersion" "ERROR"
        Write-Log "Attempting download from release server..." "WARNING"
        
        # Download from GitHub releases
        $downloadUrl = "https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$TargetVersion/RawrXD-$TargetVersion-x64.msi"
        $tempFile = "$env:TEMP\RawrXD_Downgrade_$TargetVersion.msi"
        
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -TimeoutSec 300
            Write-Log "Downloaded v$TargetVersion installer"
            
            # Install the older version
            Write-Log "Installing v$TargetVersion..."
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$tempFile`" /qn /norestart" -Wait -PassThru
            
            if ($process.ExitCode -ne 0) {
                throw "Installation failed with exit code $($process.ExitCode)"
            }
            
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Log "Failed to download/install v$TargetVersion: $_" "ERROR"
            return $false
        }
    }
    else {
        Write-Log "Restoring from backup: $targetBackup"
        
        # Stop service
        Write-Log "Stopping RawrXD service..."
        Stop-Service -Name "RawrXD" -ErrorAction SilentlyContinue
        
        # Backup current before downgrade
        $currentVersion = Get-CurrentVersion
        $currentBackup = Join-Path $BackupDir "v$currentVersion-pre-downgrade-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Write-Log "Creating pre-downgrade backup: $currentBackup"
        Copy-Item -Path $InstallDir -Destination $currentBackup -Recurse -Force
        
        # Restore target version
        Write-Log "Restoring v$TargetVersion files..."
        Remove-Item -Path "$InstallDir\*" -Recurse -Force -ErrorAction SilentlyContinue
        Copy-Item -Path "$targetBackup\*" -Destination $InstallDir -Recurse -Force
        
        # Start service
        Write-Log "Starting RawrXD service..."
        Start-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    }
    
    # Verify downgrade
    $newVersion = Get-CurrentVersion
    if ($newVersion -eq $TargetVersion) {
        Write-Log "Downgrade to v$TargetVersion completed successfully" "SUCCESS"
        return $true
    }
    else {
        Write-Log "Downgrade verification failed. Current version: $newVersion" "ERROR"
        return $false
    }
}

# Main execution
Write-Log "RawrXD Emergency Version Downgrade Tool"

$currentVersion = Get-CurrentVersion
if (-not $currentVersion) {
    Write-Log "Cannot determine current version" "ERROR"
    exit 1
}

if ($currentVersion -eq $TargetVersion) {
    Write-Log "Already running v$TargetVersion"
    exit 0
}

# Check compatibility
$compat = Test-VersionCompatibility -FromVersion $currentVersion -ToVersion $TargetVersion
if (-not $compat.Compatible -and -not $Force) {
    Write-Log "Version downgrade not compatible. Use -Force to override." "ERROR"
    exit 1
}

if ($compat.RequiresMigration -and -not $PreserveData) {
    Write-Log "Data migration required. Use -PreserveData to include data migration." "WARNING"
}

# Confirm
if (-not $Force) {
    Write-Host ""
    Write-Host "WARNING: This will downgrade RawrXD from v$currentVersion to v$TargetVersion" -ForegroundColor Yellow
    Write-Host "Current configuration and data may be affected." -ForegroundColor Yellow
    $confirm = Read-Host "Type 'DOWNGRADE' to confirm"
    if ($confirm -ne "DOWNGRADE") {
        Write-Log "Downgrade cancelled by user"
        exit 0
    }
}

# Execute downgrade
if (Invoke-VersionDowngrade) {
    Write-Log "Emergency downgrade completed" "SUCCESS"
    exit 0
}
else {
    Write-Log "Emergency downgrade failed" "ERROR"
    exit 1
}
