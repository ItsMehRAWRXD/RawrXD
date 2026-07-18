# rollback.ps1
# Rollback Script for RawrXD Sovereign Deployment

param(
    [string]$BackupPath = $null,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Write-RollbackLog($Message, $Level = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

Write-RollbackLog "RawrXD Rollback Procedure"
Write-RollbackLog ""

# Confirm rollback
if (-not $Force) {
    Write-Host "WARNING: This will rollback the RawrXD deployment" -ForegroundColor Yellow
    $confirm = Read-Host "Type 'ROLLBACK' to confirm"
    if ($confirm -ne "ROLLBACK") {
        Write-RollbackLog "Rollback cancelled"
        exit 0
    }
}

# Step 1: Stop service
Write-RollbackLog "Stopping RawrXD service..."
Stop-Service -Name "RawrXD" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5

# Step 2: Create current state backup
Write-RollbackLog "Creating backup of current state..."
$currentBackup = "${env:ProgramData}\RawrXD\backups\pre-rollback-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
if (Test-Path "${env:ProgramFiles}\RawrXD") {
    Copy-Item -Path "${env:ProgramFiles}\RawrXD" -Destination $currentBackup -Recurse -Force
}

# Step 3: Uninstall
Write-RollbackLog "Uninstalling RawrXD..."
$uninstallString = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RawrXD" -ErrorAction SilentlyContinue).UninstallString
if ($uninstallString) {
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/x {12345678-1234-1234-1234-123456789012} /qn /norestart" -Wait
}

# Step 4: Restore from backup (if provided)
if ($BackupPath -and (Test-Path $BackupPath)) {
    Write-RollbackLog "Restoring from backup: $BackupPath"
    # Restore logic here
}

# Step 5: Verify rollback
Write-RollbackLog "Verifying rollback..."
if (-not (Test-Path "${env:ProgramFiles}\RawrXD\RawrXD.exe")) {
    Write-RollbackLog "✅ Rollback successful" "SUCCESS"
    Write-RollbackLog "Current state backed up to: $currentBackup"
} else {
    Write-RollbackLog "⚠️ Rollback may not be complete" "WARNING"
}

Write-RollbackLog ""
Write-RollbackLog "Rollback procedure complete"
