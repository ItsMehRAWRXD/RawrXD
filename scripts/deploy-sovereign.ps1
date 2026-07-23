# Sovereign Substrate Deployment Script
# Usage: .\deploy-sovereign.ps1 [environment] [version]
# Example: .\deploy-sovereign.ps1 production 1.0.0

param(
    [string]$Environment = "staging",
    [string]$Version = "latest"
)

# Configuration
$DeployDir = "C:\\opt\\sovereign"
$BackupDir = "C:\\opt\\sovereign-backups"
$LogFile = "C:\\var\\log\\sovereign-deploy.log"

# Ensure log directory exists
if (!(Test-Path "C:\\var\\log")) {
    New-Item -ItemType Directory -Path "C:\\var\\log" -Force | Out-Null
}

# Logging functions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        default { "Green" }
    }
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
    "[$timestamp] [$Level] $Message" | Out-File -FilePath $LogFile -Append
}

function Write-ErrorLog {
    param([string]$Message)
    Write-Log $Message "ERROR"
    throw $Message
}

function Write-WarnLog {
    param([string]$Message)
    Write-Log $Message "WARN"
}

# Pre-deployment checks
function Test-Prerequisites {
    Write-Log "Checking prerequisites..."
    
    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-ErrorLog "This script must be run as Administrator"
    }
    
    # Check Docker
    try {
        $null = docker version 2>$null
    } catch {
        Write-ErrorLog "Docker is required but not installed or not running"
    }
    
    # Check Docker Compose
    try {
        $null = docker-compose version 2>$null
    } catch {
        Write-ErrorLog "Docker Compose is required but not installed"
    }
    
    # Check disk space
    $drive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
    if ($freeSpaceGB -lt 1) {
        Write-ErrorLog "Insufficient disk space. At least 1GB required (found $freeSpaceGB GB)"
    }
    
    Write-Log "Prerequisites check passed"
}

# Create backup
function New-Backup {
    Write-Log "Creating backup..."
    
    if (Test-Path $DeployDir) {
        $backupName = "sovereign-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
        
        # Stop current instance
        if (Test-Path "$DeployDir\\docker-compose.yml") {
            try {
                Push-Location $DeployDir
                docker-compose down 2>$null
                Pop-Location
            } catch {
                Write-WarnLog "Failed to stop current instance"
            }
        }
        
        # Create backup
        $backupPath = "$BackupDir\\$backupName.zip"
        Compress-Archive -Path "$DeployDir\\*" -DestinationPath $backupPath -Force
        Write-Log "Backup created: $backupPath"
    }
}

# Deploy new version
function Start-Deploy {
    Write-Log "Deploying Sovereign Substrate v$Version to $Environment..."
    
    # Create deployment directory
    New-Item -ItemType Directory -Path $DeployDir -Force | Out-Null
    
    # Copy configuration
    $configSource = "config\\sovereign.$Environment.json"
    if (Test-Path $configSource) {
        Copy-Item $configSource "$DeployDir\\config.json" -Force
    } else {
        Write-WarnLog "Configuration file not found: $configSource"
    }
    
    # Copy Docker Compose file
    $composeSource = "docker\\docker-compose.$Environment.yml"
    if (Test-Path $composeSource) {
        Copy-Item $composeSource "$DeployDir\\docker-compose.yml" -Force
    } else {
        Write-WarnLog "Docker Compose file not found: $composeSource"
    }
    
    # Pull and start services
    Push-Location $DeployDir
    try {
        docker-compose pull
        if ($LASTEXITCODE -ne 0) { throw "Failed to pull Docker image" }
        
        docker-compose up -d
        if ($LASTEXITCODE -ne 0) { throw "Failed to start services" }
    } finally {
        Pop-Location
    }
    
    Write-Log "Deployment completed successfully"
}

# Health check
function Test-Health {
    Write-Log "Running health checks..."
    
    # Wait for services to start
    Start-Sleep -Seconds 10
    
    # Check if container is running
    $containerRunning = docker ps | Select-String "sovereign"
    if (!$containerRunning) {
        Write-ErrorLog "Sovereign container is not running"
    }
    
    # Check HTTP endpoint
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8080/health" -UseBasicParsing -TimeoutSec 5
        if ($response.StatusCode -ne 200) {
            throw "Health check returned status $($response.StatusCode)"
        }
    } catch {
        Write-ErrorLog "Health check failed: $_"
    }
    
    Write-Log "Health checks passed"
}

# Cleanup old backups
function Remove-OldBackups {
    Write-Log "Cleaning up old backups..."
    
    # Keep only last 10 backups
    Get-ChildItem -Path $BackupDir -Filter "*.zip" |
        Sort-Object CreationTime -Descending |
        Select-Object -Skip 10 |
        Remove-Item -Force
    
    Write-Log "Cleanup completed"
}

# Rollback function
function Start-Rollback {
    Write-Log "Deployment failed. Rolling back..." "ERROR"
    
    # Find latest backup
    $latestBackup = Get-ChildItem -Path $BackupDir -Filter "*.zip" |
        Sort-Object CreationTime -Descending |
        Select-Object -First 1
    
    if ($latestBackup) {
        # Stop current instance
        Push-Location $DeployDir
        docker-compose down 2>$null
        Pop-Location
        
        # Restore backup
        Remove-Item -Path "$DeployDir\\*" -Recurse -Force
        Expand-Archive -Path $latestBackup.FullName -DestinationPath $DeployDir -Force
        
        # Restart services
        Push-Location $DeployDir
        docker-compose up -d
        Pop-Location
        
        Write-Log "Rollback completed"
    } else {
        Write-ErrorLog "No backup found for rollback"
    }
}

# Main deployment flow
function Main {
    Write-Log "Starting Sovereign Substrate deployment"
    Write-Log "Environment: $Environment"
    Write-Log "Version: $Version"
    
    try {
        Test-Prerequisites
        New-Backup
        Start-Deploy
        Test-Health
        Remove-OldBackups
        
        Write-Log "Deployment completed successfully!"
        Write-Log "Sovereign Substrate is now running on $Environment"
        Write-Log ""
        Write-Log "Access points:"
        Write-Log "  - API: http://localhost:8080"
        Write-Log "  - Metrics: http://localhost:8081"
        Write-Log "  - Logs: docker-compose logs -f"
    } catch {
        Start-Rollback
        exit 1
    }
}

# Run main function
Main
