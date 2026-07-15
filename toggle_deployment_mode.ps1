# Sovereign Engine Deployment Mode Toggle
# Switches between Simulation and Physical deployment modes
# Usage: .\toggle_deployment_mode.ps1 [-Mode {Simulation|Physical}]

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Simulation", "Physical")]
    [string]$Mode
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Sovereign Engine Deployment Mode Toggle" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$configFile = "D:\RawrXD\deployment_config.json"
$deployScript = "D:\RawrXD\deploy_staging_cluster_fixed.ps1"

# Current mode detection
$currentMode = "Unknown"
if (Test-Path $configFile) {
    $config = Get-Content $configFile -ErrorAction SilentlyContinue | ConvertFrom-Json
    if ($config) {
        $currentMode = $config.Mode
    }
}

Write-Host "Current Mode: $currentMode" -ForegroundColor Gray
Write-Host "Target Mode:  $Mode`n" -ForegroundColor Yellow

# Backup current deployment script
$backupFile = "D:\RawrXD\deploy_staging_cluster_fixed.ps1.backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
Copy-Item $deployScript $backupFile -Force
Write-Host "Backup created: $backupFile" -ForegroundColor Gray

# Mode-specific configurations
$configs = @{
    Simulation = @{
        Description = "Localhost simulation with port offsets"
        Nodes = @(
            @{ Id = 0; Role = "HEAD";   IP = "127.0.0.1"; RouterPort = 5555; PubPort = 5556; GPU = $true;  AMX = $true },
            @{ Id = 1; Role = "WORKER"; IP = "127.0.0.1"; RouterPort = 5557; PubPort = 5558; GPU = $true;  AMX = $true },
            @{ Id = 2; Role = "WORKER"; IP = "127.0.0.1"; RouterPort = 5559; PubPort = 5560; GPU = $true;  AMX = $true },
            @{ Id = 3; Role = "WORKER"; IP = "127.0.0.1"; RouterPort = 5561; PubPort = 5562; GPU = $true;  AMX = $true },
            @{ Id = 4; Role = "WORKER"; IP = "127.0.0.1"; RouterPort = 5563; PubPort = 5564; GPU = $false; AMX = $true },
            @{ Id = 5; Role = "WORKER"; IP = "127.0.0.1"; RouterPort = 5565; PubPort = 5566; GPU = $false; AMX = $true },
            @{ Id = 6; Role = "WORKER"; IP = "127.0.0.1"; RouterPort = 5567; PubPort = 5568; GPU = $false; AMX = $true },
            @{ Id = 7; Role = "WORKER"; IP = "127.0.0.1"; RouterPort = 5569; PubPort = 5570; GPU = $false; AMX = $true }
        )
        ExecutionMode = "SIMULATION"
        RemoteExecution = $false
        BinaryPath = "D:\RawrXD\build\production\bin"
        ConfigBasePath = "D:\RawrXD\simulation"
    }
    
    Physical = @{
        Description = "Physical 8-node cluster (192.168.1.10-17)"
        Nodes = @(
            @{ Id = 0; Role = "HEAD";   IP = "192.168.1.10"; RouterPort = 5555; PubPort = 5556; GPU = $true;  AMX = $true },
            @{ Id = 1; Role = "WORKER"; IP = "192.168.1.11"; RouterPort = 5555; PubPort = 5556; GPU = $true;  AMX = $true },
            @{ Id = 2; Role = "WORKER"; IP = "192.168.1.12"; RouterPort = 5555; PubPort = 5556; GPU = $true;  AMX = $true },
            @{ Id = 3; Role = "WORKER"; IP = "192.168.1.13"; RouterPort = 5555; PubPort = 5556; GPU = $true;  AMX = $true },
            @{ Id = 4; Role = "WORKER"; IP = "192.168.1.14"; RouterPort = 5555; PubPort = 5556; GPU = $false; AMX = $true },
            @{ Id = 5; Role = "WORKER"; IP = "192.168.1.15"; RouterPort = 5555; PubPort = 5556; GPU = $false; AMX = $true },
            @{ Id = 6; Role = "WORKER"; IP = "192.168.1.16"; RouterPort = 5555; PubPort = 5556; GPU = $false; AMX = $true },
            @{ Id = 7; Role = "WORKER"; IP = "192.168.1.17"; RouterPort = 5555; PubPort = 5556; GPU = $false; AMX = $true }
        )
        ExecutionMode = "PHYSICAL"
        RemoteExecution = $true
        BinaryPath = "C:\Sovereign\bin"
        ConfigBasePath = "C:\Sovereign"
    }
}

$targetConfig = $configs[$Mode]

# Update deployment script
Write-Host "Updating deployment script..." -ForegroundColor Yellow

# Read current script
$scriptContent = Get-Content $deployScript -Raw

# Replace node configuration block
$oldNodesPattern = '# Node configuration.*?(?=\n\n|$)'
$newNodesBlock = @"
# Node configuration - $Mode MODE
# $($targetConfig.Description)
`$Nodes = @(
$(foreach ($node in $targetConfig.Nodes) {
    "    @{ Id = $($node.Id); Role = `"$($node.Role)`"; IP = `"$($node.IP)`"; RouterPort = $($node.RouterPort); PubPort = $($node.PubPort); GPU = `$$($node.GPU.ToString().ToLower()); AMX = `$$($node.AMX.ToString().ToLower()) },"
})
)
"@

$scriptContent = $scriptContent -replace $oldNodesPattern, $newNodesBlock

# Update execution mode markers
if ($Mode -eq "Simulation") {
    # Ensure simulation mode markers are present
    if (-not ($scriptContent -match "SIMULATION MODE")) {
        Write-Host "  Adding simulation mode markers..." -ForegroundColor Gray
    }
} else {
    # Switch to remote execution
    Write-Host "  Switching to remote execution mode..." -ForegroundColor Gray
}

# Save updated script
$scriptContent | Out-File $deployScript -Force

# Save configuration metadata
$metadata = @{
    Mode = $Mode
    Description = $targetConfig.Description
    UpdatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    NodeCount = $targetConfig.Nodes.Count
    RemoteExecution = $targetConfig.RemoteExecution
    BinaryPath = $targetConfig.BinaryPath
    ConfigBasePath = $targetConfig.ConfigBasePath
}

$metadata | ConvertTo-Json | Out-File $configFile -Force

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Mode Switch Complete: $Mode" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Configuration Summary:" -ForegroundColor White
Write-Host "  Mode:           $($metadata.Mode)" -ForegroundColor Gray
Write-Host "  Nodes:          $($metadata.NodeCount)" -ForegroundColor Gray
Write-Host "  Remote Exec:    $($metadata.RemoteExecution)" -ForegroundColor Gray
Write-Host "  Binary Path:    $($metadata.BinaryPath)" -ForegroundColor Gray
Write-Host "  Config Path:    $($metadata.ConfigBasePath)" -ForegroundColor Gray
Write-Host ""

if ($Mode -eq "Physical") {
    Write-Host "Pre-Deployment Checklist:" -ForegroundColor Yellow
    Write-Host "  ☐ Verify all 8 nodes are reachable (ping 192.168.1.10-17)" -ForegroundColor Gray
    Write-Host "  ☐ Verify WinRM is enabled on all nodes" -ForegroundColor Gray
    Write-Host "  ☐ Ensure binaries exist at $($metadata.BinaryPath)" -ForegroundColor Gray
    Write-Host "  ☐ Verify firewall rules allow ports 5555-5570" -ForegroundColor Gray
    Write-Host "  ☐ Confirm NTP synchronization across cluster" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To deploy: .\deploy_staging_cluster_fixed.ps1" -ForegroundColor Cyan
} else {
    Write-Host "Simulation Mode Active:" -ForegroundColor Yellow
    Write-Host "  All nodes mapped to 127.0.0.1 with unique port offsets" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To deploy: .\deploy_staging_cluster_fixed.ps1" -ForegroundColor Cyan
    Write-Host "To start:   .\start_swarm.ps1" -ForegroundColor Cyan
    Write-Host "To monitor: .\monitor_cluster.ps1" -ForegroundColor Cyan
}