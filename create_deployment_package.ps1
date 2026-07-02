# Sovereign Engine Deployment Package Creator
# Creates a self-contained deployment package for the 8-node cluster
# Usage: .\create_deployment_package.ps1 [-OutputPath <path>]

param(
    [string]$OutputPath = "D:\RawrXD\SovereignEngine-Deployment-v1.0.zip",
    [switch]$IncludeBinaries = $true
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Sovereign Engine Deployment Package" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Create temporary staging directory
$stagingDir = "D:\RawrXD\deployment_staging"
if (Test-Path $stagingDir) {
    Remove-Item -Path $stagingDir -Recurse -Force
}
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
New-Item -ItemType Directory -Path "$stagingDir\bin" -Force | Out-Null
New-Item -ItemType Directory -Path "$stagingDir\scripts" -Force | Out-Null
New-Item -ItemType Directory -Path "$stagingDir\config" -Force | Out-Null
New-Item -ItemType Directory -Path "$stagingDir\docs" -Force | Out-Null

Write-Host "Staging directory created: $stagingDir" -ForegroundColor Gray

# Copy deployment scripts
$scripts = @(
    "deploy_staging_cluster_fixed.ps1",
    "deploy_canary.ps1",
    "validate_canary.ps1",
    "start_swarm.ps1",
    "stop_swarm.ps1",
    "monitor_cluster.ps1",
    "toggle_deployment_mode.ps1",
    "integration_test_full.ps1",
    "stress_test_4k.ps1",
    "warmup_swarm.ps1"
)

Write-Host "`nCopying deployment scripts..." -ForegroundColor Yellow
foreach ($script in $scripts) {
    $source = "D:\RawrXD\$script"
    if (Test-Path $source) {
        Copy-Item -Path $source -Destination "$stagingDir\scripts\" -Force
        Write-Host "  ✓ $script" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ $script (not found)" -ForegroundColor Yellow
    }
}

# Copy binaries if requested
if ($IncludeBinaries) {
    Write-Host "`nCopying binaries..." -ForegroundColor Yellow
    $binaries = @(
        "sovereign_engine.dll",
        "sovereign_cli.exe",
        "sovereign_head.exe",
        "sovereign_worker.exe",
        "test_ring_integration.exe"
    )
    
    foreach ($binary in $binaries) {
        $source = "D:\RawrXD\build\bin\$binary"
        if (Test-Path $source) {
            Copy-Item -Path $source -Destination "$stagingDir\bin\" -Force
            Write-Host "  ✓ $binary" -ForegroundColor Green
        } else {
            Write-Host "  ⚠ $binary (not found - will need to be built)" -ForegroundColor Yellow
        }
    }
}

# Copy documentation
Write-Host "`nCopying documentation..." -ForegroundColor Yellow
$docs = @(
    "DEPLOYMENT_READINESS_REPORT.md",
    "CANARY_DEPLOYMENT_GUIDE.md",
    "FINAL_DEPLOYMENT_READINESS.md"
)

foreach ($doc in $docs) {
    $source = "D:\RawrXD\$doc"
    if (Test-Path $source) {
        Copy-Item -Path $source -Destination "$stagingDir\docs\" -Force
        Write-Host "  ✓ $doc" -ForegroundColor Green
    }
}

# Create deployment configuration
Write-Host "`nCreating deployment configuration..." -ForegroundColor Yellow
$deployConfig = @{
    version = "1.0.0"
    created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    target_nodes = @(
        @{ id = 0; ip = "192.168.1.10"; role = "HEAD"; gpu = $true; amx = $true },
        @{ id = 1; ip = "192.168.1.11"; role = "WORKER"; gpu = $true; amx = $true },
        @{ id = 2; ip = "192.168.1.12"; role = "WORKER"; gpu = $true; amx = $true },
        @{ id = 3; ip = "192.168.1.13"; role = "WORKER"; gpu = $true; amx = $true },
        @{ id = 4; ip = "192.168.1.14"; role = "WORKER"; gpu = $false; amx = $true },
        @{ id = 5; ip = "192.168.1.15"; role = "WORKER"; gpu = $false; amx = $true },
        @{ id = 6; ip = "192.168.1.16"; role = "WORKER"; gpu = $false; amx = $true },
        @{ id = 7; ip = "192.168.1.17"; role = "WORKER"; gpu = $false; amx = $true }
    )
    zmq_router_port = 5555
    zmq_pub_port = 5556
    metrics_port_base = 8080
    binary_path = "C:\Sovereign\bin"
    config_path = "C:\Sovereign\config"
} | ConvertTo-Json -Depth 10

$deployConfig | Set-Content "$stagingDir\config\deployment_config.json"
Write-Host "  ✓ deployment_config.json" -ForegroundColor Green

# Create README for deployment package
$readme = @"
# Sovereign Engine Deployment Package v1.0

## Quick Start

1. Extract this package to the head node (192.168.1.10)
2. Run: .\scripts\deploy_staging_cluster_fixed.ps1
3. Run: .\scripts\start_swarm.ps1
4. Monitor: .\scripts\monitor_cluster.ps1 -Continuous

## Canary Deployment (Recommended)

```powershell
# Stage 1: Head only
.\scripts\deploy_canary.ps1 -Stage 1
.\scripts\validate_canary.ps1 -Stage 1 -Duration 60

# Stage 2: Head + 1 Worker
.\scripts\deploy_canary.ps1 -Stage 2
.\scripts\validate_canary.ps1 -Stage 2 -Duration 60 -LoadTest

# Continue through Stage 4...
```

## Package Contents

- bin/ - Sovereign Engine binaries
- scripts/ - Deployment automation
- config/ - Node configuration
- docs/ - Documentation

## Target Cluster

8 nodes: 192.168.1.10-17
- Head: 192.168.1.10 (GPU + AMX)
- Workers: 192.168.1.11-17 (4 GPU, 4 non-GPU)

Created: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
"@

$readme | Set-Content "$stagingDir\README.txt"
Write-Host "  ✓ README.txt" -ForegroundColor Green

# Create the ZIP package
Write-Host "`nCreating deployment package..." -ForegroundColor Yellow
if (Test-Path $OutputPath) {
    Remove-Item -Path $OutputPath -Force
}

Compress-Archive -Path "$stagingDir\*" -DestinationPath $OutputPath -Force

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Deployment Package Created!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Package: $OutputPath" -ForegroundColor Cyan
Write-Host "Size: $([math]::Round((Get-Item $OutputPath).Length / 1MB, 2)) MB" -ForegroundColor Gray
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Transfer package to head node (192.168.1.10)" -ForegroundColor Gray
Write-Host "  2. Extract to C:\Sovereign\" -ForegroundColor Gray
Write-Host "  3. Run: .\scripts\deploy_staging_cluster_fixed.ps1" -ForegroundColor Gray
Write-Host "  4. Run: .\scripts\start_swarm.ps1" -ForegroundColor Gray
Write-Host ""

# Cleanup staging directory
Remove-Item -Path $stagingDir -Recurse -Force
Write-Host "Staging directory cleaned up." -ForegroundColor Gray
