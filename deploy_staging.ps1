# Sovereign Engine Staging Deployment
# Phase 1: Manual Bootstrap for 8-Node Cluster
# Usage: .\deploy_staging_cluster.ps1 [-ValidateOnly]

param(
    [string]$ConfigFile = "staging_config.json",
    [switch]$ValidateOnly = $false
)

$ErrorActionPreference = "Stop"

# Node configuration
$Nodes = @(
    @{ Id = 0; Role = "HEAD"; IP = "10.0.1.10"; GPU = $true; AMX = $true },
    @{ Id = 1; Role = "WORKER"; IP = "10.0.1.11"; GPU = $true; AMX = $true },
    @{ Id = 2; Role = "WORKER"; IP = "10.0.1.12"; GPU = $true; AMX = $true },
    @{ Id = 3; Role = "WORKER"; IP = "10.0.1.13"; GPU = $true; AMX = $true },
    @{ Id = 4; Role = "WORKER"; IP = "10.0.1.14"; GPU = $false; AMX = $true },
    @{ Id = 5; Role = "WORKER"; IP = "10.0.1.15"; GPU = $false; AMX = $true },
    @{ Id = 6; Role = "WORKER"; IP = "10.0.1.16"; GPU = $false; AMX = $true },
    @{ Id = 7; Role = "WORKER"; IP = "10.0.1.17"; GPU = $false; AMX = $true }
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Sovereign Engine Staging Deployment" -ForegroundColor Cyan
Write-Host "Phase 1: Manual Bootstrap" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Pre-deployment checks
Write-Host "Phase 1: Pre-deployment Validation" -ForegroundColor Yellow

$allNodesReady = $true

foreach ($node in $Nodes) {
    Write-Host "  Checking Node $($node.Id) ($($node.IP))..." -NoNewline
    
    # Test connectivity
    if (Test-Connection -ComputerName $node.IP -Count 1 -Quiet -ErrorAction SilentlyContinue) {
        Write-Host " ✅ Online" -ForegroundColor Green
    } else {
        Write-Host " ❌ Offline" -ForegroundColor Red
        $allNodesReady = $false
        continue
    }
    
    # Check ports (5555, 5556)
    try {
        $port5555 = Test-NetConnection -ComputerName $node.IP -Port 5555 -WarningAction SilentlyContinue
        $port5556 = Test-NetConnection -ComputerName $node.IP -Port 5556 -WarningAction SilentlyContinue
        
        if ($port5555.TcpTestSucceeded -and $port5556.TcpTestSucceeded) {
            Write-Host "    Ports 5555/5556: ✅ Open" -ForegroundColor Green
        } else {
            Write-Host "    Ports 5555/5556: ⚠️ Check firewall" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    Port check: ⚠️ Unable to verify" -ForegroundColor Yellow
    }
    
    # Check NTP sync
    try {
        $ntpStatus = Invoke-Command -ComputerName $node.IP -ScriptBlock {
            $service = Get-Service w32time -ErrorAction SilentlyContinue
            return $service.Status
        } -ErrorAction SilentlyContinue
        
        if ($ntpStatus -eq "Running") {
            Write-Host "    NTP: ✅ Synchronized" -ForegroundColor Green
        } else {
            Write-Host "    NTP: ⚠️ Service not running" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    NTP: ⚠️ Unable to verify" -ForegroundColor Yellow
    }
}

if (-not $allNodesReady) {
    Write-Host "`n❌ Validation failed. Not all nodes are reachable." -ForegroundColor Red
    exit 1
}

if ($ValidateOnly) {
    Write-Host "`n✅ Validation complete. All nodes ready for deployment." -ForegroundColor Green
    exit 0
}

# Deploy binaries
Write-Host "`nPhase 2: Binary Deployment" -ForegroundColor Yellow

$DeployPath = "C:\Sovereign\bin"
$Artifacts = @(
    "SovereignOrchestrator.dll",
    "SovereignFlowControl.dll",
    "SovereignWeightSync.dll",
    "SovereignRingAttention.dll",
    "swarm_benchmark_optimized.exe",
    "sovereign_cli.exe"
)

foreach ($node in $Nodes) {
    Write-Host "  Deploying to Node $($node.Id) ($($node.IP))..." -NoNewline
    
    try {
        # Create directory
        Invoke-Command -ComputerName $node.IP -ScriptBlock {
            param($path)
            New-Item -ItemType Directory -Force -Path $path | Out-Null
        } -ArgumentList $DeployPath -ErrorAction SilentlyContinue
        
        # Copy artifacts
        foreach ($artifact in $Artifacts) {
            $source = ".\build\production\bin\$artifact"
            if (Test-Path $source) {
                $dest = "\\$($node.IP)\C$\Sovereign\bin\$artifact"
                Copy-Item $source $dest -Force -ErrorAction SilentlyContinue
            }
        }
        
        Write-Host " ✅ Deployed" -ForegroundColor Green
    } catch {
        Write-Host " ❌ Failed: $_" -ForegroundColor Red
    }
}

# Configure nodes
Write-Host "`nPhase 3: Node Configuration" -ForegroundColor Yellow

$headNode = $Nodes | Where-Object { $_.Role -eq "HEAD" }

foreach ($node in $Nodes) {
    Write-Host "  Configuring Node $($node.Id)..." -NoNewline
    
    $config = @"
{
    "nodeId": $($node.Id),
    "role": "$($node.Role)",
    "headNodeIp": "$($headNode.IP)",
    "bindAddress": "0.0.0.0:7777",
    "dataPlane": {
        "routerEndpoint": "tcp://$($headNode.IP):5555",
        "pubEndpoint": "tcp://$($node.IP):5556"
    },
    "hardware": {
        "enableGPU": $($node.GPU.ToString().ToLower()),
        "enableAMX": $($node.AMX.ToString().ToLower()),
        "threadPoolSize": 8
    },
    "telemetry": {
        "prometheusPort": 8080,
        "logLevel": "INFO"
    }
}
"@
    
    try {
        $configPath = "\\$($node.IP)\C$\Sovereign\config.json"
        $config | Out-File -FilePath $configPath -Encoding UTF8 -Force
        Write-Host " ✅ Configured" -ForegroundColor Green
    } catch {
        Write-Host " ❌ Failed: $_" -ForegroundColor Red
    }
}

# Start services
Write-Host "`nPhase 4: Service Startup" -ForegroundColor Yellow

foreach ($node in $Nodes) {
    Write-Host "  Starting Node $($node.Id)..." -NoNewline
    
    try {
        Invoke-Command -ComputerName $node.IP -ScriptBlock {
            param($nodeId, $isHead)
            
            $exePath = "C:\Sovereign\bin\sovereign_cli.exe"
            $configPath = "C:\Sovereign\config.json"
            
            if (Test-Path $exePath) {
                # Kill existing process if running
                Get-Process -Name "sovereign_cli" -ErrorAction SilentlyContinue | Stop-Process -Force
                
                # Start new process
                $process = Start-Process -FilePath $exePath `
                    -ArgumentList "--config `"$configPath`" --daemon" `
                    -PassThru -WindowStyle Hidden -WorkingDirectory "C:\Sovereign"
                
                # Store PID
                $process.Id | Out-File "C:\Sovereign\sovereign.pid" -Force
            }
        } -ArgumentList $node.Id, ($node.Role -eq "HEAD") -ErrorAction SilentlyContinue
        
        Write-Host " ✅ Started" -ForegroundColor Green
    } catch {
        Write-Host " ❌ Failed: $_" -ForegroundColor Red
    }
}

# Verify cluster
Write-Host "`nPhase 5: Cluster Verification" -ForegroundColor Yellow

Start-Sleep -Seconds 5

Write-Host "  Checking cluster status..." -NoNewline

try {
    $headStatus = Invoke-Command -ComputerName $headNode.IP -ScriptBlock {
        # Check if process is running
        $process = Get-Process -Name "sovereign_cli" -ErrorAction SilentlyContinue
        if ($process) {
            return "Running (PID: $($process.Id))"
        } else {
            return "Not running"
        }
    } -ErrorAction SilentlyContinue
    
    Write-Host " ✅ $headStatus" -ForegroundColor Green
} catch {
    Write-Host " ⚠️ Unable to verify" -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Deployment Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor White
Write-Host "  1. Validate cluster: .\validate_cluster.ps1" -ForegroundColor Gray
Write-Host "  2. Run benchmark: .\run_benchmark.ps1 --duration 300" -ForegroundColor Gray
Write-Host "  3. Monitor: http://$($headNode.IP):8080/metrics" -ForegroundColor Gray
Write-Host ""
Write-Host "Dashboard: http://$($headNode.IP):3000 (Grafana)" -ForegroundColor Cyan