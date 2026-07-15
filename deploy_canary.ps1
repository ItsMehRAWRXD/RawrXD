# Sovereign Engine Canary Deployment
# Staged rollout: Head → Head+1 → Head+3 → Full 8-node
# Usage: .\deploy_canary.ps1 -Stage {1|2|3|4} [-ValidateOnly]

param(
    [Parameter(Mandatory=$true)]
    [ValidateRange(1,4)]
    [int]$Stage,
    
    [switch]$ValidateOnly = $false,
    [switch]$Force = $false
)

$ErrorActionPreference = "Stop"

# Stage definitions
$StageConfig = @{
    1 = @{ 
        Name = "HEAD-ONLY"
        Description = "Deploy Head node only (192.168.1.10)"
        Nodes = @(0)
        HealthCheckDuration = 30
        SuccessCriteria = "Head node responds to health checks"
    }
    2 = @{ 
        Name = "HEAD+1"
        Description = "Deploy Head + 1 Worker (192.168.1.10-11)"
        Nodes = @(0,1)
        HealthCheckDuration = 60
        SuccessCriteria = "Ring topology established between 2 nodes"
    }
    3 = @{ 
        Name = "HEAD+3"
        Description = "Deploy Head + 3 Workers (192.168.1.10-13)"
        Nodes = @(0,1,2,3)
        HealthCheckDuration = 120
        SuccessCriteria = "KV-cache distributed across 4 nodes"
    }
    4 = @{ 
        Name = "FULL-DEPLOYMENT"
        Description = "Deploy all 8 nodes (192.168.1.10-17)"
        Nodes = @(0,1,2,3,4,5,6,7)
        HealthCheckDuration = 180
        SuccessCriteria = "Full 8-node cluster operational"
    }
}

# Full node configuration
$AllNodes = @(
    @{ Id = 0; Role = "HEAD";   IP = "192.168.1.10"; RouterPort = 5555; PubPort = 5556; GPU = $true;  AMX = $true },
    @{ Id = 1; Role = "WORKER"; IP = "192.168.1.11"; RouterPort = 5555; PubPort = 5556; GPU = $true;  AMX = $true },
    @{ Id = 2; Role = "WORKER"; IP = "192.168.1.12"; RouterPort = 5555; PubPort = 5556; GPU = $true;  AMX = $true },
    @{ Id = 3; Role = "WORKER"; IP = "192.168.1.13"; RouterPort = 5555; PubPort = 5556; GPU = $true;  AMX = $true },
    @{ Id = 4; Role = "WORKER"; IP = "192.168.1.14"; RouterPort = 5555; PubPort = 5556; GPU = $false; AMX = $true },
    @{ Id = 5; Role = "WORKER"; IP = "192.168.1.15"; RouterPort = 5555; PubPort = 5556; GPU = $false; AMX = $true },
    @{ Id = 6; Role = "WORKER"; IP = "192.168.1.16"; RouterPort = 5555; PubPort = 5556; GPU = $false; AMX = $true },
    @{ Id = 7; Role = "WORKER"; IP = "192.168.1.17"; RouterPort = 5555; PubPort = 5556; GPU = $false; AMX = $true }
)

$currentStage = $StageConfig[$Stage]
$targetNodes = $AllNodes | Where-Object { $currentStage.Nodes -contains $_.Id }

Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    SOVEREIGN ENGINE CANARY DEPLOYMENT                          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Stage $Stage`: $($currentStage.Name)" -ForegroundColor Yellow
Write-Host "$($currentStage.Description)" -ForegroundColor Gray
Write-Host ""
Write-Host "Target Nodes: $($targetNodes.Count)" -ForegroundColor White
foreach ($node in $targetNodes) {
    Write-Host "  Node $($node.Id) ($($node.Role)): $($node.IP)" -ForegroundColor Gray
}
Write-Host ""

# Pre-deployment validation
Write-Host "PHASE 1: Pre-Deployment Validation" -ForegroundColor Yellow

$validationResults = @()
foreach ($node in $targetNodes) {
    Write-Host "  Validating Node $($node.Id) ($($node.IP))..." -NoNewline
    
    $result = @{
        NodeId = $node.Id
        Reachable = $false
        WinRM = $false
        Ports = $false
        NTP = $false
    }
    
    # Test connectivity
    if (Test-Connection -ComputerName $node.IP -Count 1 -Quiet -ErrorAction SilentlyContinue) {
        $result.Reachable = $true
    }
    
    # Test WinRM
    try {
        $winrmTest = Test-WSMan -ComputerName $node.IP -ErrorAction SilentlyContinue
        if ($winrmTest) {
            $result.WinRM = $true
        }
    } catch {}
    
    # Test ports
    try {
        $portTest = Test-NetConnection -ComputerName $node.IP -Port 5985 -WarningAction SilentlyContinue
        if ($portTest.TcpTestSucceeded) {
            $result.Ports = $true
        }
    } catch {}
    
    $validationResults += $result
    
    $status = $(if ($result.Reachable -and $result.WinRM) { "✅" } else { "❌" }
    Write-Host " $status" -ForegroundColor $(if ($result.Reachable -and $result.WinRM) { "Green" } else { "Red" })
}

$validNodes = ($validationResults | Where-Object { $_.Reachable -and $_.WinRM }).Count
Write-Host "  Validated: $validNodes/$($targetNodes.Count) nodes ready" -ForegroundColor $(if ($validNodes -eq $targetNodes.Count) { "Green" } else { "Red" })

if ($validNodes -lt $targetNodes.Count) {
    Write-Host "`n❌ Validation failed. Not all nodes are reachable." -ForegroundColor Red
    exit 1
}

if ($ValidateOnly) {
    Write-Host "`n✅ Validation complete. Ready for Stage $Stage deployment." -ForegroundColor Green
    exit 0
}

if (-not $Force) {
    Write-Host "`n⚠️  This will deploy to $($targetNodes.Count) physical nodes!" -ForegroundColor Yellow
    $confirm = Read-Host "Type 'DEPLOY' to continue"
    if ($confirm -ne "DEPLOY") {
        Write-Host "Deployment cancelled." -ForegroundColor Gray
        exit 0
    }
}

# Deployment
Write-Host "`nPHASE 2: Deployment" -ForegroundColor Yellow

$deployPath = "C:\Sovereign\bin"
$artifacts = @(
    "sovereign_cli.exe",
    "SovereignOrchestrator.dll",
    "SovereignFlowControl.dll",
    "SovereignWeightSync.dll",
    "SovereignRingAttention.dll"
)

foreach ($node in $targetNodes) {
    Write-Host "  Deploying to Node $($node.Id) ($($node.IP))..." -NoNewline
    
    try {
        # Create directory
        Invoke-Command -ComputerName $node.IP -ScriptBlock {
            param($path)
            New-Item -ItemType Directory -Force -Path $path | Out-Null
        } -ArgumentList $deployPath -ErrorAction Stop
        
        # Copy artifacts
        foreach ($artifact in $artifacts) {
            $source = "D:\RawrXD\build\production\bin\$artifact"
            if (Test-Path $source) {
                $dest = "\\$($node.IP)\C$\Sovereign\bin\$artifact"
                Copy-Item $source $dest -Force -ErrorAction Stop
            }
        }
        
        Write-Host " ✅ Deployed" -ForegroundColor Green
    } catch {
        Write-Host " ❌ Failed: $_" -ForegroundColor Red
        if (-not $Force) {
            exit 1
        }
    }
}

# Configuration
Write-Host "`nPHASE 3: Configuration" -ForegroundColor Yellow

$headNode = $targetNodes | Where-Object { $_.Role -eq "HEAD" }

foreach ($node in $targetNodes) {
    Write-Host "  Configuring Node $($node.Id)..." -NoNewline
    
    $config = @"
{
    "nodeId": $($node.Id),
    "role": "$($node.Role)",
    "headNodeIp": "$($headNode.IP)",
    "bindAddress": "0.0.0.0:$($node.RouterPort)",
    "dataPlane": {
        "routerEndpoint": "tcp://$($headNode.IP):$($headNode.RouterPort)",
        "pubEndpoint": "tcp://$($node.IP):$($node.PubPort)"
    },
    "hardware": {
        "enableGPU": $($node.GPU.ToString().ToLower()),
        "enableAMX": $($node.AMX.ToString().ToLower()),
        "threadPoolSize": 8
    },
    "telemetry": {
        "prometheusPort": $(8080 + $node.Id),
        "logLevel": "INFO"
    },
    "canary": {
        "stage": $Stage,
        "deploymentId": "$(Get-Date -Format 'yyyyMMdd_HHmmss')"
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

# Service startup
Write-Host "`nPHASE 4: Service Startup" -ForegroundColor Yellow

foreach ($node in $targetNodes) {
    Write-Host "  Starting Node $($node.Id)..." -NoNewline
    
    try {
        Invoke-Command -ComputerName $node.IP -ScriptBlock {
            param($nodeId)
            
            $exePath = "C:\Sovereign\bin\sovereign_cli.exe"
            $configPath = "C:\Sovereign\config.json"
            
            # Kill existing
            Get-Process -Name "sovereign_cli" -ErrorAction SilentlyContinue | Stop-Process -Force
            
            # Start new
            $process = Start-Process -FilePath $exePath `
                -ArgumentList "--config `"$configPath`" --daemon" `
                -PassThru -WindowStyle Hidden
            
            $process.Id | Out-File "C:\Sovereign\sovereign.pid" -Force
            return $process.Id
        } -ArgumentList $node.Id -ErrorAction Stop
        
        Write-Host " ✅ Started" -ForegroundColor Green
    } catch {
        Write-Host " ❌ Failed: $_" -ForegroundColor Red
    }
}

# Health check
Write-Host "`nPHASE 5: Health Check ($($currentStage.HealthCheckDuration)s)" -ForegroundColor Yellow

$healthCheckStart = Get-Date
$healthResults = @()

while (((Get-Date) - $healthCheckStart).TotalSeconds -lt $currentStage.HealthCheckDuration) {
    $elapsed = [math]::Round(((Get-Date) - $healthCheckStart).TotalSeconds)
    $remaining = $currentStage.HealthCheckDuration - $elapsed
    
    Write-Progress -Activity "Health Check" -Status "$elapsed/$($currentStage.HealthCheckDuration) seconds" -PercentComplete (($elapsed / $currentStage.HealthCheckDuration) * 100)
    
    Start-Sleep -Seconds 1
}

Write-Progress -Activity "Health Check" -Completed

# Verify nodes
Write-Host "`n  Verifying node health..." -ForegroundColor Gray

foreach ($node in $targetNodes) {
    try {
        $processCheck = Invoke-Command -ComputerName $node.IP -ScriptBlock {
            $process = Get-Process -Name "sovereign_cli" -ErrorAction SilentlyContinue
            return ($process -ne $null)
        }
        
        $healthResults += [PSCustomObject]@{
            NodeId = $node.Id
            Healthy = $processCheck
        }
        
        $status = $(if ($processCheck) { "✅" } else { "❌" }
        Write-Host "    Node $($node.Id): $status" -ForegroundColor $(if ($processCheck) { "Green" } else { "Red" })
    } catch {
        $healthResults += [PSCustomObject]@{
            NodeId = $node.Id
            Healthy = $false
        }
        Write-Host "    Node $($node.Id): ❌ (error)" -ForegroundColor Red
    }
}

$healthyNodes = ($healthResults | Where-Object { $_.Healthy }).Count

# Results
Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $(if ($healthyNodes -eq $targetNodes.Count) { "Green" } else { "Yellow" })
Write-Host "║                    STAGE $Stage DEPLOYMENT COMPLETE                            ║" -ForegroundColor $(if ($healthyNodes -eq $targetNodes.Count) { "Green" } else { "Yellow" })
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor $(if ($healthyNodes -eq $targetNodes.Count) { "Green" } else { "Yellow" })

Write-Host "`nHealth Status: $healthyNodes/$($targetNodes.Count) nodes healthy" -ForegroundColor $(if ($healthyNodes -eq $targetNodes.Count) { "Green" } else { "Yellow" })
Write-Host "Success Criteria: $($currentStage.SuccessCriteria)" -ForegroundColor Gray

if ($healthyNodes -eq $targetNodes.Count) {
    Write-Host "`n✅ Stage $Stage deployment successful!" -ForegroundColor Green
    
    if ($Stage -lt 4) {
        Write-Host "`nNext Steps:" -ForegroundColor White
        Write-Host "  1. Validate workload: .\validate_canary.ps1 -Stage $Stage" -ForegroundColor Gray
        Write-Host "  2. Monitor metrics: .\monitor_cluster.ps1" -ForegroundColor Gray
        Write-Host "  3. Proceed to Stage $($Stage+1): .\deploy_canary.ps1 -Stage $($Stage+1)" -ForegroundColor Cyan
    } else {
        Write-Host "`n🎉 Full deployment complete!" -ForegroundColor Green
        Write-Host "  Run production validation: .\integration_test_full.ps1" -ForegroundColor Gray
    }
} else {
    Write-Host "`n⚠️  Some nodes unhealthy. Review logs before proceeding." -ForegroundColor Yellow
    Write-Host "  Rollback: .\rollback_canary.ps1 -Stage $Stage" -ForegroundColor Red
}

# Save deployment state
$deploymentState = @{
    Stage = $Stage
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Nodes = $targetNodes | ForEach-Object { $_.Id }
    Healthy = $healthyNodes
    Total = $targetNodes.Count
}

$deploymentState | ConvertTo-Json | Out-File "D:\RawrXD\canary_deployment_state.json" -Force