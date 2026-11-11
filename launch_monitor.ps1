# Sovereign Engine - Launch Monitor
# Auto-deploys when all 8 nodes become reachable
# Usage: .\launch_monitor.ps1 [-Continuous] [-AutoDeploy]

param(
    [switch]$Continuous = $false,
    [switch]$AutoDeploy = $false,
    [int]$CheckInterval = 10,
    [int]$StableThreshold = 3  # Number of consecutive successful pings before deploy
)

$ErrorActionPreference = "Stop"

# Node configuration
$Nodes = @(
    @{ Id = 0; IP = "192.168.1.10"; Role = "HEAD"; Status = "UNKNOWN"; LastSeen = $null },
    @{ Id = 1; IP = "192.168.1.11"; Role = "WORKER"; Status = "UNKNOWN"; LastSeen = $null },
    @{ Id = 2; IP = "192.168.1.12"; Role = "WORKER"; Status = "UNKNOWN"; LastSeen = $null },
    @{ Id = 3; IP = "192.168.1.13"; Role = "WORKER"; Status = "UNKNOWN"; LastSeen = $null },
    @{ Id = 4; IP = "192.168.1.14"; Role = "WORKER"; Status = "UNKNOWN"; LastSeen = $null },
    @{ Id = 5; IP = "192.168.1.15"; Role = "WORKER"; Status = "UNKNOWN"; LastSeen = $null },
    @{ Id = 6; IP = "192.168.1.16"; Role = "WORKER"; Status = "UNKNOWN"; LastSeen = $null },
    @{ Id = 7; IP = "192.168.1.17"; Role = "WORKER"; Status = "UNKNOWN"; LastSeen = $null }
)

# Track consecutive successes for stability detection
$NodeStability = @{}
foreach ($node in $Nodes) {
    $NodeStability[$node.IP] = 0
}

$DeployTriggered = $false
$StartTime = Get-Date

function Clear-ScreenBuffer {
    # Cross-platform clear
    if ($Host.UI.RawUI) {
        $Host.UI.RawUI.ClearHost()
    } else {
        Clear-Host
    }
}

function Write-StatusHeader {
    param([int]$OnlineCount, [int]$TotalCount, [string]$Elapsed)
    
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           SOVEREIGN ENGINE - LAUNCH MONITOR                    ║" -ForegroundColor Cyan
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  Status: WAITING FOR HARDWARE    Mode: $(if($AutoDeploy){'AUTO-DEPLOY'}else{'MONITOR ONLY'})" -ForegroundColor Cyan
    Write-Host "║  Online: $OnlineCount/$TotalCount nodes    Elapsed: $Elapsed" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Test-NodeStatus {
    param($Node)
    
    try {
        $pingResult = Test-Connection -ComputerName $Node.IP -Count 1 -ErrorAction Stop
        return @{ Success = $true; Latency = $pingResult.ResponseTime }
    } catch {
        return @{ Success = $false; Latency = -1 }
    }
}

function Write-NodeStatus {
    param($Nodes)
    
    Write-Host "  Node Status:"
    Write-Host "  ──────────────────────────────────────────────────────────────"
    Write-Host "  ID  IP Address      Role     Status      Latency    Stability"
    Write-Host "  ──────────────────────────────────────────────────────────────"
    
    foreach ($node in $Nodes | Sort-Object Id) {
        $statusColor = switch ($node.Status) {
            "ONLINE"  { "Green" }
            "OFFLINE" { "Red" }
            default   { "Gray" }
        }
        
        $latencyStr = $(if ($node.LastSeen) { 
            "$($node.LastSeen)ms" 
        } else { 
            "N/A" 
        }
        
        $stability = $NodeStability[$node.IP]
        $stabilityIndicator = "█" * $stability + "░" * ($StableThreshold - $stability)
        
        Write-Host "  [$($node.Id)]  $($node.IP.PadRight(15)) $($node.Role.PadRight(8)) " -NoNewline
        Write-Host "$($node.Status.PadRight(10))" -ForegroundColor $statusColor -NoNewline
        Write-Host " $latencyStr.PadRight(10) [$stabilityIndicator]"
    }
    Write-Host ""
}

function Write-DeployBanner {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║                                                              ║" -ForegroundColor Green
    Write-Host "  ║     🚀 ALL NODES ONLINE - INITIATING DEPLOYMENT 🚀          ║" -ForegroundColor Green
    Write-Host "  ║                                                              ║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
}

function Invoke-Deployment {
    Write-Host "  [DEPLOY] Starting Sovereign Engine deployment..." -ForegroundColor Yellow
    
    try {
        # Step 1: Validate
        Write-Host "  [DEPLOY] Phase 1: Pre-deployment validation..." -ForegroundColor Gray
        & "$PSScriptRoot\deploy_staging_cluster_fixed.ps1" -ValidateOnly
        if ($LASTEXITCODE -ne 0) { throw "Validation failed" }
        
        # Step 2: Deploy
        Write-Host "  [DEPLOY] Phase 2: Deploying binaries..." -ForegroundColor Gray
        & "$PSScriptRoot\deploy_staging_cluster_fixed.ps1"
        if ($LASTEXITCODE -ne 0) { throw "Deployment failed" }
        
        # Step 3: Start swarm
        Write-Host "  [DEPLOY] Phase 3: Starting swarm..." -ForegroundColor Gray
        & "$PSScriptRoot\start_swarm.ps1"
        if ($LASTEXITCODE -ne 0) { throw "Swarm start failed" }
        
        # Step 4: Run integration test
        Write-Host "  [DEPLOY] Phase 4: Running integration tests..." -ForegroundColor Gray
        & "$PSScriptRoot\integration_test_full.ps1" -Verbose
        
        Write-Host ""
        Write-Host "  ✅ DEPLOYMENT COMPLETE!" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Next steps:"
        Write-Host "    - Monitor: .\monitor_cluster.ps1 -Continuous"
        Write-Host "    - Stress test: .\stress_test_4k.ps1"
        Write-Host "    - Stop: .\stop_swarm.ps1"
        Write-Host ""
        
        return $true
    }
    catch {
        Write-Host "  ❌ DEPLOYMENT FAILED: $_" -ForegroundColor Red
        Write-Host "  Check logs for details." -ForegroundColor Red
        return $false
    }
}

# Main monitoring loop
Clear-ScreenBuffer

while ($true) {
    $OnlineCount = 0
    $CurrentTime = Get-Date
    $Elapsed = $CurrentTime - $StartTime
    $ElapsedStr = "{0:D2}:{1:D2}:{2:D2}" -f $Elapsed.Hours, $Elapsed.Minutes, $Elapsed.Seconds
    
    # Check each node
    foreach ($node in $Nodes) {
        $result = Test-NodeStatus -Node $node
        
        if ($result.Success) {
            $node.Status = "ONLINE"
            $node.LastSeen = $result.Latency
            $NodeStability[$node.IP] = [Math]::Min($NodeStability[$node.IP] + 1, $StableThreshold)
            $OnlineCount++
        } else {
            $node.Status = "OFFLINE"
            $node.LastSeen = $null
            $NodeStability[$node.IP] = 0
        }
    }
    
    # Display status
    Clear-ScreenBuffer
    Write-StatusHeader -OnlineCount $OnlineCount -TotalCount $Nodes.Count -Elapsed $ElapsedStr
    Write-NodeStatus -Nodes $Nodes
    
    # Check if all nodes are stable
    $StableCount = ($NodeStability.Values | Where-Object { $_ -ge $StableThreshold } | Measure-Object).Count
    
    if ($StableCount -eq $Nodes.Count -and -not $DeployTriggered) {
        Write-DeployBanner
        
        if ($AutoDeploy) {
            $DeployTriggered = $true
            $success = Invoke-Deployment
            
            if ($success) {
                Write-Host "  Press any key to exit..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                exit 0
            } else {
                Write-Host "  Deployment failed. Press any key to continue monitoring..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                $DeployTriggered = $false  # Reset to allow retry
            }
        } else {
            Write-Host "  All nodes are stable and ready for deployment!" -ForegroundColor Green
            Write-Host "  Run with -AutoDeploy flag to auto-deploy, or manually execute:"
            Write-Host "    .\deploy_staging_cluster_fixed.ps1"
            Write-Host ""
        }
    }
    
    # Show progress bar
    $progress = ($OnlineCount / $Nodes.Count) * 100
    $progressBar = "█" * [Math]::Floor($progress / 2) + "░" * (50 - [Math]::Floor($progress / 2))
    Write-Host "  Cluster Readiness: [$progressBar] $([Math]::Round($progress,1))%"
    Write-Host ""
    Write-Host "  Checking every $CheckInterval seconds... (Press Ctrl+C to stop)" -ForegroundColor Gray
    
    if (-not $Continuous -and $OnlineCount -eq $Nodes.Count) {
        Write-Host ""
        Write-Host "  All nodes online. Exiting (use -Continuous to keep monitoring)." -ForegroundColor Green
        exit 0
    }
    
    Start-Sleep -Seconds $CheckInterval
}
