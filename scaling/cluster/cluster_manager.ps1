# RawrXD Cluster Manager
# Phase L.2 - Multi-Node Cluster Setup
# Manages multi-node RawrXD deployment with health monitoring and failover

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "cluster_config.json",

    [Parameter(Mandatory=$false)]
    [ValidateSet("init", "join", "leave", "status", "failover", "rebalance")]
    [string]$Action = "status",

    [Parameter(Mandatory=$false)]
    [string]$NodeAddress = "",

    [Parameter(Mandatory=$false)]
    [switch]$Watch
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Cluster state
$script:ClusterState = @{
    Nodes = @()
    Leader = $null
    Version = 1
    LastUpdate = $null
}

# Logging
function Write-ClusterLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colorMap = @{
        "INFO" = "White"
        "WARNING" = "Yellow"
        "ERROR" = "Red"
        "SUCCESS" = "Green"
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colorMap[$Level]
}

# Node class definition
class ClusterNode {
    [string]$Id
    [string]$Address
    [int]$Port
    [string]$Status  # healthy, degraded, unhealthy, offline
    [int]$Weight
    [hashtable]$Metrics
    [DateTime]$LastHeartbeat
    [string]$Role  # primary, backup, leader

    ClusterNode([string]$address, [int]$port) {
        $this.Id = [Guid]::NewGuid().ToString()
        $this.Address = $address
        $this.Port = $port
        $this.Status = "unknown"
        $this.Weight = 5
        $this.Metrics = @{}
        $this.LastHeartbeat = [DateTime]::MinValue
        $this.Role = "backup"
    }

    [string] GetEndpoint() {
        return "http://$($this.Address):$($this.Port)"
    }

    [bool] IsHealthy() {
        return $this.Status -eq "healthy"
    }

    [void] UpdateMetrics([hashtable]$newMetrics) {
        $this.Metrics = $newMetrics
        $this.LastHeartbeat = Get-Date
    }
}

# Configuration management
function Load-ClusterConfig {
    param([string]$Path)

    if (Test-Path $Path) {
        $json = Get-Content $Path -Raw | ConvertFrom-Json
        Write-ClusterLog "Loaded cluster configuration from $Path" "INFO"
        return $json
    } else {
        Write-ClusterLog "No existing configuration found at $Path" "WARNING"
        return @{
            ClusterName = "rawrxd-cluster"
            Nodes = @()
            ReplicationFactor = 2
            HeartbeatInterval = 5
            FailoverTimeout = 30
        }
    }
}

function Save-ClusterConfig {
    param(
        [string]$Path,
        [hashtable]$Config
    )

    $Config | ConvertTo-Json -Depth 10 | Out-File $Path -Encoding UTF8
    Write-ClusterLog "Saved cluster configuration to $Path" "SUCCESS"
}

# Health checking
function Test-NodeHealth {
    param([ClusterNode]$Node)

    try {
        $response = Invoke-WebRequest -Uri "$($Node.GetEndpoint())/health" -TimeoutSec 5 -ErrorAction Stop

        if ($response.StatusCode -eq 200) {
            $healthData = $response.Content | ConvertFrom-Json -ErrorAction SilentlyContinue

            $metrics = @{
                TPS = $healthData.tps
                Latency = $healthData.latency_ms
                MemoryUsage = $healthData.memory_percent
                GPUUtilization = $healthData.gpu_percent
                ActiveRequests = $healthData.active_requests
            }

            $Node.UpdateMetrics($metrics)

            # Determine status based on metrics
            if ($metrics.Latency -gt 500 -or $metrics.MemoryUsage -gt 90) {
                $Node.Status = "degraded"
            } else {
                $Node.Status = "healthy"
            }

            return $true
        }
    } catch {
        $Node.Status = "unhealthy"
        return $false
    }

    return $false
}

# Cluster operations
function Initialize-Cluster {
    param(
        [string]$ClusterName,
        [string]$ListenAddress = "0.0.0.0",
        [int]$ListenPort = 7946
    )

    Write-ClusterLog "Initializing new cluster: $ClusterName" "INFO"

    $config = @{
        ClusterName = $ClusterName
        NodeId = [Guid]::NewGuid().ToString()
        ListenAddress = $ListenAddress
        ListenPort = $ListenPort
        Nodes = @()
        ReplicationFactor = 2
        HeartbeatInterval = 5
        FailoverTimeout = 30
        CreatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }

    # Create local node as leader
    $localNode = [ClusterNode]::new($ListenAddress, 8080)
    $localNode.Role = "leader"
    $localNode.Status = "healthy"
    $config.Nodes += @{
        Id = $localNode.Id
        Address = $localNode.Address
        Port = $localNode.Port
        Role = $localNode.Role
        Weight = $localNode.Weight
    }

    Save-ClusterConfig -Path $ConfigFile -Config $config
    Write-ClusterLog "Cluster initialized successfully" "SUCCESS"
    Write-ClusterLog "Node ID: $($config.NodeId)" "INFO"
    Write-ClusterLog "Cluster members: $($config.Nodes.Count)" "INFO"

    return $config
}

function Join-Cluster {
    param(
        [string]$JoinAddress,
        [int]$JoinPort = 7946,
        [string]$LocalAddress = "",
        [int]$LocalPort = 8080
    )

    Write-ClusterLog "Joining cluster at $JoinAddress`:$JoinPort" "INFO"

    try {
        # Request to join cluster
        $joinRequest = @{
            NodeId = [Guid]::NewGuid().ToString()
            Address = if ($LocalAddress) { $LocalAddress } else { (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" } | Select-Object -First 1).IPAddress }
            Port = $LocalPort
            Role = "backup"
            Weight = 5
        } | ConvertTo-Json

        $response = Invoke-WebRequest -Uri "http://$JoinAddress`:$JoinPort/cluster/join" -Method POST -Body $joinRequest -ContentType "application/json" -TimeoutSec 10

        if ($response.StatusCode -eq 200) {
            $clusterInfo = $response.Content | ConvertFrom-Json

            $config = @{
                ClusterName = $clusterInfo.ClusterName
                NodeId = $joinRequest.NodeId
                ListenAddress = $joinRequest.Address
                ListenPort = $JoinPort
                Nodes = $clusterInfo.Nodes
                ReplicationFactor = $clusterInfo.ReplicationFactor
                HeartbeatInterval = $clusterInfo.HeartbeatInterval
                FailoverTimeout = $clusterInfo.FailoverTimeout
                JoinedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }

            Save-ClusterConfig -Path $ConfigFile -Config $config
            Write-ClusterLog "Successfully joined cluster: $($clusterInfo.ClusterName)" "SUCCESS"
            return $config
        }
    } catch {
        Write-ClusterLog "Failed to join cluster: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-ClusterStatus {
    param([hashtable]$Config)

    Write-ClusterLog "Cluster: $($Config.ClusterName)" "INFO"
    Write-ClusterLog "Node ID: $($Config.NodeId)" "INFO"
    Write-ClusterLog "Members: $($Config.Nodes.Count)" "INFO"
    Write-ClusterLog "Replication Factor: $($Config.ReplicationFactor)" "INFO"
    Write-ClusterLog ""

    Write-Host "Node Status:" -ForegroundColor Cyan
    Write-Host "------------" -ForegroundColor Cyan

    foreach ($nodeInfo in $Config.Nodes) {
        $node = [ClusterNode]::new($nodeInfo.Address, $nodeInfo.Port)
        $node.Id = $nodeInfo.Id
        $node.Role = $nodeInfo.Role
        $node.Weight = $nodeInfo.Weight

        $healthy = Test-NodeHealth -Node $node

        $statusColor = switch ($node.Status) {
            "healthy" { "Green" }
            "degraded" { "Yellow" }
            default { "Red" }
        }

        Write-Host "  $($node.Address):$($node.Port) " -NoNewline
        Write-Host "[$($node.Role)]" -NoNewline -ForegroundColor Gray
        Write-Host " - " -NoNewline
        Write-Host $node.Status -ForegroundColor $statusColor

        if ($node.Metrics.Count -gt 0) {
            Write-Host "    TPS: $($node.Metrics.TPS) | Latency: $($node.Metrics.Latency)ms | Memory: $($node.Metrics.MemoryUsage)%" -ForegroundColor Gray
        }
    }

    # Calculate cluster health
    $healthyCount = ($Config.Nodes | Where-Object {
        $n = [ClusterNode]::new($_.Address, $_.Port)
        Test-NodeHealth -Node $n
        $n.IsHealthy()
    }).Count

    Write-Host ""
    Write-Host "Cluster Health: $healthyCount/$($Config.Nodes.Count) nodes healthy" -ForegroundColor $(if ($healthyCount -eq $Config.Nodes.Count) { "Green" } else { "Yellow" })
}

function Invoke-ClusterFailover {
    param([hashtable]$Config)

    Write-ClusterLog "Initiating cluster failover..." "WARNING"

    # Find current leader
    $currentLeader = $Config.Nodes | Where-Object { $_.Role -eq "leader" }

    if (!$currentLeader) {
        Write-ClusterLog "No leader found in cluster" "ERROR"
        return
    }

    # Test leader health
    $leaderNode = [ClusterNode]::new($currentLeader.Address, $currentLeader.Port)
    $leaderHealthy = Test-NodeHealth -Node $leaderNode

    if ($leaderHealthy) {
        Write-ClusterLog "Current leader is healthy, no failover needed" "INFO"
        return
    }

    # Find new leader among healthy backups
    $newLeader = $null
    foreach ($nodeInfo in $Config.Nodes | Where-Object { $_.Role -eq "backup" }) {
        $node = [ClusterNode]::new($nodeInfo.Address, $nodeInfo.Port)
        if (Test-NodeHealth -Node $node) {
            $newLeader = $nodeInfo
            break
        }
    }

    if ($newLeader) {
        Write-ClusterLog "Promoting $($newLeader.Address):$($newLeader.Port) to leader" "SUCCESS"

        # Update roles
        $currentLeader.Role = "backup"
        $newLeader.Role = "leader"

        Save-ClusterConfig -Path $ConfigFile -Config $Config

        # Notify all nodes of leadership change
        foreach ($nodeInfo in $Config.Nodes) {
            try {
                Invoke-WebRequest -Uri "http://$($nodeInfo.Address):$($Config.ListenPort)/cluster/leader" -Method POST -Body (@{ NewLeader = $newLeader.Id } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 5 | Out-Null
            } catch {
                Write-ClusterLog "Failed to notify $($nodeInfo.Address): $($_.Exception.Message)" "WARNING"
            }
        }
    } else {
        Write-ClusterLog "No healthy backup nodes available for failover!" "ERROR"
    }
}

function Invoke-ClusterRebalance {
    param([hashtable]$Config)

    Write-ClusterLog "Rebalancing cluster load..." "INFO"

    $healthyNodes = @()
    foreach ($nodeInfo in $Config.Nodes) {
        $node = [ClusterNode]::new($nodeInfo.Address, $nodeInfo.Port)
        if (Test-NodeHealth -Node $node) {
            $healthyNodes += @{ Node = $node; Info = $nodeInfo }
        }
    }

    if ($healthyNodes.Count -eq 0) {
        Write-ClusterLog "No healthy nodes available for rebalancing" "ERROR"
        return
    }

    # Calculate optimal weights based on performance metrics
    $totalTPS = ($healthyNodes | Measure-Object -Property { $_.Node.Metrics.TPS } -Sum).Sum

    foreach ($entry in $healthyNodes) {
        $node = $entry.Node
        $nodeInfo = $entry.Info

        if ($totalTPS -gt 0) {
            $optimalWeight = [math]::Round(($node.Metrics.TPS / $totalTPS) * 10)
            $nodeInfo.Weight = [math]::Max(1, [math]::Min(10, $optimalWeight))
        }

        Write-ClusterLog "Node $($node.Address):$($node.Port) weight set to $($nodeInfo.Weight)" "INFO"
    }

    Save-ClusterConfig -Path $ConfigFile -Config $Config
    Write-ClusterLog "Cluster rebalanced successfully" "SUCCESS"
}

# Main execution
switch ($Action) {
    "init" {
        Initialize-Cluster -ClusterName "rawrxd-cluster"
    }
    "join" {
        if (!$NodeAddress) {
            Write-ClusterLog "Node address required for join operation" "ERROR"
            exit 1
        }
        Join-Cluster -JoinAddress $NodeAddress
    }
    "leave" {
        Write-ClusterLog "Leave cluster operation not yet implemented" "WARNING"
    }
    "status" {
        $config = Load-ClusterConfig -Path $ConfigFile
        Get-ClusterStatus -Config $config
    }
    "failover" {
        $config = Load-ClusterConfig -Path $ConfigFile
        Invoke-ClusterFailover -Config $config
    }
    "rebalance" {
        $config = Load-ClusterConfig -Path $ConfigFile
        Invoke-ClusterRebalance -Config $config
    }
}

if ($Watch) {
    Write-ClusterLog "Starting cluster watch mode..." "INFO"
    while ($true) {
        Clear-Host
        $config = Load-ClusterConfig -Path $ConfigFile
        Get-ClusterStatus -Config $config
        Write-Host "`nRefreshing in 5 seconds... (Ctrl+C to exit)" -ForegroundColor Gray
        Start-Sleep -Seconds 5
    }
}
