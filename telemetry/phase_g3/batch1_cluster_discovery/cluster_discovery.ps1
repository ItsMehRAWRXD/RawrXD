#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase G.3 Batch 1/5: Cluster Discovery Service
    
.DESCRIPTION
    Auto-discovers RawrXD instances on network with service registry:
    - UDP multicast discovery (port 7946)
    - TCP health checking
    - Node metadata collection (hardware, version, capabilities)
    - Service registry with TTL-based expiration
    - Leader election for high availability
    
.PARAMETER Mode
    Operation mode: server, client, or both (default: both)
    
.PARAMETER DiscoveryPort
    UDP multicast port (default: 7946)
    
.PARAMETER RegistryPath
    Path to store service registry (default: .\cluster_registry)
    
.PARAMETER NodeId
    Unique node identifier (default: auto-generated)
    
.PARAMETER AdvertiseAddr
    Address to advertise (default: auto-detect)
    
.PARAMETER Metadata
    Additional node metadata as JSON string
    
.EXAMPLE
    .\cluster_discovery.ps1 -Mode both
    
.EXAMPLE
    .\cluster_discovery.ps1 -Mode server -DiscoveryPort 7947
    
.EXAMPLE
    .\cluster_discovery.ps1 -Mode client -NodeId "prod-01" -Metadata '{"gpu": "RX7800XT"}'
#
>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("server", "client", "both")]
    [string]$Mode = "both",
    
    [Parameter(Mandatory=$false)]
    [int]$DiscoveryPort = 7946,
    
    [Parameter(Mandatory=$false)]
    [string]$RegistryPath = ".\cluster_registry",
    
    [Parameter(Mandatory=$false)]
    [string]$NodeId = $null,
    
    [Parameter(Mandatory=$false)]
    [string]$AdvertiseAddr = $null,
    
    [Parameter(Mandatory=$false)]
    [string]$Metadata = "{}"
)

# Error action preference
$ErrorActionPreference = "Stop"

# Banner
Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase G.3 Batch 1/5: Cluster Discovery Service                     ║
║  Auto-Discovery with Service Registry & Health Checking          ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Auto-generate node ID if not provided
if (-not $NodeId) {
    $NodeId = "$(hostname)-$([Guid]::NewGuid().ToString().Substring(0,8))"
}

# Auto-detect advertise address
if (-not $AdvertiseAddr) {
    $AdvertiseAddr = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" } | Select-Object -First 1).IPAddress
    if (-not $AdvertiseAddr) { $AdvertiseAddr = "127.0.0.1" }
}

# Parse metadata
$nodeMetadata = $Metadata | ConvertFrom-Json -AsHashtable
if (-not $nodeMetadata) { $nodeMetadata = @{} }

# Add system metadata
$nodeMetadata.hostname = hostname
$nodeMetadata.os = $PSVersionTable.OS
$nodeMetadata.powershell_version = $PSVersionTable.PSVersion.ToString()
$nodeMetadata.discovery_time = Get-Date -Format "o"

# Create registry directory
New-Item -ItemType Directory -Force -Path $RegistryPath | Out-Null

# Node state
$script:NodeState = @{
    node_id = $NodeId
    address = $AdvertiseAddr
    port = $DiscoveryPort
    mode = $Mode
    metadata = $nodeMetadata
    last_heartbeat = Get-Date
    is_leader = $false
    known_nodes = [System.Collections.ArrayList]::new()
    running = $true
}

# Multicast group
$MulticastGroup = "239.255.79.46"

function Send-DiscoveryBeacon {
    <#
    .SYNOPSIS
        Sends UDP multicast discovery beacon
    #>
    $beacon = @{
        node_id = $script:NodeState.node_id
        address = $script:NodeState.address
        port = $script:NodeState.port
        timestamp = Get-Date -Format "o"
        metadata = $script:NodeState.metadata
        message_type = "DISCOVERY_BEACON"
    } | ConvertTo-Json -Compress
    
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($beacon)
    $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($MulticastGroup), $DiscoveryPort)
    
    $udpClient = New-Object System.Net.Sockets.UdpClient
    $udpClient.JoinMulticastGroup([System.Net.IPAddress]::Parse($MulticastGroup))
    $udpClient.Send($bytes, $bytes.Length, $endpoint) | Out-Null
    $udpClient.Close()
}

function Receive-DiscoveryBeacons {
    <#
    .SYNOPSIS
        Listens for UDP multicast discovery beacons
    #>
    $udpClient = New-Object System.Net.Sockets.UdpClient($DiscoveryPort)
    $udpClient.JoinMulticastGroup([System.Net.IPAddress]::Parse($MulticastGroup))
    $udpClient.Client.ReceiveTimeout = 1000
    
    $remoteEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    
    try {
        $bytes = $udpClient.Receive([ref]$remoteEndpoint)
        $message = [System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        
        if ($message.node_id -ne $script:NodeState.node_id -and $message.message_type -eq "DISCOVERY_BEACON") {
            Register-Node -NodeInfo $message
        }
    }
    catch [System.Net.Sockets.SocketException] {
        # Timeout - no beacons received
    }
    finally {
        $udpClient.Close()
    }
}

function Register-Node {
    <#
    .SYNOPSIS
        Registers discovered node in local registry
    #>
    param([hashtable]$NodeInfo)
    
    $existing = $script:NodeState.known_nodes | Where-Object { $_.node_id -eq $NodeInfo.node_id }
    
    if ($existing) {
        $existing.last_seen = Get-Date -Format "o"
        $existing.address = $NodeInfo.address
        $existing.metadata = $NodeInfo.metadata
    } else {
        $newNode = @{
            node_id = $NodeInfo.node_id
            address = $NodeInfo.address
            port = $NodeInfo.port
            first_seen = Get-Date -Format "o"
            last_seen = Get-Date -Format "o"
            metadata = $NodeInfo.metadata
            health_status = "unknown"
        }
        [void]$script:NodeState.known_nodes.Add($newNode)
        Write-Host "  + Discovered node: $($NodeInfo.node_id) at $($NodeInfo.address)" -ForegroundColor Green
    }
    
    # Persist registry
    Save-NodeRegistry
}

function Save-NodeRegistry {
    <#
    .SYNOPSIS
        Saves node registry to disk
    #>
    $registry = @{
        local_node = @{
            node_id = $script:NodeState.node_id
            address = $script:NodeState.address
            port = $script:NodeState.port
            metadata = $script:NodeState.metadata
            is_leader = $script:NodeState.is_leader
        }
        known_nodes = $script:NodeState.known_nodes
        last_updated = Get-Date -Format "o"
    }
    
    $registryPath = Join-Path $RegistryPath "cluster_registry.json"
    $registry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryPath
}

function Test-NodeHealth {
    <#
    .SYNOPSIS
        Performs health check on discovered nodes
    #>
    $nodesToCheck = $script:NodeState.known_nodes | Where-Object { 
        $lastSeen = [DateTime]::Parse($_.last_seen)
        (Get-Date) - $lastSeen -lt [TimeSpan]::FromMinutes(5)
    }
    
    foreach ($node in $nodesToCheck) {
        try {
            $response = Invoke-RestMethod -Uri "http://$($node.address):$($node.port)/health" -Method GET -TimeoutSec 2 -ErrorAction SilentlyContinue
            $node.health_status = "healthy"
            $node.last_health_check = Get-Date -Format "o"
        }
        catch {
            $node.health_status = "unreachable"
            $node.last_health_check = Get-Date -Format "o"
        }
    }
}

function Invoke-LeaderElection {
    <#
    .SYNOPSIS
        Simple leader election (lowest node_id wins)
    #>
    $allNodes = @($script:NodeState.node_id) + ($script:NodeState.known_nodes | ForEach-Object { $_.node_id })
    $sortedNodes = $allNodes | Sort-Object
    $leader = $sortedNodes[0]
    
    $script:NodeState.is_leader = ($leader -eq $script:NodeState.node_id)
    
    if ($script:NodeState.is_leader) {
        Write-Host "  ♔ Elected as leader" -ForegroundColor Yellow
    }
}

function Show-ClusterStatus {
    <#
    .SYNOPSIS
        Displays current cluster status
    #>
    Clear-Host
    Write-Host "`nCluster Discovery Status" -ForegroundColor Cyan
    Write-Host "=".PadRight(60, "=") -ForegroundColor Gray
    Write-Host "Local Node: $($script:NodeState.node_id)" -ForegroundColor White
    Write-Host "  Address: $($script:NodeState.address):$($script:NodeState.port)" -ForegroundColor Gray
    Write-Host "  Mode: $($script:NodeState.mode)" -ForegroundColor Gray
    Write-Host "  Leader: $(if ($script:NodeState.is_leader) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($script:NodeState.is_leader) { "Yellow" } else { "Gray" })
    Write-Host "`nKnown Nodes: $($script:NodeState.known_nodes.Count)" -ForegroundColor White
    
    foreach ($node in $script:NodeState.known_nodes | Sort-Object last_seen -Descending) {
        $healthColor = switch ($node.health_status) {
            "healthy" { "Green" }
            "unreachable" { "Red" }
            default { "Gray" }
        }
        $lastSeen = [DateTime]::Parse($node.last_seen)
        $ago = [Math]::Floor(((Get-Date) - $lastSeen).TotalSeconds)
        
        Write-Host "  • $($node.node_id)" -NoNewline -ForegroundColor White
        Write-Host " [$($node.health_status)]" -NoNewline -ForegroundColor $healthColor
        Write-Host " (${ago}s ago)" -ForegroundColor DarkGray
        Write-Host "    $($node.address):$($node.port)" -ForegroundColor Gray
    }
    
    Write-Host "`nPress Ctrl+C to stop`n" -ForegroundColor DarkGray
}

# Main execution
Write-Host "`nConfiguration:" -ForegroundColor Yellow
Write-Host "  Node ID: $NodeId" -ForegroundColor White
Write-Host "  Address: $AdvertiseAddr`:$DiscoveryPort" -ForegroundColor White
Write-Host "  Mode: $Mode" -ForegroundColor White
Write-Host "  Multicast Group: $MulticastGroup`:$DiscoveryPort" -ForegroundColor White
Write-Host "  Registry: $RegistryPath" -ForegroundColor White

Write-Host "`nStarting cluster discovery...`n" -ForegroundColor Green

$beaconInterval = 5
$healthCheckInterval = 30
$electionInterval = 60
$displayInterval = 10

$lastBeacon = 0
$lastHealthCheck = 0
$lastElection = 0
$lastDisplay = 0

try {
    while ($script:NodeState.running) {
        $now = Get-Date
        
        # Send discovery beacon (if server or both)
        if (($Mode -eq "server" -or $Mode -eq "both") -and ($now - $lastBeacon).TotalSeconds -ge $beaconInterval) {
            Send-DiscoveryBeacon
            $lastBeacon = $now
        }
        
        # Receive discovery beacons (if client or both)
        if ($Mode -eq "client" -or $Mode -eq "both") {
            Receive-DiscoveryBeacons
        }
        
        # Health checks
        if (($now - $lastHealthCheck).TotalSeconds -ge $healthCheckInterval) {
            Test-NodeHealth
            $lastHealthCheck = $now
        }
        
        # Leader election
        if (($now - $lastElection).TotalSeconds -ge $electionInterval) {
            Invoke-LeaderElection
            $lastElection = $now
        }
        
        # Display status
        if (($now - $lastDisplay).TotalSeconds -ge $displayInterval) {
            Show-ClusterStatus
            $lastDisplay = $now
        }
        
        Start-Sleep -Milliseconds 100
    }
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
}
finally {
    Save-NodeRegistry
    Write-Host "`nCluster discovery stopped. Registry saved." -ForegroundColor Yellow
}
