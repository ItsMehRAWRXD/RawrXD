# RawrXD Model Sharding Manager
# Phase L.3 - Distributed Model Serving
# Manages sharded model distribution across cluster nodes

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ModelPath = "",

    [Parameter(Mandatory=$false)]
    [int]$ShardCount = 4,

    [Parameter(Mandatory=$false)]
    [ValidateSet("tensor", "pipeline", "expert")]
    [string]$ShardType = "tensor",

    [Parameter(Mandatory=$false)]
    [string[]]$TargetNodes = @(),

    [Parameter(Mandatory=$false)]
    [switch]$Deploy,

    [Parameter(Mandatory=$false)]
    [switch]$Status
)

$ErrorActionPreference = "Stop"

# Logging
function Write-ShardLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "SUCCESS" = "Green"; "WARNING" = "Yellow"; "ERROR" = "Red" }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level]
}

# Model shard metadata
class ModelShard {
    [string]$ShardId
    [string]$ModelName
    [int]$ShardIndex
    [int]$TotalShards
    [string]$ShardType
    [long]$SizeBytes
    [string]$Checksum
    [string[]]$LayerRange
    [hashtable]$NodeAssignments
    [DateTime]$CreatedAt

    ModelShard([string]$modelName, [int]$index, [int]$total, [string]$type) {
        $this.ShardId = "$modelName-shard-$index-of-$total"
        $this.ModelName = $modelName
        $this.ShardIndex = $index
        $this.TotalShards = $total
        $this.ShardType = $type
        $this.NodeAssignments = @{}
        $this.CreatedAt = Get-Date
    }
}

# Calculate optimal sharding for a model
function Get-OptimalSharding {
    param(
        [string]$ModelPath,
        [int]$TargetShardCount,
        [string]$Strategy = "tensor"
    )

    Write-ShardLog "Analyzing model for optimal sharding..." "INFO"

    if (!(Test-Path $ModelPath)) {
        throw "Model path not found: $ModelPath"
    }

    $modelSize = (Get-ChildItem $ModelPath -Recurse | Measure-Object -Property Length -Sum).Sum
    $modelName = Split-Path $ModelPath -Leaf

    Write-ShardLog "Model: $modelName" "INFO"
    Write-ShardLog "Total size: $([math]::Round($modelSize / 1GB, 2)) GB" "INFO"
    Write-ShardLog "Target shards: $TargetShardCount" "INFO"
    Write-ShardLog "Strategy: $Strategy" "INFO"

    $shards = @()

    switch ($Strategy) {
        "tensor" {
            # Tensor parallelism - split attention heads and FFN
            $layersPerShard = [math]::Ceiling(100 / $TargetShardCount)  # Assuming ~100 layers

            for ($i = 0; $i -lt $TargetShardCount; $i++) {
                $shard = [ModelShard]::new($modelName, $i, $TargetShardCount, "tensor")
                $startLayer = $i * $layersPerShard
                $endLayer = [math]::Min(($i + 1) * $layersPerShard - 1, 99)
                $shard.LayerRange = @($startLayer, $endLayer)
                $shard.SizeBytes = [math]::Floor($modelSize / $TargetShardCount)
                $shards += $shard
            }
        }
        "pipeline" {
            # Pipeline parallelism - split by layer groups
            $layersPerShard = [math]::Ceiling(100 / $TargetShardCount)

            for ($i = 0; $i -lt $TargetShardCount; $i++) {
                $shard = [ModelShard]::new($modelName, $i, $TargetShardCount, "pipeline")
                $startLayer = $i * $layersPerShard
                $endLayer = [math]::Min(($i + 1) * $layersPerShard - 1, 99)
                $shard.LayerRange = @($startLayer, $endLayer)
                $shard.SizeBytes = [math]::Floor($modelSize / $TargetShardCount)
                $shards += $shard
            }
        }
        "expert" {
            # Expert parallelism - for MoE models
            $expertsPerShard = [math]::Ceiling(64 / $TargetShardCount)  # Assuming 64 experts

            for ($i = 0; $i -lt $TargetShardCount; $i++) {
                $shard = [ModelShard]::new($modelName, $i, $TargetShardCount, "expert")
                $startExpert = $i * $expertsPerShard
                $endExpert = [math]::Min(($i + 1) * $expertsPerShard - 1, 63)
                $shard.LayerRange = @($startExpert, $endExpert)
                $shard.SizeBytes = [math]::Floor($modelSize / $TargetShardCount)
                $shards += $shard
            }
        }
    }

    Write-ShardLog "Created $($shards.Count) shards" "SUCCESS"
    return $shards
}

# Assign shards to nodes based on capacity
function Assign-ShardsToNodes {
    param(
        [ModelShard[]]$Shards,
        [string[]]$Nodes
    )

    Write-ShardLog "Assigning shards to nodes..." "INFO"

    # Get node capacities
    $nodeCapacities = @{}
    foreach ($node in $Nodes) {
        try {
            $response = Invoke-WebRequest -Uri "http://$node`:8080/capacity" -TimeoutSec 5
            $capacity = $response.Content | ConvertFrom-Json
            $nodeCapacities[$node] = $capacity
            Write-ShardLog "  $node - Available: $([math]::Round($capacity.memory_available_gb, 2)) GB" "INFO"
        } catch {
            Write-ShardLog "  $node - Failed to get capacity" "WARNING"
            $nodeCapacities[$node] = @{ memory_available_gb = 0 }
        }
    }

    # Sort nodes by available capacity (descending)
    $sortedNodes = $nodeCapacities.GetEnumerator() | Sort-Object { $_.Value.memory_available_gb } -Descending

    # Assign shards using best-fit algorithm
    $assignments = @{}
    foreach ($shard in $Shards) {
        $shardSizeGB = $shard.SizeBytes / 1GB
        $assigned = $false

        foreach ($nodeEntry in $sortedNodes) {
            $node = $nodeEntry.Key
            $capacity = $nodeEntry.Value.memory_available_gb

            if ($capacity -ge $shardSizeGB) {
                $shard.NodeAssignments[$node] = @{
                    Status = "assigned"
                    AssignedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
                $nodeCapacities[$node].memory_available_gb -= $shardSizeGB
                $assigned = $true

                if (!$assignments[$node]) {
                    $assignments[$node] = @()
                }
                $assignments[$node] += $shard.ShardId

                Write-ShardLog "Assigned $($shard.ShardId) to $node" "SUCCESS"
                break
            }
        }

        if (!$assigned) {
            Write-ShardLog "Failed to assign $($shard.ShardId) - no node with sufficient capacity" "ERROR"
        }
    }

    return $assignments
}

# Deploy shards to nodes
function Deploy-ModelShards {
    param(
        [ModelShard[]]$Shards,
        [string]$SourcePath
    )

    Write-ShardLog "Deploying model shards..." "INFO"

    $deploymentResults = @()

    foreach ($shard in $Shards) {
        foreach ($nodeAssignment in $shard.NodeAssignments.GetEnumerator()) {
            $node = $nodeAssignment.Key
            $status = $nodeAssignment.Value

            try {
                Write-ShardLog "Deploying $($shard.ShardId) to $node..." "INFO"

                # Create shard package
                $shardPackage = @{
                    shard_id = $shard.ShardId
                    model_name = $shard.ModelName
                    shard_index = $shard.ShardIndex
                    total_shards = $shard.TotalShards
                    shard_type = $shard.ShardType
                    layer_range = $shard.LayerRange
                    checksum = $shard.Checksum
                } | ConvertTo-Json -Depth 10

                # Upload shard metadata
                $uploadResponse = Invoke-WebRequest -Uri "http://$node`:8080/admin/shards" -Method POST -Body $shardPackage -ContentType "application/json" -TimeoutSec 30

                if ($uploadResponse.StatusCode -eq 200) {
                    $status.Status = "deployed"
                    $status.DeployedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

                    $deploymentResults += @{
                        ShardId = $shard.ShardId
                        Node = $node
                        Status = "success"
                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }

                    Write-ShardLog "  ✓ Deployed successfully" "SUCCESS"
                }
            } catch {
                $status.Status = "failed"
                $status.Error = $_.Exception.Message

                $deploymentResults += @{
                    ShardId = $shard.ShardId
                    Node = $node
                    Status = "failed"
                    Error = $_.Exception.Message
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }

                Write-ShardLog "  ✗ Deployment failed: $($_.Exception.Message)" "ERROR"
            }
        }
    }

    return $deploymentResults
}

# Get shard deployment status
function Get-ShardStatus {
    param([string[]]$Nodes)

    Write-ShardLog "Checking shard deployment status..." "INFO"

    $allShards = @()

    foreach ($node in $Nodes) {
        try {
            $response = Invoke-WebRequest -Uri "http://$node`:8080/admin/shards" -TimeoutSec 5
            $shards = $response.Content | ConvertFrom-Json

            foreach ($shard in $shards) {
                $allShards += @{
                    ShardId = $shard.shard_id
                    Node = $node
                    Status = $shard.status
                    ModelName = $shard.model_name
                    LoadPercent = $shard.load_percent
                    LastUsed = $shard.last_used
                }
            }

            Write-ShardLog "  $node - $($shards.Count) shards" "INFO"
        } catch {
            Write-ShardLog "  $node - Failed to query" "WARNING"
        }
    }

    # Display status table
    Write-Host "`nShard Status:" -ForegroundColor Cyan
    Write-Host "--------------" -ForegroundColor Cyan

    $allShards | Sort-Object ShardId | Format-Table -AutoSize | Out-String | Write-Host

    return $allShards
}

# Main execution
if ($Status) {
    if ($TargetNodes.Count -eq 0) {
        $TargetNodes = @("192.168.1.10:8080", "192.168.1.11:8080", "192.168.1.12:8080", "192.168.1.13:8080")
    }
    Get-ShardStatus -Nodes $TargetNodes
}
elseif ($Deploy) {
    if (!$ModelPath) {
        Write-ShardLog "Model path required for deployment" "ERROR"
        exit 1
    }

    if ($TargetNodes.Count -eq 0) {
        $TargetNodes = @("192.168.1.10:8080", "192.168.1.11:8080", "192.168.1.12:8080", "192.168.1.13:8080")
    }

    # Calculate sharding
    $shards = Get-OptimalSharding -ModelPath $ModelPath -TargetShardCount $ShardCount -Strategy $ShardType

    # Assign to nodes
    $assignments = Assign-ShardsToNodes -Shards $shards -Nodes $TargetNodes

    # Deploy
    $results = Deploy-ModelShards -Shards $shards -SourcePath $ModelPath

    # Summary
    $successCount = ($results | Where-Object { $_.Status -eq "success" }).Count
    $failCount = ($results | Where-Object { $_.Status -eq "failed" }).Count

    Write-ShardLog "Deployment complete: $successCount succeeded, $failCount failed" $(if ($failCount -eq 0) { "SUCCESS" } else { "WARNING" })
}
else {
    Write-Host @"
RawrXD Model Sharding Manager
Usage:
  .\model_sharding.ps1 -Deploy -ModelPath <path> -ShardCount 4 -TargetNodes @("node1:8080", "node2:8080")
  .\model_sharding.ps1 -Status -TargetNodes @("node1:8080", "node2:8080")

Parameters:
  -ModelPath      Path to model directory
  -ShardCount     Number of shards (default: 4)
  -ShardType      Sharding strategy: tensor, pipeline, expert (default: tensor)
  -TargetNodes    Array of node addresses
  -Deploy         Deploy shards to nodes
  -Status         Check deployment status
"@ -ForegroundColor Cyan
}
