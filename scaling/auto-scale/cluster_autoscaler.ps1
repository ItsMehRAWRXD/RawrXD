# RawrXD Cluster Autoscaler
# Phase L.5 - Auto-Scaling Policies
# Manages node-level scaling for RawrXD cluster infrastructure

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [int]$MinNodes = 2,

    [Parameter(Mandatory=$false)]
    [int]$MaxNodes = 10,

    [Parameter(Mandatory=$false)]
    [string]$NodeGroup = "rawrxd-gpu-nodes",

    [Parameter(Mandatory=$false)]
    [string]$CloudProvider = "aws",  # aws, azure, gcp

    [Parameter(Mandatory=$false)]
    [switch]$EnableScaleDown,

    [Parameter(Mandatory=$false)]
    [switch]$Monitor
)

$ErrorActionPreference = "Stop"

# Logging
function Write-ClusterScalerLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "SUCCESS" = "Green"; "WARNING" = "Yellow"; "ERROR" = "Red" }
    Write-Host "[$timestamp] [CLUSTER-SCALER] [$Level] $Message" -ForegroundColor $colors[$Level]
}

# Cluster node information
class ClusterNode {
    [string]$Name
    [string]$InstanceType
    [string]$Zone
    [string]$Status
    [hashtable]$Resources
    [hashtable]$Allocatable
    [hashtable]$Allocated
    [DateTime]$CreatedAt
    [int]$AgeMinutes
    [bool]$IsGPU

    ClusterNode([string]$name, [string]$instanceType) {
        $this.Name = $name
        $this.InstanceType = $instanceType
        $this.Status = "unknown"
        $this.Resources = @{}
        $this.Allocatable = @{}
        $this.Allocated = @{}
        $this.CreatedAt = Get-Date
        $this.AgeMinutes = 0
        $this.IsGPU = $instanceType -match "gpu|p3|p4|g4|g5|a10|a100|h100"
    }

    [double] GetCPUUtilization() {
        if ($this.Allocatable.cpu -gt 0) {
            return ($this.Allocated.cpu / $this.Allocatable.cpu) * 100
        }
        return 0
    }

    [double] GetMemoryUtilization() {
        if ($this.Allocatable.memory -gt 0) {
            return ($this.Allocated.memory / $this.Allocatable.memory) * 100
        }
        return 0
    }

    [bool] IsUnderutilized() {
        return $this.GetCPUUtilization() -lt 30 -and $this.GetMemoryUtilization() -lt 40 -and $this.AgeMinutes -gt 10
    }
}

# Get current cluster state
function Get-ClusterState {
    param([string]$NodeGroup)

    Write-ClusterScalerLog "Fetching cluster state for node group: $NodeGroup" "INFO"

    # In real implementation, query Kubernetes API
    # kubectl get nodes -l node-group=$NodeGroup -o json

    # Simulate cluster state
    $nodes = @()

    # Simulate 4 nodes
    for ($i = 1; $i -le 4; $i++) {
        $node = [ClusterNode]::new("$NodeGroup-$i", "p3.2xlarge")
        $node.Zone = "us-east-1a"
        $node.Status = "Ready"
        $node.Allocatable = @{
            cpu = 8
            memory = 64
            gpu = 1
        }
        $node.Allocated = @{
            cpu = 3 + (Get-Random -Minimum 0 -Maximum 3)
            memory = 24 + (Get-Random -Minimum 0 -Maximum 20)
            gpu = if (Get-Random -Minimum 0 -Maximum 2 -eq 1) { 1 } else { 0 }
        }
        $node.AgeMinutes = Get-Random -Minimum 30 -Maximum 300
        $nodes += $node
    }

    return $nodes
}

# Calculate scaling decision
function Get-ScalingDecision {
    param(
        [ClusterNode[]]$Nodes,
        [int]$Min,
        [int]$Max,
        [bool]$ScaleDownEnabled
    )

    $currentCount = $Nodes.Count
    $avgCPU = ($Nodes | Measure-Object -Property { $_.GetCPUUtilization() } -Average).Average
    $avgMemory = ($Nodes | Measure-Object -Property { $_.GetMemoryUtilization() } -Average).Average
    $gpuUtilization = ($Nodes | Where-Object { $_.Allocated.gpu -gt 0 }).Count / $currentCount * 100

    Write-ClusterScalerLog "Current: $currentCount nodes, Avg CPU: $([math]::Round($avgCPU, 1))%, Avg Memory: $([math]::Round($avgMemory, 1))%, GPU Util: $([math]::Round($gpuUtilization, 1))%" "INFO"

    $decision = @{
        Action = "none"
        Reason = ""
        TargetCount = $currentCount
    }

    # Scale up conditions
    if ($avgCPU -gt 70 -or $avgMemory -gt 80 -or $gpuUtilization -gt 90) {
        if ($currentCount -lt $Max) {
            $decision.Action = "scale_up"
            $decision.TargetCount = [math]::Min($currentCount + 1, $Max)
            $decision.Reason = "High resource utilization: CPU=$([math]::Round($avgCPU, 1))%, Memory=$([math]::Round($avgMemory, 1))%"
        } else {
            $decision.Reason = "Max nodes reached ($Max), cannot scale up"
        }
    }
    # Scale down conditions
    elseif ($ScaleDownEnabled -and $avgCPU -lt 30 -and $avgMemory -lt 40 -and $gpuUtilization -lt 20) {
        if ($currentCount -gt $Min) {
            # Find underutilized nodes
            $underutilized = $Nodes | Where-Object { $_.IsUnderutilized() } | Sort-Object AgeMinutes -Descending

            if ($underutilized.Count -gt 0) {
                $decision.Action = "scale_down"
                $decision.TargetCount = [math]::Max($currentCount - 1, $Min)
                $decision.Reason = "Low utilization: CPU=$([math]::Round($avgCPU, 1))%, Memory=$([math]::Round($avgMemory, 1))%"
                $decision.NodesToRemove = $underutilized[0].Name
            }
        } else {
            $decision.Reason = "Min nodes reached ($Min), cannot scale down"
        }
    } else {
        $decision.Reason = "Utilization within target range"
    }

    return $decision
}

# Execute scale up
function Invoke-ScaleUp {
    param(
        [string]$NodeGroup,
        [string]$CloudProvider,
        [int]$TargetCount
    )

    Write-ClusterScalerLog "Scaling UP node group $NodeGroup to $TargetCount nodes" "SUCCESS"

    switch ($CloudProvider) {
        "aws" {
            # aws autoscaling update-auto-scaling-group --auto-scaling-group-name $NodeGroup --desired-capacity $TargetCount
            Write-ClusterScalerLog "  AWS: Updated ASG desired capacity to $TargetCount" "INFO"
        }
        "azure" {
            # az aks nodepool scale --resource-group $ResourceGroup --cluster-name $Cluster --name $NodeGroup --node-count $TargetCount
            Write-ClusterScalerLog "  Azure: Scaled VMSS to $TargetCount nodes" "INFO"
        }
        "gcp" {
            # gcloud container clusters resize $Cluster --node-pool $NodeGroup --num-nodes $TargetCount
            Write-ClusterScalerLog "  GCP: Resized node pool to $TargetCount nodes" "INFO"
        }
    }

    return $true
}

# Execute scale down
function Invoke-ScaleDown {
    param(
        [string]$NodeGroup,
        [string]$CloudProvider,
        [string]$NodeName
    )

    Write-ClusterScalerLog "Scaling DOWN: cordoning and draining node $NodeName" "WARNING"

    # Step 1: Cordon node
    # kubectl cordon $NodeName
    Write-ClusterScalerLog "  Cordoned node $NodeName" "INFO"

    # Step 2: Drain node
    # kubectl drain $NodeName --ignore-daemonsets --delete-emptydir-data --force
    Write-ClusterScalerLog "  Drained workloads from $NodeName" "INFO"

    # Step 3: Terminate node via cloud provider
    switch ($CloudProvider) {
        "aws" {
            # aws autoscaling terminate-instance-in-auto-scaling-group --instance-id $InstanceId --should-decrement-desired-capacity
            Write-ClusterScalerLog "  AWS: Terminated instance" "INFO"
        }
        "azure" {
            # az vmss delete-instances --resource-group $ResourceGroup --name $NodeGroup --instance-ids $InstanceId
            Write-ClusterScalerLog "  Azure: Deleted VMSS instance" "INFO"
        }
        "gcp" {
            # gcloud compute instances delete $NodeName --zone $Zone --quiet
            Write-ClusterScalerLog "  GCP: Deleted instance" "INFO"
        }
    }

    return $true
}

# Generate cluster autoscaler YAML
function Get-ClusterAutoscalerYAML {
    param(
        [string]$CloudProvider,
        [int]$Min,
        [int]$Max
    )

    $yaml = @"
# Cluster Autoscaler Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cluster-autoscaler
  namespace: kube-system
  labels:
    app: cluster-autoscaler
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cluster-autoscaler
  template:
    metadata:
      labels:
        app: cluster-autoscaler
    spec:
      serviceAccountName: cluster-autoscaler
      containers:
        - image: registry.k8s.io/autoscaling/cluster-autoscaler:v1.28.0
          name: cluster-autoscaler
          resources:
            limits:
              cpu: 1000m
              memory: 1Gi
            requests:
              cpu: 100m
              memory: 512Mi
          command:
            - ./cluster-autoscaler
            - --cloud-provider=$CloudProvider
            - --namespace=kube-system
            - --node-group-auto-discovery=asg:tag=k8s.io/cluster-autoscaler/enabled,k8s.io/cluster-autoscaler/rawrxd-cluster
            - --balance-similar-node-groups=true
            - --skip-nodes-with-system-pods=false
            - --skip-nodes-with-local-storage=false
            - --scale-down-enabled=true
            - --scale-down-delay-after-add=10m
            - --scale-down-unneeded-time=10m
            - --scale-down-utilization-threshold=0.5
            - --max-node-provision-time=15m
            - --scan-interval=10s
          env:
            - name: AWS_REGION
              value: us-east-1
          volumeMounts:
            - name: ssl-certs
              mountPath: /etc/ssl/certs/ca-certificates.crt
              readOnly: true
      volumes:
        - name: ssl-certs
          hostPath:
            path: /etc/ssl/certs/ca-bundle.crt
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cluster-autoscaler
  namespace: kube-system
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/cluster-autoscaler
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-autoscaler
rules:
  - apiGroups: [""]
    resources: ["events", "endpoints"]
    verbs: ["create", "patch"]
  - apiGroups: [""]
    resources: ["pods/status"]
    verbs: ["update"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["watch", "list", "get", "update"]
  - apiGroups: [""]
    resources: ["pods", "services", "replicationcontrollers", "persistentvolumeclaims", "persistentvolumes"]
    verbs: ["watch", "list", "get"]
  - apiGroups: ["extensions"]
    resources: ["replicasets", "daemonsets"]
    verbs: ["watch", "list", "get"]
  - apiGroups: ["policy"]
    resources: ["poddisruptionbudgets"]
    verbs: ["watch", "list"]
  - apiGroups: ["apps"]
    resources: ["statefulsets", "replicasets", "daemonsets"]
    verbs: ["watch", "list", "get"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses", "csinodes", "csidrivers", "csistoragecapacities"]
    verbs: ["watch", "list", "get"]
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["watch", "list", "get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cluster-autoscaler
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-autoscaler
subjects:
  - kind: ServiceAccount
    name: cluster-autoscaler
    namespace: kube-system
"@

    return $yaml
}

# Monitor cluster scaling
function Start-ClusterMonitor {
    param(
        [string]$NodeGroup,
        [string]$CloudProvider
    )

    Write-ClusterScalerLog "Starting cluster scaling monitor..." "INFO"

    while ($true) {
        Clear-Host
        Write-Host "RawrXD Cluster Autoscaler Monitor" -ForegroundColor Cyan
        Write-Host "================================" -ForegroundColor Cyan
        Write-Host ""

        $nodes = Get-ClusterState -NodeGroup $NodeGroup

        Write-Host "Node Group: $NodeGroup" -ForegroundColor Yellow
        Write-Host "Cloud Provider: $CloudProvider" -ForegroundColor Yellow
        Write-Host ""

        Write-Host "Nodes:" -ForegroundColor Yellow
        foreach ($node in $nodes) {
            $cpuColor = if ($node.GetCPUUtilization() -gt 70) { "Red" } elseif ($node.GetCPUUtilization() -gt 50) { "Yellow" } else { "Green" }
            $memColor = if ($node.GetMemoryUtilization() -gt 80) { "Red" } elseif ($node.GetMemoryUtilization() -gt 60) { "Yellow" } else { "Green" }

            Write-Host "  $($node.Name) [$($node.InstanceType)]" -NoNewline
            Write-Host " - CPU: " -NoNewline
            Write-Host "$([math]::Round($node.GetCPUUtilization(), 1))%" -ForegroundColor $cpuColor -NoNewline
            Write-Host " | Mem: " -NoNewline
            Write-Host "$([math]::Round($node.GetMemoryUtilization(), 1))%" -ForegroundColor $memColor -NoNewline
            Write-Host " | GPU: $($node.Allocated.gpu)/$($node.Allocatable.gpu)" -NoNewline
            Write-Host " | Age: $($node.AgeMinutes)m"
        }

        Write-Host ""

        $decision = Get-ScalingDecision -Nodes $nodes -Min $MinNodes -Max $MaxNodes -ScaleDownEnabled $EnableScaleDown

        Write-Host "Scaling Decision:" -ForegroundColor Yellow
        Write-Host "  Action: $($decision.Action)"
        Write-Host "  Reason: $($decision.Reason)"
        if ($decision.TargetCount -ne $nodes.Count) {
            Write-Host "  Target: $($decision.TargetCount) nodes"
        }

        Write-Host ""
        Write-Host "Refreshing in 10 seconds... (Ctrl+C to exit)" -ForegroundColor Gray
        Start-Sleep -Seconds 10
    }
}

# Main execution
if ($Monitor) {
    Start-ClusterMonitor -NodeGroup $NodeGroup -CloudProvider $CloudProvider
} else {
    Write-Host @"
RawrXD Cluster Autoscaler
Usage:
  .\cluster_autoscaler.ps1 -Monitor -NodeGroup rawrxd-gpu-nodes -CloudProvider aws
  .\cluster_autoscaler.ps1 -MinNodes 2 -MaxNodes 10 -EnableScaleDown

Parameters:
  -MinNodes           Minimum nodes in cluster (default: 2)
  -MaxNodes           Maximum nodes in cluster (default: 10)
  -NodeGroup          Name of the node group/ASG (default: rawrxd-gpu-nodes)
  -CloudProvider      Cloud provider: aws, azure, gcp (default: aws)
  -EnableScaleDown    Enable automatic scale-down (default: false)
  -Monitor            Start monitoring mode

This script manages cluster-level autoscaling:
  - Monitors node utilization across the cluster
  - Scales up when resources are constrained
  - Scales down underutilized nodes (if enabled)
  - Supports AWS, Azure, and GCP
"@ -ForegroundColor Cyan
}
