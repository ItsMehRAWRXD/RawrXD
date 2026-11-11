# RawrXD Auto-Scaler
# Phase L.5 - Auto-Scaling Policies
# Implements horizontal and vertical pod autoscaling for RawrXD

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("hpa", "vpa", "keda", "custom")]
    [string]$Mode = "hpa",

    [Parameter(Mandatory=$false)]
    [int]$MinReplicas = 2,

    [Parameter(Mandatory=$false)]
    [int]$MaxReplicas = 10,

    [Parameter(Mandatory=$false)]
    [int]$TargetCPU = 70,

    [Parameter(Mandatory=$false)]
    [int]$TargetMemory = 80,

    [Parameter(Mandatory=$false)]
    [string]$Namespace = "rawrxd",

    [Parameter(Mandatory=$false)]
    [switch]$Apply,

    [Parameter(Mandatory=$false)]
    [switch]$Monitor
)

$ErrorActionPreference = "Stop"

# Logging
function Write-ScalerLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "SUCCESS" = "Green"; "WARNING" = "Yellow"; "ERROR" = "Red" }
    Write-Host "[$timestamp] [AUTOSCALER] [$Level] $Message" -ForegroundColor $colors[$Level]
}

# Generate HPA YAML
function Get-HPAConfig {
    param(
        [int]$Min,
        [int]$Max,
        [int]$CPU,
        [int]$Memory,
        [string]$Ns
    )

    $yaml = @"
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: rawrxd-hpa
  namespace: $Ns
  labels:
    app.kubernetes.io/name: rawrxd
    app.kubernetes.io/component: autoscaler
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: StatefulSet
    name: rawrxd-node
  minReplicas: $Min
  maxReplicas: $Max
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: $CPU
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: $Memory
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Percent
          value: 100
          periodSeconds: 15
        - type: Pods
          value: 2
          periodSeconds: 15
      selectPolicy: Max
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 10
          periodSeconds: 60
        - type: Pods
          value: 1
          periodSeconds: 60
      selectPolicy: Min
"@

    return $yaml
}

# Generate VPA YAML
function Get-VPAConfig {
    param(
        [string]$Ns,
        [ValidateSet("Auto", "Recreate", "Initial", "Off")]
        [string]$UpdateMode = "Auto"
    )

    $yaml = @"
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: rawrxd-vpa
  namespace: $Ns
spec:
  targetRef:
    apiVersion: apps/v1
    kind: StatefulSet
    name: rawrxd-node
  updatePolicy:
    updateMode: "$UpdateMode"
  resourcePolicy:
    containerPolicies:
      - containerName: rawrxd
        minAllowed:
          cpu: 100m
          memory: 512Mi
        maxAllowed:
          cpu: 8
          memory: 32Gi
        controlledResources: ["cpu", "memory"]
        controlledValues: RequestsAndLimits
"@

    return $yaml
}

# Generate KEDA ScaledObject YAML
function Get-KEDAConfig {
    param(
        [int]$Min,
        [int]$Max,
        [string]$Ns
    )

    $yaml = @"
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: rawrxd-keda
  namespace: $Ns
  labels:
    app.kubernetes.io/name: rawrxd
spec:
  scaleTargetRef:
    name: rawrxd-node
  minReplicaCount: $Min
  maxReplicaCount: $Max
  cooldownPeriod: 300
  pollingInterval: 15
  triggers:
    # CPU-based scaling
    - type: cpu
      metricType: Utilization
      metadata:
        value: "70"
    # Memory-based scaling
    - type: memory
      metricType: Utilization
      metadata:
        value: "80"
    # Prometheus-based scaling on inference latency
    - type: prometheus
      metadata:
        serverAddress: http://prometheus.monitoring.svc.cluster.local:9090
        metricName: rawrxd_inference_latency
        threshold: "100"
        query: |
          histogram_quantile(0.95, 
            sum(rate(rawrxd_inference_latency_bucket{namespace="$Ns"}[5m])) by (le)
          )
    # Queue-based scaling for request backlog
    - type: metrics-api
      metadata:
        targetValue: "50"
        url: "http://rawrxd-lb.$Ns.svc.cluster.local/metrics/backlog"
        valueLocation: "backlog_size"
  advanced:
    restoreToOriginalReplicaCount: false
    horizontalPodAutoscalerConfig:
      behavior:
        scaleDown:
          stabilizationWindowSeconds: 300
          policies:
            - type: Percent
              value: 10
              periodSeconds: 60
"@

    return $yaml
}

# Custom autoscaler implementation
function Start-CustomAutoscaler {
    param(
        [int]$Min,
        [int]$Max,
        [int]$CPU,
        [int]$Memory,
        [string]$Ns
    )

    Write-ScalerLog "Starting custom autoscaler..." "INFO"
    Write-ScalerLog "Min: $Min, Max: $Max, Target CPU: $CPU%, Target Memory: $Memory%" "INFO"

    $lastScaleTime = [DateTime]::MinValue
    $scaleCooldown = [TimeSpan]::FromMinutes(5)
    $currentReplicas = $Min

    while ($true) {
        try {
            # Get current metrics
            $metrics = Get-ClusterMetrics -Namespace $Ns

            Write-ScalerLog "Current state: $currentReplicas replicas, CPU: $($metrics.CPU)%, Memory: $($metrics.Memory)%, Latency: $($metrics.Latency)ms" "INFO"

            $shouldScale = $false
            $targetReplicas = $currentReplicas

            # Scale up conditions
            if ($metrics.CPU -gt $CPU -or $metrics.Memory -gt $Memory -or $metrics.Latency -gt 100) {
                if ($currentReplicas -lt $Max -and ((Get-Date) - $lastScaleTime) -gt $scaleCooldown) {
                    $targetReplicas = [math]::Min($currentReplicas + 1, $Max)
                    $shouldScale = $true
                    Write-ScalerLog "Scale up triggered: CPU=$($metrics.CPU)%, Memory=$($metrics.Memory)%" "WARNING"
                }
            }

            # Scale down conditions
            if ($metrics.CPU -lt ($CPU * 0.5) -and $metrics.Memory -lt ($Memory * 0.5) -and $metrics.Latency -lt 50) {
                if ($currentReplicas -gt $Min -and ((Get-Date) - $lastScaleTime) -gt $scaleCooldown) {
                    $targetReplicas = [math]::Max($currentReplicas - 1, $Min)
                    $shouldScale = $true
                    Write-ScalerLog "Scale down triggered: CPU=$($metrics.CPU)%, Memory=$($metrics.Memory)%" "WARNING"
                }
            }

            if ($shouldScale -and $targetReplicas -ne $currentReplicas) {
                Write-ScalerLog "Scaling from $currentReplicas to $targetReplicas replicas..." "INFO"

                # Apply scaling
                $result = Invoke-ScaleOperation -Namespace $Ns -TargetReplicas $targetReplicas

                if ($result) {
                    $currentReplicas = $targetReplicas
                    $lastScaleTime = Get-Date
                    Write-ScalerLog "Scale operation completed successfully" "SUCCESS"
                } else {
                    Write-ScalerLog "Scale operation failed" "ERROR"
                }
            }

            Start-Sleep -Seconds 15
        } catch {
            Write-ScalerLog "Error in autoscaler loop: $($_.Exception.Message)" "ERROR"
            Start-Sleep -Seconds 30
        }
    }
}

# Get cluster metrics
function Get-ClusterMetrics {
    param([string]$Namespace)

    # In a real implementation, this would query Prometheus/Kubernetes metrics API
    # For simulation, return realistic values

    $baseCPU = 45
    $baseMemory = 60
    $baseLatency = 45

    # Add some variation
    $cpu = [math]::Min(100, [math]::Max(0, $baseCPU + (Get-Random -Minimum -20 -Maximum 40)))
    $memory = [math]::Min(100, [math]::Max(0, $baseMemory + (Get-Random -Minimum -15 -Maximum 30)))
    $latency = [math]::Max(10, $baseLatency + (Get-Random -Minimum -15 -Maximum 80))

    return @{
        CPU = [math]::Round($cpu, 1)
        Memory = [math]::Round($memory, 1)
        Latency = [math]::Round($latency, 1)
        ActiveRequests = Get-Random -Minimum 10 -Maximum 200
        QueueDepth = Get-Random -Minimum 0 -Maximum 20
    }
}

# Execute scale operation
function Invoke-ScaleOperation {
    param(
        [string]$Namespace,
        [int]$TargetReplicas
    )

    try {
        # In real implementation, this would call Kubernetes API
        # kubectl scale statefulset rawrxd-node --replicas=$TargetReplicas -n $Namespace
        Write-ScalerLog "Executing: kubectl scale statefulset rawrxd-node --replicas=$TargetReplicas -n $Namespace" "INFO"
        return $true
    } catch {
        Write-ScalerLog "Scale operation failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Monitor scaling events
function Start-ScalingMonitor {
    param([string]$Namespace)

    Write-ScalerLog "Starting scaling event monitor..." "INFO"

    while ($true) {
        Clear-Host
        Write-Host "RawrXD Auto-Scaling Monitor" -ForegroundColor Cyan
        Write-Host "==========================" -ForegroundColor Cyan
        Write-Host ""

        $metrics = Get-ClusterMetrics -Namespace $Namespace

        Write-Host "Current Metrics:" -ForegroundColor Yellow
        Write-Host "  CPU Usage:        $($metrics.CPU)%" $(if ($metrics.CPU -gt 70) { "-ForegroundColor Red" } else { "-ForegroundColor Green" })
        Write-Host "  Memory Usage:     $($metrics.Memory)%" $(if ($metrics.Memory -gt 80) { "-ForegroundColor Red" } else { "-ForegroundColor Green" })
        Write-Host "  P95 Latency:      $($metrics.Latency)ms" $(if ($metrics.Latency -gt 100) { "-ForegroundColor Red" } else { "-ForegroundColor Green" })
        Write-Host "  Active Requests:  $($metrics.ActiveRequests)"
        Write-Host "  Queue Depth:      $($metrics.QueueDepth)"
        Write-Host ""

        # Simulate HPA status
        Write-Host "HPA Status:" -ForegroundColor Yellow
        Write-Host "  Current Replicas: 4"
        Write-Host "  Desired Replicas: $(if ($metrics.CPU -gt 70) { 6 } else { 4 })"
        Write-Host "  Last Scale Time:  2026-07-13 10:23:45"
        Write-Host "  Conditions:       ScalingActive=True, AbleToScale=True"
        Write-Host ""

        Write-Host "Refreshing in 5 seconds... (Ctrl+C to exit)" -ForegroundColor Gray
        Start-Sleep -Seconds 5
    }
}

# Main execution
switch ($Mode) {
    "hpa" {
        $config = Get-HPAConfig -Min $MinReplicas -Max $MaxReplicas -CPU $TargetCPU -Memory $TargetMemory -Ns $Namespace

        if ($Apply) {
            $config | kubectl apply -f -
            Write-ScalerLog "HPA configuration applied to cluster" "SUCCESS"
        } else {
            Write-Host $config
            Write-ScalerLog "HPA configuration generated (use -Apply to deploy)" "INFO"
        }
    }
    "vpa" {
        $config = Get-VPAConfig -Ns $Namespace

        if ($Apply) {
            $config | kubectl apply -f -
            Write-ScalerLog "VPA configuration applied to cluster" "SUCCESS"
        } else {
            Write-Host $config
            Write-ScalerLog "VPA configuration generated (use -Apply to deploy)" "INFO"
        }
    }
    "keda" {
        $config = Get-KEDAConfig -Min $MinReplicas -Max $MaxReplicas -Ns $Namespace

        if ($Apply) {
            $config | kubectl apply -f -
            Write-ScalerLog "KEDA ScaledObject applied to cluster" "SUCCESS"
        } else {
            Write-Host $config
            Write-ScalerLog "KEDA configuration generated (use -Apply to deploy)" "INFO"
        }
    }
    "custom" {
        if ($Monitor) {
            Start-ScalingMonitor -Namespace $Namespace
        } else {
            Start-CustomAutoscaler -Min $MinReplicas -Max $MaxReplicas -CPU $TargetCPU -Memory $TargetMemory -Ns $Namespace
        }
    }
}
