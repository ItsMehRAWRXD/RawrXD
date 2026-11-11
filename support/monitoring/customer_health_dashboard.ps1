# RawrXD Customer Health Dashboard
# Phase P.3 - Customer Success Monitoring
# Real-time dashboard for monitoring customer deployments

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "customer_deployments.json",

    [Parameter(Mandatory=$false)]
    [switch]$Watch,

    [Parameter(Mandatory=$false)]
    [int]$RefreshInterval = 30
)

$ErrorActionPreference = "Stop"

# Customer deployment class
class CustomerDeployment {
    [string]$CustomerId
    [string]$CustomerName
    [string]$Environment
    [string]$Endpoint
    [string]$ApiKey
    [hashtable]$Status
    [hashtable]$Metrics
    [DateTime]$LastCheck
    [array]$Alerts

    CustomerDeployment([string]$id, [string]$name, [string]$endpoint) {
        $this.CustomerId = $id
        $this.CustomerName = $name
        $this.Endpoint = $endpoint
        $this.Environment = "production"
        $this.Status = @{}
        $this.Metrics = @{}
        $this.Alerts = @()
        $this.LastCheck = [DateTime]::MinValue
    }
}

# Logging
function Write-DashboardLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "SUCCESS" = "Green"; "WARNING" = "Yellow"; "ERROR" = "Red"; "ALERT" = "Magenta" }
    Write-Host "[$timestamp] [DASHBOARD] [$Level] $Message" -ForegroundColor $colors[$Level]
}

# Load customer deployments
function Import-CustomerDeployments {
    param([string]$Path)

    if (Test-Path $Path) {
        $json = Get-Content $Path -Raw | ConvertFrom-Json
        $deployments = @()
        foreach ($item in $json) {
            $dep = [CustomerDeployment]::new($item.customer_id, $item.customer_name, $item.endpoint)
            $dep.Environment = $item.environment
            $dep.ApiKey = $item.api_key
            $deployments += $dep
        }
        return $deployments
    }

    # Return sample data if no config
    return @(
        [CustomerDeployment]::new("C001", "Acme Corp", "https://acme.rawrxd.local"),
        [CustomerDeployment]::new("C002", "TechStart Inc", "https://techstart.rawrxd.local"),
        [CustomerDeployment]::new("C003", "Global Systems", "https://global.rawrxd.local")
    )
}

# Check deployment health
function Test-DeploymentHealth {
    param([CustomerDeployment]$Deployment)

    try {
        $headers = @{}
        if ($Deployment.ApiKey) {
            $headers["Authorization"] = "Bearer $($Deployment.ApiKey)"
        }

        $response = Invoke-WebRequest -Uri "$($Deployment.Endpoint)/health" -Headers $headers -TimeoutSec 10
        $health = $response.Content | ConvertFrom-Json

        $Deployment.Status = @{
            healthy = $true
            status = $health.status
            version = $health.version
            uptime = $health.uptime
            models_loaded = $health.models_loaded
            gpu_available = $health.gpu_available
        }

        $Deployment.LastCheck = Get-Date

        # Get metrics
        $metricsResponse = Invoke-WebRequest -Uri "$($Deployment.Endpoint)/metrics" -Headers $headers -TimeoutSec 10
        $metrics = Parse-PrometheusMetrics -Data $metricsResponse.Content

        $Deployment.Metrics = @{
            requests_per_second = $metrics["rawrxd_requests_per_second"]
            avg_latency_ms = $metrics["rawrxd_request_duration_seconds_sum"] / $metrics["rawrxd_request_duration_seconds_count"] * 1000
            error_rate = $metrics["rawrxd_errors_total"] / $metrics["rawrxd_requests_total"]
            memory_usage_percent = $metrics["rawrxd_memory_usage_percent"]
            gpu_utilization = $metrics["rawrxd_gpu_utilization_percent"]
        }

        # Check for alerts
        $Deployment.Alerts = @()
        if ($Deployment.Metrics.avg_latency_ms -gt 500) {
            $Deployment.Alerts += "High latency: $([Math]::Round($Deployment.Metrics.avg_latency_ms, 2))ms"
        }
        if ($Deployment.Metrics.error_rate -gt 0.01) {
            $Deployment.Alerts += "High error rate: $([Math]::Round($Deployment.Metrics.error_rate * 100, 2))%"
        }
        if ($Deployment.Metrics.memory_usage_percent -gt 90) {
            $Deployment.Alerts += "Memory pressure: $([Math]::Round($Deployment.Metrics.memory_usage_percent, 1))%"
        }

        return $true
    } catch {
        $Deployment.Status = @{
            healthy = $false
            error = $_.Exception.Message
        }
        $Deployment.LastCheck = Get-Date
        $Deployment.Alerts = @("Unreachable: $($_.Exception.Message)")
        return $false
    }
}

# Parse Prometheus metrics
function Parse-PrometheusMetrics {
    param([string]$Data)

    $metrics = @{}
    $lines = $Data -split "`n"

    foreach ($line in $lines) {
        if ($line -match '^([a-zA-Z_][a-zA-Z0-9_]*)\s+([0-9.e+-]+)$') {
            $name = $matches[1]
            $value = [double]$matches[2]
            $metrics[$name] = $value
        }
    }

    return $metrics
}

# Display dashboard
function Show-HealthDashboard {
    param([CustomerDeployment[]]$Deployments)

    Clear-Host
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    RawrXD Customer Health Dashboard                            ║" -ForegroundColor Cyan
    Write-Host "║                    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')                              ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    # Summary
    $healthy = ($Deployments | Where-Object { $_.Status.healthy }).Count
    $unhealthy = ($Deployments | Where-Object { -not $_.Status.healthy }).Count
    $totalAlerts = ($Deployments | Measure-Object -Property { $_.Alerts.Count } -Sum).Sum

    Write-Host "Summary: " -NoNewline
    Write-Host "$healthy Healthy" -ForegroundColor Green -NoNewline
    Write-Host " | " -NoNewline
    Write-Host "$unhealthy Unhealthy" -ForegroundColor $(if ($unhealthy -gt 0) { "Red" } else { "Green" }) -NoNewline
    Write-Host " | " -NoNewline
    Write-Host "$totalAlerts Alerts" -ForegroundColor $(if ($totalAlerts -gt 0) { "Yellow" } else { "Green" })
    Write-Host ""

    # Customer table
    Write-Host "Customer Deployments:" -ForegroundColor Yellow
    Write-Host "─────────────────────────────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host "{0,-12} {1,-20} {2,-12} {3,-10} {4,-12} {5,-8}" -f "Customer", "Name", "Status", "Version", "Latency", "Alerts" -ForegroundColor Gray
    Write-Host "─────────────────────────────────────────────────────────────────────────────" -ForegroundColor Gray

    foreach ($dep in $Deployments | Sort-Object CustomerId) {
        $statusColor = if ($dep.Status.healthy) { "Green" } else { "Red" }
        $statusText = if ($dep.Status.healthy) { "✓ Healthy" } else { "✗ Down" }

        $latency = if ($dep.Metrics.avg_latency_ms) {
            "$([Math]::Round($dep.Metrics.avg_latency_ms, 0))ms"
        } else { "N/A" }

        $latencyColor = if ($dep.Metrics.avg_latency_ms -gt 500) { "Red" } elseif ($dep.Metrics.avg_latency_ms -gt 200) { "Yellow" } else { "Green" }

        $alertCount = $dep.Alerts.Count
        $alertColor = if ($alertCount -gt 0) { "Red" } else { "Green" }

        Write-Host "{0,-12} {1,-20} " -f $dep.CustomerId, $dep.CustomerName -NoNewline
        Write-Host "{0,-12} " -f $statusText -ForegroundColor $statusColor -NoNewline
        Write-Host "{0,-10} " -f $dep.Status.version -NoNewline
        Write-Host "{0,-12} " -f $latency -ForegroundColor $latencyColor -NoNewline
        Write-Host "{0,-8}" -f $alertCount -ForegroundColor $alertColor
    }

    Write-Host "─────────────────────────────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host ""

    # Active alerts
    $allAlerts = $Deployments | Where-Object { $_.Alerts.Count -gt 0 }
    if ($allAlerts.Count -gt 0) {
        Write-Host "Active Alerts:" -ForegroundColor Red
        foreach ($dep in $allAlerts) {
            Write-Host "  [$($dep.CustomerId)] $($dep.CustomerName):" -ForegroundColor Yellow
            foreach ($alert in $dep.Alerts) {
                Write-Host "    ⚠ $alert" -ForegroundColor Red
            }
        }
        Write-Host ""
    }

    # Legend
    Write-Host "Legend: " -NoNewline -ForegroundColor Gray
    Write-Host "✓ Healthy" -ForegroundColor Green -NoNewline
    Write-Host " | " -NoNewline -ForegroundColor Gray
    Write-Host "✗ Down" -ForegroundColor Red -NoNewline
    Write-Host " | " -NoNewline -ForegroundColor Gray
    Write-Host "⚠ Alert" -ForegroundColor Yellow
    Write-Host ""

    Write-Host "Press Ctrl+C to exit" -ForegroundColor DarkGray
}

# Generate health report
function Export-HealthReport {
    param(
        [CustomerDeployment[]]$Deployments,
        [string]$OutputPath
    )

    $report = @{
        generated_at = Get-Date -Format "o"
        summary = @{
            total_deployments = $Deployments.Count
            healthy = ($Deployments | Where-Object { $_.Status.healthy }).Count
            unhealthy = ($Deployments | Where-Object { -not $_.Status.healthy }).Count
            total_alerts = ($Deployments | Measure-Object -Property { $_.Alerts.Count } -Sum).Sum
        }
        deployments = $Deployments | ForEach-Object {
            @{
                customer_id = $_.CustomerId
                customer_name = $_.CustomerName
                environment = $_.Environment
                endpoint = $_.Endpoint
                status = $_.Status
                metrics = $_.Metrics
                alerts = $_.Alerts
                last_check = $_.LastCheck.ToString("o")
            }
        }
    }

    $report | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8
    Write-DashboardLog "Report saved to $OutputPath" "SUCCESS"
}

# Main execution
Write-DashboardLog "RawrXD Customer Health Dashboard Started" "INFO"

$deployments = Import-CustomerDeployments -Path $ConfigFile
Write-DashboardLog "Loaded $($deployments.Count) customer deployments" "INFO"

if ($Watch) {
    Write-DashboardLog "Starting watch mode (refresh every $RefreshInterval seconds)" "INFO"

    while ($true) {
        # Check all deployments
        foreach ($dep in $deployments) {
            Test-DeploymentHealth -Deployment $dep | Out-Null
        }

        # Display dashboard
        Show-HealthDashboard -Deployments $deployments

        Start-Sleep -Seconds $RefreshInterval
    }
} else {
    # Single check
    foreach ($dep in $deployments) {
        Test-DeploymentHealth -Deployment $dep | Out-Null
    }

    Show-HealthDashboard -Deployments $deployments

    # Export report
    $reportPath = "customer_health_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    Export-HealthReport -Deployments $deployments -OutputPath $reportPath
}
