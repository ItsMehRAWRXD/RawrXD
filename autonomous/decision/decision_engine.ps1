# RawrXD Autonomous Decision Engine
# Phase G.3 Batch 1/5: Automated Decision Making
# Makes autonomous decisions based on analytics from Phase G.2

param(
    [Parameter()]
    [switch]$Daemon,
    
    [Parameter()]
    [int]$DecisionIntervalSeconds = 30,
    
    [Parameter()]
    [ValidateSet("Conservative", "Balanced", "Aggressive")]
    [string]$RiskProfile = "Balanced",
    
    [Parameter()]
    [switch]$DryRun,
    
    [Parameter()]
    [string]$ConfigPath = "$PSScriptRoot\decision_config.json",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\autonomous\decisions",
    
    [Parameter()]
    [switch]$ShowStatus
)

# Risk profile thresholds
$RiskProfiles = @{
    Conservative = @{
        ConfidenceThreshold = 0.85
        ActionCooldownMinutes = 10
        MaxActionsPerHour = 3
        RequireHumanApproval = $true
        RollbackOnAnomaly = $true
    }
    Balanced = @{
        ConfidenceThreshold = 0.75
        ActionCooldownMinutes = 5
        MaxActionsPerHour = 6
        RequireHumanApproval = $false
        RollbackOnAnomaly = $true
    }
    Aggressive = @{
        ConfidenceThreshold = 0.65
        ActionCooldownMinutes = 2
        MaxActionsPerHour = 12
        RequireHumanApproval = $false
        RollbackOnAnomaly = $false
    }
}

# Decision types and their handlers
$DecisionTypes = @{
    Scale = @{
        Description = "Scale resources up or down"
        Action = {
            param($Decision, $Context)
            $direction = if ($Decision.Parameters.Direction -eq "Up") { "up" } else { "down" }
            Write-DecisionLog "Scaling $direction by $($Decision.Parameters.Amount) units"
            
            if (-not $DryRun) {
                # Call capacity planner to execute scaling
                $capacityPlanner = "$PSScriptRoot\..\..\analytics\capacity\capacity_planner.ps1"
                if (Test-Path $capacityPlanner) {
                    & $capacityPlanner -SimulateScaling -Verbose:$false
                }
            }
            return $true
        }
    }
    Optimize = @{
        Description = "Optimize resource parameters"
        Action = {
            param($Decision, $Context)
            Write-DecisionLog "Optimizing parameters: $($Decision.Parameters.Changes -join ', ')"
            
            if (-not $DryRun) {
                $optimizer = "$PSScriptRoot\..\..\analytics\optimizer\resource_optimizer.ps1"
                if (Test-Path $optimizer) {
                    & $optimizer -AutoTune -Strategy $RiskProfile -Verbose:$false
                }
            }
            return $true
        }
    }
    Alert = @{
        Description = "Send alert notification"
        Action = {
            param($Decision, $Context)
            Write-DecisionLog "Sending alert: $($Decision.Parameters.Message)"
            
            if (-not $DryRun) {
                # Send to monitoring webhook
                $monitor = "$PSScriptRoot\..\..\governance\monitoring\health_monitor.ps1"
                if (Test-Path $monitor) {
                    & $monitor -Action alert -Message $Decision.Parameters.Message -Severity $Decision.Parameters.Severity
                }
            }
            return $true
        }
    }
    Rebalance = @{
        Description = "Rebalance load across backends"
        Action = {
            param($Decision, $Context)
            Write-DecisionLog "Rebalancing load with algorithm: $($Decision.Parameters.Algorithm)"
            
            if (-not $DryRun) {
                $lb = "$PSScriptRoot\..\..\analytics\loadbalancer\load_balancer.ps1"
                if (Test-Path $lb) {
                    # Signal load balancer to rebalance
                    $signalFile = "$PSScriptRoot\..\..\analytics\loadbalancer\rebalance.signal"
                    "REBALANCE:$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $signalFile -Encoding UTF8
                }
            }
            return $true
        }
    }
    CircuitBreak = @{
        Description = "Trigger circuit breaker"
        Action = {
            param($Decision, $Context)
            Write-DecisionLog "Triggering circuit breaker for: $($Decision.Parameters.Service)"
            
            if (-not $DryRun) {
                $healing = "$PSScriptRoot\..\..\governance\healing\self_healing.ps1"
                if (Test-Path $healing) {
                    & $healing -Action trip -Service $Decision.Parameters.Service
                }
            }
            return $true
        }
    }
    Rollback = @{
        Description = "Rollback previous changes"
        Action = {
            param($Decision, $Context)
            Write-DecisionLog "Rolling back changes from: $($Decision.Parameters.Timestamp)"
            
            if (-not $DryRun) {
                $optimizer = "$PSScriptRoot\..\..\analytics\optimizer\resource_optimizer.ps1"
                if (Test-Path $optimizer) {
                    & $optimizer -Rollback -Verbose:$false
                }
            }
            return $true
        }
    }
}

# Ensure log directory exists
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# State file for tracking decisions
$StateFile = "$PSScriptRoot\decision_state.json"

function Write-DecisionLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $logFile = Join-Path $LogPath "decisions_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "ACTION" { "Green" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-DecisionState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        LastDecisionTime = $null
        DecisionsLastHour = @()
        TotalDecisions = 0
        SuccessfulDecisions = 0
        FailedDecisions = 0
        PendingApprovals = @()
        DecisionHistory = @()
    }
}

function Save-DecisionState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function Get-AnalyticsData {
    $data = @{}
    
    # Get prediction data
    $predictionFile = "$PSScriptRoot\..\..\analytics\prediction\models\latest_forecast.json"
    if (Test-Path $predictionFile) {
        $data.Predictions = Get-Content $predictionFile | ConvertFrom-Json
    }
    
    # Get anomaly data
    $anomalyFile = "$PSScriptRoot\..\..\analytics\anomaly\anomaly_models\latest_anomalies.json"
    if (Test-Path $anomalyFile) {
        $data.Anomalies = Get-Content $anomalyFile | ConvertFrom-Json
    }
    
    # Get capacity data
    $capacityFile = "$PSScriptRoot\..\..\analytics\capacity\capacity_plans\latest_plan.json"
    if (Test-Path $capacityFile) {
        $data.Capacity = Get-Content $capacityFile | ConvertFrom-Json
    }
    
    # Get current metrics from telemetry
    $telemetryFile = "$PSScriptRoot\..\..\governance\telemetry\latest_metrics.json"
    if (Test-Path $telemetryFile) {
        $data.CurrentMetrics = Get-Content $telemetryFile | ConvertFrom-Json
    }
    
    return $data
}

function Evaluate-DecisionCondition {
    param($Condition, $AnalyticsData)
    
    switch ($Condition.Type) {
        "MetricThreshold" {
            $metric = $AnalyticsData.CurrentMetrics.$($Condition.Metric)
            if ($null -eq $metric) { return $false }
            
            switch ($Condition.Operator) {
                "GreaterThan" { return $metric -gt $Condition.Value }
                "LessThan" { return $metric -lt $Condition.Value }
                "Equals" { return $metric -eq $Condition.Value }
                "GreaterThanOrEqual" { return $metric -ge $Condition.Value }
                "LessThanOrEqual" { return $metric -le $Condition.Value }
            }
        }
        "AnomalyDetected" {
            if ($null -eq $AnalyticsData.Anomalies) { return $false }
            return $AnalyticsData.Anomalies.Count -gt 0
        }
        "PredictionConfidence" {
            if ($null -eq $AnalyticsData.Predictions) { return $false }
            return $AnalyticsData.Predictions.Confidence -ge $Condition.Threshold
        }
        "CapacityForecast" {
            if ($null -eq $AnalyticsData.Capacity) { return $false }
            return $AnalyticsData.Capacity.Recommendations.Count -gt 0
        }
        "TimeBased" {
            $now = Get-Date
            $inWindow = $now.Hour -ge $Condition.StartHour -and $now.Hour -lt $Condition.EndHour
            return $inWindow
        }
        "Composite" {
            # All sub-conditions must be true
            foreach ($subCondition in $Condition.Conditions) {
                if (-not (Evaluate-DecisionCondition -Condition $subCondition -AnalyticsData $AnalyticsData)) {
                    return $false
                }
            }
            return $true
        }
    }
    
    return $false
}

function Calculate-DecisionConfidence {
    param($Decision, $AnalyticsData)
    
    $confidence = 0.5  # Base confidence
    
    # Boost confidence based on data quality
    if ($null -ne $AnalyticsData.CurrentMetrics) {
        $confidence += 0.1
    }
    if ($null -ne $AnalyticsData.Predictions) {
        $confidence += 0.15
    }
    if ($null -ne $AnalyticsData.Anomalies -and $AnalyticsData.Anomalies.Count -eq 0) {
        $confidence += 0.1  # No anomalies = more confident
    }
    
    # Adjust based on decision type
    switch ($Decision.Type) {
        "Alert" { $confidence += 0.1 }  # Low risk
        "Scale" { $confidence += 0.05 }
        "Optimize" { $confidence += 0.0 }
        "Rebalance" { $confidence -= 0.05 }
        "CircuitBreak" { $confidence -= 0.1 }  # Higher risk
        "Rollback" { $confidence -= 0.15 }  # Highest risk
    }
    
    # Cap at 0.95
    return [Math]::Min($confidence, 0.95)
}

function Generate-DecisionRecommendations {
    param($AnalyticsData, $RiskConfig)
    
    $recommendations = @()
    
    # Check for capacity needs
    if ($null -ne $AnalyticsData.Capacity -and $AnalyticsData.Capacity.Recommendations) {
        foreach ($rec in $AnalyticsData.Capacity.Recommendations) {
            if ($rec.Action -eq "ScaleUp" -or $rec.Action -eq "ScaleDown") {
                $recommendations += @{
                    Type = "Scale"
                    Priority = if ($rec.Urgency -eq "High") { 1 } else { 2 }
                    Parameters = @{
                        Direction = if ($rec.Action -eq "ScaleUp") { "Up" } else { "Down" }
                        Amount = $rec.Amount
                        Reason = $rec.Reason
                    }
                    Conditions = @(
                        @{ Type = "CapacityForecast" }
                    )
                }
            }
        }
    }
    
    # Check for anomalies requiring action
    if ($null -ne $AnalyticsData.Anomalies) {
        $criticalAnomalies = $AnalyticsData.Anomalies | Where-Object { $_.Severity -eq "Critical" }
        if ($criticalAnomalies.Count -gt 0) {
            $recommendations += @{
                Type = "Alert"
                Priority = 1
                Parameters = @{
                    Message = "Critical anomalies detected: $($criticalAnomalies.Count)"
                    Severity = "Critical"
                    Anomalies = $criticalAnomalies
                }
                Conditions = @(
                    @{ Type = "AnomalyDetected" }
                )
            }
            
            if ($RiskConfig.RollbackOnAnomaly) {
                $recommendations += @{
                    Type = "Rollback"
                    Priority = 1
                    Parameters = @{
                        Reason = "Critical anomalies detected"
                        Timestamp = (Get-Date).AddHours(-1).ToString("yyyy-MM-dd HH:mm:ss")
                    }
                    Conditions = @(
                        @{ Type = "AnomalyDetected" }
                    )
                }
            }
        }
        
        $warningAnomalies = $AnalyticsData.Anomalies | Where-Object { $_.Severity -eq "Warning" }
        if ($warningAnomalies.Count -gt 0) {
            $recommendations += @{
                Type = "Alert"
                Priority = 2
                Parameters = @{
                    Message = "Warning-level anomalies detected: $($warningAnomalies.Count)"
                    Severity = "Warning"
                    Anomalies = $warningAnomalies
                }
                Conditions = @(
                    @{ Type = "AnomalyDetected" }
                )
            }
        }
    }
    
    # Check for optimization opportunities
    if ($null -ne $AnalyticsData.Predictions) {
        $forecast = $AnalyticsData.Predictions
        if ($forecast.Trend -eq "Declining" -and $forecast.Confidence -gt 0.7) {
            $recommendations += @{
                Type = "Optimize"
                Priority = 3
                Parameters = @{
                    Changes = @("ThreadCount", "BatchSize")
                    Reason = "Performance trend declining"
                    ExpectedImprovement = "10-15%"
                }
                Conditions = @(
                    @{ 
                        Type = "Composite"
                        Conditions = @(
                            @{ Type = "PredictionConfidence"; Threshold = 0.7 }
                            @{ Type = "MetricThreshold"; Metric = "TPS"; Operator = "LessThan"; Value = 35 }
                        )
                    }
                )
            }
        }
    }
    
    # Check for load rebalancing needs
    if ($null -ne $AnalyticsData.CurrentMetrics) {
        $loadVariance = $AnalyticsData.CurrentMetrics.LoadVariance
        if ($null -ne $loadVariance -and $loadVariance -gt 0.3) {
            $recommendations += @{
                Type = "Rebalance"
                Priority = 2
                Parameters = @{
                    Algorithm = "Adaptive"
                    Reason = "High load variance detected: $([math]::Round($loadVariance * 100, 1))%"
                }
                Conditions = @(
                    @{ Type = "MetricThreshold"; Metric = "LoadVariance"; Operator = "GreaterThan"; Value = 0.3 }
                )
            }
        }
    }
    
    # Sort by priority
    return $recommendations | Sort-Object Priority
}

function Execute-Decision {
    param($Decision, $Context)
    
    $decisionType = $DecisionTypes[$Decision.Type]
    if ($null -eq $decisionType) {
        Write-DecisionLog "Unknown decision type: $($Decision.Type)" "ERROR"
        return $false
    }
    
    try {
        Write-DecisionLog "Executing decision: $($decisionType.Description)" "ACTION"
        $result = & $decisionType.Action $Decision $Context
        return $result
    }
    catch {
        Write-DecisionLog "Decision execution failed: $_" "ERROR"
        return $false
    }
}

function Show-DecisionStatus {
    $state = Get-DecisionState
    $riskConfig = $RiskProfiles[$RiskProfile]
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║         RawrXD Autonomous Decision Engine Status              ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Risk Profile:     $RiskProfile" -ForegroundColor Cyan
    Write-Host "║ Confidence Threshold: $($riskConfig.ConfidenceThreshold * 100)%" -ForegroundColor Cyan
    Write-Host "║ Max Actions/Hour:    $($riskConfig.MaxActionsPerHour)" -ForegroundColor Cyan
    Write-Host "║ Require Approval:     $($riskConfig.RequireHumanApproval)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Total Decisions:      $($state.TotalDecisions)" -ForegroundColor Cyan
    Write-Host "║ Successful:           $($state.SuccessfulDecisions)" -ForegroundColor Green
    Write-Host "║ Failed:               $($state.FailedDecisions)" -ForegroundColor Red
    Write-Host "║ Pending Approvals:    $($state.PendingApprovals.Count)" -ForegroundColor Yellow
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Recent Decisions (Last 5):" -ForegroundColor Cyan
    
    $recentDecisions = $state.DecisionHistory | Select-Object -Last 5
    if ($recentDecisions.Count -eq 0) {
        Write-Host "║   No decisions recorded yet" -ForegroundColor Gray
    }
    else {
        foreach ($dec in $recentDecisions) {
            $statusColor = if ($dec.Success) { "Green" } else { "Red" }
            Write-Host "║   [$($dec.Timestamp)] $($dec.Type) - Success: $($dec.Success)" -ForegroundColor $statusColor
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

function Run-DecisionCycle {
    $state = Get-DecisionState
    $riskConfig = $RiskProfiles[$RiskProfile]
    
    # Check cooldown
    if ($state.LastDecisionTime) {
        $lastDecision = [DateTime]::Parse($state.LastDecisionTime)
        $cooldown = New-TimeSpan -Minutes $riskConfig.ActionCooldownMinutes
        if ((Get-Date) - $lastDecision -lt $cooldown) {
            $remaining = $cooldown - ((Get-Date) - $lastDecision)
            Write-DecisionLog "In cooldown period. Next decision in $([math]::Round($remaining.TotalSeconds))s" "WARN"
            return
        }
    }
    
    # Check hourly limit
    $hourAgo = (Get-Date).AddHours(-1)
    $recentDecisions = $state.DecisionsLastHour | Where-Object { 
        [DateTime]::Parse($_) -gt $hourAgo 
    }
    if ($recentDecisions.Count -ge $riskConfig.MaxActionsPerHour) {
        Write-DecisionLog "Hourly action limit reached ($($riskConfig.MaxActionsPerHour)). Waiting..." "WARN"
        return
    }
    
    # Gather analytics data
    Write-DecisionLog "Gathering analytics data..."
    $analyticsData = Get-AnalyticsData
    
    # Generate recommendations
    Write-DecisionLog "Generating decision recommendations..."
    $recommendations = Generate-DecisionRecommendations -AnalyticsData $analyticsData -RiskConfig $riskConfig
    
    if ($recommendations.Count -eq 0) {
        Write-DecisionLog "No action recommendations at this time"
        return
    }
    
    Write-DecisionLog "Found $($recommendations.Count) recommendation(s)"
    
    # Evaluate each recommendation
    foreach ($rec in $recommendations) {
        # Check conditions
        $conditionsMet = $true
        foreach ($condition in $rec.Conditions) {
            if (-not (Evaluate-DecisionCondition -Condition $condition -AnalyticsData $analyticsData)) {
                $conditionsMet = $false
                break
            }
        }
        
        if (-not $conditionsMet) {
            Write-DecisionLog "Conditions not met for $($rec.Type), skipping"
            continue
        }
        
        # Calculate confidence
        $confidence = Calculate-DecisionConfidence -Decision $rec -AnalyticsData $analyticsData
        Write-DecisionLog "Decision confidence for $($rec.Type): $([math]::Round($confidence * 100, 1))%"
        
        # Check confidence threshold
        if ($confidence -lt $riskConfig.ConfidenceThreshold) {
            Write-DecisionLog "Confidence below threshold ($($riskConfig.ConfidenceThreshold * 100)%), skipping"
            continue
        }
        
        # Create decision record
        $decision = @{
            Id = [Guid]::NewGuid().ToString()
            Type = $rec.Type
            Parameters = $rec.Parameters
            Confidence = $confidence
            RiskProfile = $RiskProfile
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            RequiresApproval = $riskConfig.RequireHumanApproval
            Status = if ($riskConfig.RequireHumanApproval) { "PendingApproval" } else { "Executing" }
        }
        
        if ($riskConfig.RequireHumanApproval) {
            Write-DecisionLog "Decision requires human approval: $($rec.Type)" "WARN"
            $state.PendingApprovals += $decision
            Save-DecisionState -State $state
            continue
        }
        
        # Execute decision
        $context = @{
            AnalyticsData = $analyticsData
            RiskConfig = $riskConfig
            DryRun = $DryRun
        }
        
        $success = Execute-Decision -Decision $decision -Context $context
        
        # Update state
        $state.LastDecisionTime = $decision.Timestamp
        $state.DecisionsLastHour += $decision.Timestamp
        $state.TotalDecisions++
        
        if ($success) {
            $state.SuccessfulDecisions++
            $decision.Status = "Completed"
            Write-DecisionLog "Decision executed successfully: $($rec.Type)" "ACTION"
        }
        else {
            $state.FailedDecisions++
            $decision.Status = "Failed"
            Write-DecisionLog "Decision failed: $($rec.Type)" "ERROR"
        }
        
        $state.DecisionHistory += @{
            Type = $decision.Type
            Confidence = $decision.Confidence
            Success = $success
            Timestamp = $decision.Timestamp
        }
        
        # Keep only last 100 decisions in history
        if ($state.DecisionHistory.Count -gt 100) {
            $state.DecisionHistory = $state.DecisionHistory | Select-Object -Last 100
        }
        
        Save-DecisionState -State $state
        
        # Only execute one decision per cycle
        break
    }
}

# Main execution
if ($ShowStatus) {
    Show-DecisionStatus
    exit 0
}

Write-DecisionLog "RawrXD Autonomous Decision Engine Started"
Write-DecisionLog "Risk Profile: $RiskProfile"
Write-DecisionLog "Decision Interval: $DecisionIntervalSeconds seconds"
Write-DecisionLog "Dry Run: $DryRun"

if ($Daemon) {
    Write-DecisionLog "Running in daemon mode..."
    while ($true) {
        Run-DecisionCycle
        Start-Sleep -Seconds $DecisionIntervalSeconds
    }
}
else {
    Write-DecisionLog "Running single decision cycle..."
    Run-DecisionCycle
    Write-DecisionLog "Decision cycle complete"
}
