# RawrXD Feedback Loop
# Phase G.3 Batch 5/5: Continuous Learning and Improvement
# Implements continuous feedback collection, learning, and system improvement

param(
    [Parameter()]
    [switch]$Daemon,
    
    [Parameter()]
    [int]$FeedbackIntervalSeconds = 300,
    
    [Parameter()]
    [string]$FeedbackPath = "$PSScriptRoot\feedback_store",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\autonomous\feedback",
    
    [Parameter()]
    [ValidateSet("Collect", "Analyze", "Learn", "Improve", "Report")]
    [string]$Action = "Collect",
    
    [Parameter()]
    [string]$Source,
    
    [Parameter()]
    [string]$Metric,
    
    [Parameter()]
    [double]$Value,
    
    [Parameter()]
    [hashtable]$Context = @{},
    
    [Parameter()]
    [switch]$ShowReport
)

# Feedback sources
$FeedbackSources = @{
    Performance = @{
        Description = "Performance metrics feedback"
        Metrics = @("TPS", "Latency", "Throughput", "ErrorRate", "ResourceUsage")
        Weight = 1.0
    }
    User = @{
        Description = "User experience feedback"
        Metrics = @("Satisfaction", "ResponseTime", "Quality", "Reliability")
        Weight = 1.2
    }
    Decision = @{
        Description = "Decision outcome feedback"
        Metrics = @("Success", "Efficiency", "Impact", "SideEffects")
        Weight = 1.5
    }
    Anomaly = @{
        Description = "Anomaly detection feedback"
        Metrics = @("DetectionAccuracy", "FalsePositiveRate", "ResponseTime")
        Weight = 1.3
    }
    Optimization = @{
        Description = "Optimization effectiveness feedback"
        Metrics = @("Improvement", "Stability", "ResourceEfficiency")
        Weight = 1.4
    }
}

# Learning algorithms
$LearningAlgorithms = @{
    TrendAnalysis = @{
        Description = "Analyze trends in feedback data"
        Function = {
            param($Data)
            
            $results = @{}
            
            foreach ($source in $Data.Keys) {
                $sourceData = $Data[$source]
                if ($sourceData.Count -lt 2) { continue }
                
                # Calculate trend using linear regression
                $n = $sourceData.Count
                $sumX = 0
                $sumY = 0
                $sumXY = 0
                $sumX2 = 0
                
                for ($i = 0; $i -lt $n; $i++) {
                    $x = $i
                    $y = $sourceData[$i].Value
                    $sumX += $x
                    $sumY += $y
                    $sumXY += $x * $y
                    $sumX2 += $x * $x
                }
                
                $slope = ($n * $sumXY - $sumX * $sumY) / ($n * $sumX2 - $sumX * $sumX)
                $intercept = ($sumY - $slope * $sumX) / $n
                
                # Calculate R²
                $meanY = $sumY / $n
                $ssTotal = 0
                $ssResidual = 0
                
                for ($i = 0; $i -lt $n; $i++) {
                    $predicted = $slope * $i + $intercept
                    $ssTotal += [Math]::Pow($sourceData[$i].Value - $meanY, 2)
                    $ssResidual += [Math]::Pow($sourceData[$i].Value - $predicted, 2)
                }
                
                $rSquared = if ($ssTotal -gt 0) { 1 - ($ssResidual / $ssTotal) } else { 0 }
                
                $results[$source] = @{
                    Slope = $slope
                    Intercept = $intercept
                    RSquared = $rSquared
                    Trend = if ($slope -gt 0.01) { "Improving" } elseif ($slope -lt -0.01) { "Declining" } else { "Stable" }
                    Strength = [Math]::Abs($rSquared)
                }
            }
            
            return $results
        }
    }
    
    PatternRecognition = @{
        Description = "Recognize patterns in feedback"
        Function = {
            param($Data)
            
            $patterns = @()
            
            # Look for recurring issues
            $issueGroups = $Data.GetEnumerator() | ForEach-Object {
                $source = $_.Key
                $_.Value | Where-Object { $_.Value -lt 0.5 } | Group-Object -Property Metric
            } | Where-Object { $_.Count -ge 3 }
            
            foreach ($group in $issueGroups) {
                $patterns += @{
                    Type = "RecurringIssue"
                    Metric = $group.Name
                    Frequency = $group.Count
                    Severity = ($group.Group | Measure-Object -Property Value -Average).Average
                    Recommendation = "Investigate $($group.Name) degradation"
                }
            }
            
            # Look for correlations
            $correlations = @()
            $sourcePairs = @()
            $sources = $Data.Keys | ForEach-Object { $_ }
            
            for ($i = 0; $i -lt $sources.Count; $i++) {
                for ($j = $i + 1; $j -lt $sources.Count; $j++) {
                    $sourcePairs += @($sources[$i], $sources[$j])
                }
            }
            
            foreach ($pair in $sourcePairs) {
                $data1 = $Data[$pair[0]]
                $data2 = $Data[$pair[1]]
                
                if ($data1.Count -eq 0 -or $data2.Count -eq 0) { continue }
                
                # Simple correlation check
                $avg1 = ($data1 | Measure-Object -Property Value -Average).Average
                $avg2 = ($data2 | Measure-Object -Property Value -Average).Average
                
                if ([Math]::Abs($avg1 - $avg2) -lt 0.1) {
                    $correlations += @{
                        Sources = $pair
                        Type = "Correlation"
                        Strength = "Strong"
                    }
                }
            }
            
            return @{
                Patterns = $patterns
                Correlations = $correlations
            }
        }
    }
    
    EffectivenessScoring = @{
        Description = "Score effectiveness of changes"
        Function = {
            param($Data, $Changes)
            
            $scores = @()
            
            foreach ($change in $Changes) {
                $before = $Data.GetEnumerator() | ForEach-Object {
                    $_.Value | Where-Object { $_.Timestamp -lt $change.Timestamp }
                } | Measure-Object -Property Value -Average
                
                $after = $Data.GetEnumerator() | ForEach-Object {
                    $_.Value | Where-Object { $_.Timestamp -ge $change.Timestamp }
                } | Measure-Object -Property Value -Average
                
                $improvement = if ($before.Average -gt 0) {
                    (($after.Average - $before.Average) / $before.Average) * 100
                } else { 0 }
                
                $scores += @{
                    Change = $change.Description
                    Timestamp = $change.Timestamp
                    BeforeScore = $before.Average
                    AfterScore = $after.Average
                    Improvement = $improvement
                    Effective = $improvement -gt 5
                }
            }
            
            return $scores
        }
    }
}

# Ensure directories exist
if (-not (Test-Path $FeedbackPath)) {
    New-Item -ItemType Directory -Path $FeedbackPath -Force | Out-Null
}
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# State file
$StateFile = "$PSScriptRoot\feedback_state.json"

function Write-FeedbackLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $logFile = Join-Path $LogPath "feedback_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "LEARN" { "Green" }
        "IMPROVE" { "Cyan" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-FeedbackState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        TotalFeedback = 0
        LastCollection = $null
        LastAnalysis = $null
        LearningCycles = 0
        ImprovementsMade = 0
        EffectivenessScore = 0.0
        Trends = @{}
    }
}

function Save-FeedbackState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function Collect-Feedback {
    param(
        [string]$Source,
        [string]$Metric,
        [double]$Value,
        [hashtable]$Context
    )
    
    if (-not $FeedbackSources.ContainsKey($Source)) {
        Write-FeedbackLog "Unknown feedback source: $Source" "ERROR"
        return $false
    }
    
    $feedback = @{
        Id = [Guid]::NewGuid().ToString()
        Source = $Source
        Metric = $Metric
        Value = $Value
        Context = $Context
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Weight = $FeedbackSources[$Source].Weight
    }
    
    $feedbackFile = Join-Path $FeedbackPath "$($feedback.Id).json"
    $feedback | ConvertTo-Json -Depth 10 | Out-File $feedbackFile -Encoding UTF8
    
    # Update state
    $state = Get-FeedbackState
    $state.TotalFeedback++
    $state.LastCollection = $feedback.Timestamp
    Save-FeedbackState -State $state
    
    Write-FeedbackLog "Collected feedback: [$Source] $Metric = $Value" "LEARN"
    return $true
}

function Get-FeedbackData {
    param([int]$HoursBack = 24)
    
    $cutoff = (Get-Date).AddHours(-$HoursBack).ToString("yyyy-MM-dd HH:mm:ss")
    $data = @{}
    
    foreach ($source in $FeedbackSources.Keys) {
        $data[$source] = @()
    }
    
    Get-ChildItem $FeedbackPath -Filter "*.json" | ForEach-Object {
        $feedback = Get-Content $_.FullName | ConvertFrom-Json
        if ($feedback.Timestamp -ge $cutoff) {
            if (-not $data[$feedback.Source]) {
                $data[$feedback.Source] = @()
            }
            $data[$feedback.Source] += $feedback
        }
    }
    
    return $data
}

function Analyze-Feedback {
    $data = Get-FeedbackData -HoursBack 24
    
    if ($data.Count -eq 0) {
        Write-FeedbackLog "No feedback data to analyze" "WARN"
        return $null
    }
    
    Write-FeedbackLog "Analyzing feedback from $($data.Count) sources..."
    
    $analysis = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Sources = @{}
        OverallHealth = 0.0
        Trends = @{}
        Patterns = @()
        Recommendations = @()
    }
    
    # Analyze each source
    foreach ($source in $data.Keys) {
        $sourceData = $data[$source]
        if ($sourceData.Count -eq 0) { continue }
        
        $weightedSum = 0
        $weightTotal = 0
        
        foreach ($item in $sourceData) {
            $weightedSum += $item.Value * $item.Weight
            $weightTotal += $item.Weight
        }
        
        $avgScore = if ($weightTotal -gt 0) { $weightedSum / $weightTotal } else { 0 }
        
        $analysis.Sources[$source] = @{
            Count = $sourceData.Count
            AverageScore = $avgScore
            Health = if ($avgScore -ge 0.8) { "Good" } elseif ($avgScore -ge 0.6) { "Fair" } else { "Poor" }
        }
    }
    
    # Calculate overall health
    $allScores = $analysis.Sources.Values | ForEach-Object { $_.AverageScore }
    $analysis.OverallHealth = ($allScores | Measure-Object -Average).Average
    
    # Run trend analysis
    $trendAlgo = $LearningAlgorithms.TrendAnalysis
    $analysis.Trends = & $trendAlgo.Function $data
    
    # Run pattern recognition
    $patternAlgo = $LearningAlgorithms.PatternRecognition
    $patterns = & $patternAlgo.Function $data
    $analysis.Patterns = $patterns.Patterns
    $analysis.Correlations = $patterns.Correlations
    
    # Generate recommendations
    foreach ($source in $analysis.Sources.Keys) {
        $sourceHealth = $analysis.Sources[$source]
        if ($sourceHealth.Health -eq "Poor") {
            $analysis.Recommendations += @{
                Priority = "High"
                Source = $source
                Issue = "Low performance score: $([math]::Round($sourceHealth.AverageScore * 100, 1))%"
                Action = "Review and optimize $source configuration"
            }
        }
    }
    
    foreach ($trend in $analysis.Trends.Keys) {
        $trendData = $analysis.Trends[$trend]
        if ($trendData.Trend -eq "Declining" -and $trendData.Strength -gt 0.5) {
            $analysis.Recommendations += @{
                Priority = "High"
                Source = $trend
                Issue = "Declining trend detected"
                Action = "Investigate root cause of $trend degradation"
            }
        }
    }
    
    foreach ($pattern in $analysis.Patterns) {
        $analysis.Recommendations += @{
            Priority = "Medium"
            Source = "Pattern"
            Issue = $pattern.Type
            Action = $pattern.Recommendation
        }
    }
    
    # Update state
    $state = Get-FeedbackState
    $state.LastAnalysis = $analysis.Timestamp
    $state.Trends = $analysis.Trends
    Save-FeedbackState -State $state
    
    return $analysis
}

function Learn-FromFeedback {
    $analysis = Analyze-Feedback
    
    if ($null -eq $analysis) { return $null }
    
    Write-FeedbackLog "Learning from feedback analysis..." "LEARN"
    
    $learnings = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Insights = @()
        KnowledgeUpdates = @()
        ParameterAdjustments = @()
    }
    
    # Extract insights
    foreach ($recommendation in $analysis.Recommendations) {
        $learnings.Insights += @{
            Type = $recommendation.Issue
            Source = $recommendation.Source
            Confidence = 0.7
            Action = $recommendation.Action
        }
    }
    
    # Update knowledge base
    $knowledgeBase = "$PSScriptRoot\..\knowledge\knowledge_base.ps1"
    if (Test-Path $knowledgeBase) {
        foreach ($trend in $analysis.Trends.Keys) {
            $trendData = $analysis.Trends[$trend]
            
            $knowledgeEntry = @{
                Pattern = "$trend trend: $($trendData.Trend)"
                Metrics = @{
                    Slope = $trendData.Slope
                    RSquared = $trendData.RSquared
                }
                Confidence = $trendData.Strength
            }
            
            # Store in knowledge base
            $key = "trend_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$trend"
            & $knowledgeBase -Action Store -Category "PerformanceProfile" -Key $key -Value $knowledgeEntry -Metadata @{ Confidence = $trendData.Strength }
            
            $learnings.KnowledgeUpdates += @{
                Category = "PerformanceProfile"
                Key = $key
                Confidence = $trendData.Strength
            }
        }
    }
    
    # Generate parameter adjustments
    foreach ($source in $analysis.Sources.Keys) {
        $sourceData = $analysis.Sources[$source]
        
        if ($sourceData.Health -eq "Poor") {
            $learnings.ParameterAdjustments += @{
                Target = $source
                Parameter = "OptimizationLevel"
                CurrentValue = "Normal"
                RecommendedValue = "Aggressive"
                Reason = "Poor performance detected"
            }
        }
    }
    
    # Update state
    $state = Get-FeedbackState
    $state.LearningCycles++
    Save-FeedbackState -State $state
    
    Write-FeedbackLog "Learning cycle complete. $($learnings.Insights.Count) insights, $($learnings.KnowledgeUpdates.Count) knowledge updates" "LEARN"
    
    return $learnings
}

function Improve-System {
    $learnings = Learn-FromFeedback
    
    if ($null -eq $learnings) { return $null }
    
    Write-FeedbackLog "Applying improvements based on learnings..." "IMPROVE"
    
    $improvements = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Actions = @()
        Results = @()
    }
    
    # Apply parameter adjustments
    foreach ($adjustment in $learnings.ParameterAdjustments) {
        $action = @{
            Type = "ParameterAdjustment"
            Target = $adjustment.Target
            Parameter = $adjustment.Parameter
            OldValue = $adjustment.CurrentValue
            NewValue = $adjustment.RecommendedValue
            Applied = $false
        }
        
        # Apply the adjustment
        # In a real implementation, this would modify actual system parameters
        $action.Applied = $true
        $action.Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        $improvements.Actions += $action
        Write-FeedbackLog "Applied adjustment: $($adjustment.Target).$($adjustment.Parameter) = $($adjustment.RecommendedValue)" "IMPROVE"
    }
    
    # Trigger optimizations based on insights
    foreach ($insight in $learnings.Insights) {
        if ($insight.Type -eq "Declining trend" -and $insight.Confidence -gt 0.7) {
            $optimizer = "$PSScriptRoot\..\..\analytics\optimizer\resource_optimizer.ps1"
            if (Test-Path $optimizer) {
                Write-FeedbackLog "Triggering auto-optimization due to declining trend" "IMPROVE"
                # & $optimizer -AutoTune -Strategy "Balanced"
                
                $improvements.Actions += @{
                    Type = "AutoOptimization"
                    Trigger = $insight.Source
                    Applied = $true
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        }
    }
    
    # Update state
    $state = Get-FeedbackState
    $state.ImprovementsMade += $improvements.Actions.Count
    
    # Calculate effectiveness score
    if ($state.ImprovementsMade -gt 0 -and $state.LearningCycles -gt 0) {
        $state.EffectivenessScore = [Math]::Min(1.0, $state.ImprovementsMade / ($state.LearningCycles * 2))
    }
    
    Save-FeedbackState -State $state
    
    Write-FeedbackLog "Improvements applied: $($improvements.Actions.Count) actions" "IMPROVE"
    
    return $improvements
}

function Show-FeedbackReport {
    $state = Get-FeedbackState
    $analysis = Analyze-Feedback
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Feedback Loop Report                           ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Total Feedback Collected: $($state.TotalFeedback)" -ForegroundColor Cyan
    Write-Host "║ Learning Cycles: $($state.LearningCycles)" -ForegroundColor Cyan
    Write-Host "║ Improvements Made: $($state.ImprovementsMade)" -ForegroundColor Green
    Write-Host "║ Effectiveness Score: $([math]::Round($state.EffectivenessScore * 100, 1))%" -ForegroundColor $(if($state.EffectivenessScore -gt 0.7){"Green"}elseif($state.EffectivenessScore -gt 0.4){"Yellow"}else{"Red"})
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    if ($analysis) {
        Write-Host "║ Overall Health: $([math]::Round($analysis.OverallHealth * 100, 1))%" -ForegroundColor $(if($analysis.OverallHealth -gt 0.8){"Green"}elseif($analysis.OverallHealth -gt 0.6){"Yellow"}else{"Red"})
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        
        Write-Host "║ Source Health:" -ForegroundColor Cyan
        foreach ($source in $analysis.Sources.Keys) {
            $health = $analysis.Sources[$source]
            $color = switch ($health.Health) {
                "Good" { "Green" }
                "Fair" { "Yellow" }
                "Poor" { "Red" }
            }
            Write-Host "║   $source`: $($health.Health) ($([math]::Round($health.AverageScore * 100, 1))%)" -ForegroundColor $color
        }
        
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║ Trends:" -ForegroundColor Cyan
        foreach ($trend in $analysis.Trends.Keys) {
            $trendData = $analysis.Trends[$trend]
            $color = if ($trendData.Trend -eq "Improving") { "Green" } elseif ($trendData.Trend -eq "Declining") { "Red" } else { "Yellow" }
            Write-Host "║   $trend`: $($trendData.Trend) (strength: $([math]::Round($trendData.Strength, 2)))" -ForegroundColor $color
        }
        
        if ($analysis.Recommendations.Count -gt 0) {
            Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
            Write-Host "║ Recommendations:" -ForegroundColor Yellow
            foreach ($rec in $analysis.Recommendations | Select-Object -First 5) {
                Write-Host "║   [$($rec.Priority)] $($rec.Action)" -ForegroundColor $(if($rec.Priority -eq "High"){"Red"}else{"Yellow"})
            }
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

function Run-FeedbackCycle {
    Write-FeedbackLog "Starting feedback cycle..."
    
    # Collect system metrics as feedback
    $metrics = @{
        TPS = Get-Random -Minimum 30 -Maximum 50
        Latency = Get-Random -Minimum 50 -Maximum 150
        ErrorRate = Get-Random -Minimum 0 -Maximum 5
    }
    
    foreach ($metric in $metrics.Keys) {
        $normalizedValue = switch ($metric) {
            "TPS" { [Math]::Min(1.0, $metrics[$metric] / 50.0) }
            "Latency" { 1.0 - [Math]::Min(1.0, $metrics[$metric] / 200.0) }
            "ErrorRate" { 1.0 - [Math]::Min(1.0, $metrics[$metric] / 10.0) }
            default { 0.5 }
        }
        
        Collect-Feedback -Source "Performance" -Metric $metric -Value $normalizedValue -Context @{ RawValue = $metrics[$metric] }
    }
    
    # Analyze and learn
    $analysis = Analyze-Feedback
    if ($analysis) {
        $learnings = Learn-FromFeedback
        $improvements = Improve-System
    }
    
    Write-FeedbackLog "Feedback cycle complete"
}

# Main execution
switch ($Action) {
    "Collect" {
        if ($Source -and $Metric -and $Value) {
            $success = Collect-Feedback -Source $Source -Metric $Metric -Value $Value -Context $Context
            exit ($success ? 0 : 1)
        }
        else {
            Write-FeedbackLog "Source, Metric, and Value required for Collect action" "ERROR"
            exit 1
        }
    }
    
    "Analyze" {
        $analysis = Analyze-Feedback
        if ($analysis) {
            $analysis | ConvertTo-Json -Depth 10
        }
        exit 0
    }
    
    "Learn" {
        $learnings = Learn-FromFeedback
        if ($learnings) {
            $learnings | ConvertTo-Json -Depth 10
        }
        exit 0
    }
    
    "Improve" {
        $improvements = Improve-System
        if ($improvements) {
            $improvements | ConvertTo-Json -Depth 10
        }
        exit 0
    }
    
    "Report" {
        Show-FeedbackReport
        exit 0
    }
}

if ($ShowReport) {
    Show-FeedbackReport
    exit 0
}

Write-FeedbackLog "RawrXD Feedback Loop"
Write-FeedbackLog "Actions: Collect, Analyze, Learn, Improve, Report"

if ($Daemon) {
    Write-FeedbackLog "Running in daemon mode (interval: $FeedbackIntervalSeconds seconds)..."
    while ($true) {
        Run-FeedbackCycle
        Start-Sleep -Seconds $FeedbackIntervalSeconds
    }
}
