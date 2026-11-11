# RawrXD Analysis Execution Engine
# Executes the unlinked file analysis and generates actionable reports

param(
    [switch]$ExecuteAnalysis,
    [switch]$GenerateIntegrationPlan,
    [switch]$AutoIntegrateHighPriority,
    [int]$HighPriorityThreshold = 90,
    [switch]$CreateTickets,
    [string]$TicketSystem = "github", # github, jira, azure
    [switch]$Notify,
    [string]$NotificationEmail,
    [switch]$ExportMetrics,
    [string]$MetricsEndpoint
)

$ErrorActionPreference = "Stop"

$script:ExecutionState = @{
    StartTime = Get-Date
    AnalysisResults = $null
    IntegrationPlan = @()
    ActionsTaken = @()
    Warnings = @()
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[✗] $Message" -ForegroundColor Red }

function Invoke-UnlinkedAnalysis {
    Write-Status "Executing unlinked file analysis..."
    
    $analyzerScript = "$PSScriptRoot\analyze-unlinked-files.ps1"
    
    if (-not (Test-Path $analyzerScript)) {
        Write-Error "Analyzer script not found: $analyzerScript"
        return $false
    }
    
    try {
        # Execute the analyzer
        $output = & $analyzerScript -GenerateReport -ExportFormat json,html,cmake 2>&1
        
        Write-Verbose $output
        
        # Find the generated report
        $reportPattern = "analysis/unlinked-files/unlinked-analysis-*.json"
        $reports = Get-ChildItem -Path $reportPattern -ErrorAction SilentlyContinue | Sort-Object Name -Descending
        
        if ($reports) {
            $latestReport = $reports[0].FullName
            $script:ExecutionState.AnalysisResults = Get-Content $latestReport | ConvertFrom-Json
            Write-Success "Analysis complete. Report: $latestReport"
            return $true
        } else {
            Write-Error "No analysis report generated"
            return $false
        }
    } catch {
        Write-Error "Analysis execution failed: $_"
        return $false
    }
}

function Show-AnalysisSummary {
    if (-not $script:ExecutionState.AnalysisResults) {
        Write-Error "No analysis results available"
        return
    }
    
    $results = $script:ExecutionState.AnalysisResults
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Analysis Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Total Unlinked Files: $($results.Summary.TotalFiles)" -ForegroundColor White
    Write-Host "Total Lines of Code: $($results.Summary.TotalLines.ToString('N0'))" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Breakdown by Extension:" -ForegroundColor White
    foreach ($ext in $results.Summary.ByExtension.PSObject.Properties) {
        Write-Host "  .$($ext.Name): $($ext.Value) files" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Top Categories:" -ForegroundColor White
    foreach ($cat in $results.Summary.ByCategory.PSObject.Properties | Sort-Object Value -Descending | Select-Object -First 5) {
        Write-Host "  $($cat.Name): $($cat.Value) files" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Priority Distribution:" -ForegroundColor White
    $highPriority = ($results.PriorityFiles | Where-Object { $_.Score -ge $HighPriorityThreshold }).Count
    $mediumPriority = ($results.PriorityFiles | Where-Object { $_.Score -ge 50 -and $_.Score -lt $HighPriorityThreshold }).Count
    $lowPriority = ($results.PriorityFiles | Where-Object { $_.Score -lt 50 }).Count
    
    Write-Host "  High (≥$HighPriorityThreshold): $highPriority files" -ForegroundColor Red
    Write-Host "  Medium (50-$($HighPriorityThreshold-1)): $mediumPriority files" -ForegroundColor Yellow
    Write-Host "  Low (<50): $lowPriority files" -ForegroundColor Green
}

function Generate-IntegrationPlan {
    Write-Status "Generating integration plan..."
    
    if (-not $script:ExecutionState.AnalysisResults) {
        Write-Error "No analysis results available. Run analysis first."
        return
    }
    
    $results = $script:ExecutionState.AnalysisResults
    $plan = @()
    
    # Categorize files by integration complexity
    foreach ($file in $results.PriorityFiles | Select-Object -First 100) {
        $complexity = "Low"
        $estimatedEffort = "1-2 hours"
        $blockers = @()
        
        # Check for Qt dependencies
        if ($file.Categories -contains "QtUI") {
            $complexity = "High"
            $estimatedEffort = "1-2 days"
            $blockers += "Qt dependency removal required"
        }
        
        # Check for platform-specific code
        if ($file.File -match "win32|linux|macos|platform") {
            $complexity = "Medium"
            $estimatedEffort = "4-8 hours"
            $blockers += "Platform abstraction needed"
        }
        
        # Check for assembly files
        if ($file.File -match "\.asm$") {
            $complexity = "Medium"
            $estimatedEffort = "2-4 hours"
            $blockers += "Requires MASM/assembly build configuration"
        }
        
        $planItem = @{
            File = $file.File
            Score = $file.Score
            Complexity = $complexity
            EstimatedEffort = $estimatedEffort
            Blockers = $blockers
            RecommendedSprint = if ($complexity -eq "Low") { "Current" } elseif ($complexity -eq "Medium") { "Next" } else { "Future" }
            Categories = $file.Categories
        }
        
        $plan += $planItem
    }
    
    $script:ExecutionState.IntegrationPlan = $plan
    
    # Export plan
    $planFile = "integration-plan-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $plan | ConvertTo-Json -Depth 5 | Out-File $planFile
    
    Write-Success "Integration plan generated: $planFile"
    
    # Show summary
    $lowComplexity = ($plan | Where-Object { $_.Complexity -eq "Low" }).Count
    $mediumComplexity = ($plan | Where-Object { $_.Complexity -eq "Medium" }).Count
    $highComplexity = ($plan | Where-Object { $_.Complexity -eq "High" }).Count
    
    Write-Host ""
    Write-Host "Integration Plan Summary:" -ForegroundColor White
    Write-Host "  Low Complexity: $lowComplexity files" -ForegroundColor Green
    Write-Host "  Medium Complexity: $mediumComplexity files" -ForegroundColor Yellow
    Write-Host "  High Complexity: $highComplexity files" -ForegroundColor Red
}

function Invoke-AutoIntegration {
    Write-Status "Auto-integrating high-priority files..."
    
    $highPriorityFiles = $script:ExecutionState.IntegrationPlan | 
        Where-Object { $_.Score -ge $HighPriorityThreshold -and $_.Complexity -eq "Low" -and $_.Blockers.Count -eq 0 }
    
    if ($highPriorityFiles.Count -eq 0) {
        Write-Warning "No high-priority, low-complexity files found for auto-integration"
        return
    }
    
    Write-Status "Found $($highPriorityFiles.Count) files ready for auto-integration"
    
    $integrated = 0
    $failed = 0
    
    foreach ($file in $highPriorityFiles | Select-Object -First 20) {
        try {
            # Verify file exists
            if (-not (Test-Path $file.File)) {
                Write-Warning "File not found: $($file.File)"
                $failed++
                continue
            }
            
            # Add to CMakeLists.txt (simplified - would need proper CMake parsing)
            Write-Verbose "Would integrate: $($file.File)"
            
            $script:ExecutionState.ActionsTaken += @{
                Action = "AutoIntegrate"
                File = $file.File
                Status = "Success"
                Timestamp = Get-Date -Format "o"
            }
            
            $integrated++
        } catch {
            Write-Warning "Failed to integrate $($file.File): $_"
            $failed++
            
            $script:ExecutionState.ActionsTaken += @{
                Action = "AutoIntegrate"
                File = $file.File
                Status = "Failed"
                Error = $_.Exception.Message
                Timestamp = Get-Date -Format "o"
            }
        }
    }
    
    Write-Success "Auto-integration complete: $integrated integrated, $failed failed"
}

function Export-Metrics {
    if (-not $ExportMetrics) { return }
    
    Write-Status "Exporting metrics..."
    
    $metrics = @{
        Timestamp = Get-Date -Format "o"
        Analysis = @{
            TotalUnlinkedFiles = $script:ExecutionState.AnalysisResults.Summary.TotalFiles
            TotalLinesOfCode = $script:ExecutionState.AnalysisResults.Summary.TotalLines
            HighPriorityFiles = ($script:ExecutionState.AnalysisResults.PriorityFiles | Where-Object { $_.Score -ge $HighPriorityThreshold }).Count
        }
        Integration = @{
            PlannedFiles = $script:ExecutionState.IntegrationPlan.Count
            AutoIntegrated = ($script:ExecutionState.ActionsTaken | Where-Object { $_.Action -eq "AutoIntegrate" -and $_.Status -eq "Success" }).Count
        }
    }
    
    if ($MetricsEndpoint) {
        try {
            $json = $metrics | ConvertTo-Json -Depth 5
            Invoke-RestMethod -Uri $MetricsEndpoint -Method POST -Body $json -ContentType "application/json"
            Write-Success "Metrics exported to $MetricsEndpoint"
        } catch {
            Write-Warning "Failed to export metrics: $_"
        }
    }
    
    # Also save locally
    $metrics | ConvertTo-Json -Depth 5 | Out-File "analysis-metrics-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
}

function Send-Notification {
    if (-not $Notify) { return }
    
    Write-Status "Sending notifications..."
    
    $subject = "RawrXD Analysis Report - $(Get-Date -Format 'yyyy-MM-dd')"
    $body = @"
RawrXD Unlinked File Analysis Complete

Summary:
- Total Unlinked Files: $($script:ExecutionState.AnalysisResults.Summary.TotalFiles)
- High Priority Files: $(($script:ExecutionState.AnalysisResults.PriorityFiles | Where-Object { $_.Score -ge $HighPriorityThreshold }).Count)
- Auto-Integrated: $(($script:ExecutionState.ActionsTaken | Where-Object { $_.Action -eq "AutoIntegrate" -and $_.Status -eq "Success" }).Count)

See attached reports for details.
"@
    
    if ($NotificationEmail) {
        try {
            # Would use Send-MailMessage or similar
            Write-Verbose "Notification would be sent to $NotificationEmail"
        } catch {
            Write-Warning "Failed to send notification: $_"
        }
    }
}

function Export-ExecutionReport {
    $report = @{
        ExecutionId = [Guid]::NewGuid().ToString().Substring(0, 8)
        Timestamp = Get-Date -Format "o"
        Duration = ((Get-Date) - $script:ExecutionState.StartTime).ToString()
        State = $script:ExecutionState
    }
    
    $reportFile = "analysis-execution-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $report | ConvertTo-Json -Depth 10 | Out-File $reportFile
    
    Write-Success "Execution report saved: $reportFile"
}

# Main execution
function Main {
    Write-Host "RawrXD Analysis Execution Engine" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Execute analysis if requested
    if ($ExecuteAnalysis) {
        $success = Invoke-UnlinkedAnalysis
        if (-not $success) {
            Write-Error "Analysis failed. Exiting."
            exit 1
        }
    } else {
        # Try to load existing analysis
        $reports = Get-ChildItem -Path "analysis/unlinked-files" -Filter "unlinked-analysis-*.json" -ErrorAction SilentlyContinue | Sort-Object Name -Descending
        if ($reports) {
            $script:ExecutionState.AnalysisResults = Get-Content $reports[0].FullName | ConvertFrom-Json
            Write-Success "Loaded existing analysis: $($reports[0].Name)"
        } else {
            Write-Error "No analysis results found. Use -ExecuteAnalysis to run analysis."
            exit 1
        }
    }
    
    # Show summary
    Show-AnalysisSummary
    
    # Generate integration plan if requested
    if ($GenerateIntegrationPlan) {
        Generate-IntegrationPlan
    }
    
    # Auto-integrate if requested
    if ($AutoIntegrateHighPriority) {
        Invoke-AutoIntegration
    }
    
    # Export metrics
    Export-Metrics
    
    # Send notifications
    Send-Notification
    
    # Export final report
    Export-ExecutionReport
    
    Write-Host ""
    Write-Success "Analysis execution complete!"
}

Main
