# RawrXD Final Validation
# Phase I Batch 2/5: Complete System Validation
# Validates all components before release

param(
    [Parameter()]
    [ValidateSet("Full", "Quick", "Security", "Performance", "Integration", "ShowReport")]
    [string]$ValidationType = "Full",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\logs\validation",
    
    [Parameter()]
    [string]$ReportPath = "$PSScriptRoot\artifacts\validation_report.json",
    
    [Parameter()]
    [switch]$FailOnWarning
)

# Validation configuration
$ValidationConfig = @{
    MinTestPassRate = 0.95  # 95% tests must pass
    MaxSecurityScore = 70   # Minimum security grade C
    MinPerformanceTPS = 30  # Minimum tokens per second
    MaxLatencyMs = 100      # Maximum latency in milliseconds
    RequiredComponents = @(
        "governance\telemetry",
        "governance\monitoring",
        "governance\audit",
        "governance\healing",
        "analytics\prediction",
        "analytics\loadbalancer",
        "analytics\optimizer",
        "analytics\anomaly",
        "analytics\capacity",
        "autonomous\decision",
        "autonomous\policy",
        "autonomous\workflow",
        "autonomous\knowledge",
        "autonomous\feedback",
        "production\security",
        "production\performance",
        "production\docs",
        "production\testing",
        "production\deploy"
    )
}

# Ensure log directory exists
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# Validation results
$ValidationResults = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Type = $ValidationType
    Overall = "Pending"
    Score = 0
    Duration = 0
    Categories = @{}
    Issues = @()
}

function Write-ValidationLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $logFile = Join-Path $LogPath "validation_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "PASS"  { "Green" }
        "VALIDATE" { "Cyan" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Test-ComponentExistence {
    Write-ValidationLog "Checking component existence..." "VALIDATE"
    
    $results = @{
        Category = "Components"
        Passed = 0
        Failed = 0
        Total = $ValidationConfig.RequiredComponents.Count
        Details = @()
    }
    
    $basePath = "$PSScriptRoot\.."
    
    foreach ($component in $ValidationConfig.RequiredComponents) {
        $fullPath = Join-Path $basePath $component
        $exists = Test-Path $fullPath
        
        $results.Details += @{
            Component = $component
            Exists = $exists
            Path = $fullPath
        }
        
        if ($exists) {
            $results.Passed++
            Write-ValidationLog "✓ $component" "PASS"
        }
        else {
            $results.Failed++
            Write-ValidationLog "✗ $component missing" "ERROR"
            $ValidationResults.Issues += "Missing component: $component"
        }
    }
    
    $results.SuccessRate = if ($results.Total -gt 0) { $results.Passed / $results.Total } else { 0 }
    $results.Passed = $results.SuccessRate -ge 1.0
    
    return $results
}

function Test-SecurityValidation {
    Write-ValidationLog "Running security validation..." "VALIDATE"
    
    $results = @{
        Category = "Security"
        Passed = $false
        Score = 0
        Details = @{}
    }
    
    # Run security audit
    $securityScript = "$PSScriptRoot\..\production\security\security_hardening.ps1"
    if (Test-Path $securityScript) {
        try {
            $audit = & $securityScript -Action Audit 2>$null | ConvertFrom-Json
            $results.Score = $audit.Score
            $results.Details = $audit
            
            if ($audit.Score -ge $ValidationConfig.MaxSecurityScore) {
                $results.Passed = $true
                Write-ValidationLog "Security validation passed (Score: $($audit.Score), Grade: $($audit.Grade))" "PASS"
            }
            else {
                Write-ValidationLog "Security validation failed (Score: $($audit.Score), Grade: $($audit.Grade))" "ERROR"
                $ValidationResults.Issues += "Security score too low: $($audit.Score)/100 (Grade $($audit.Grade))"
            }
        }
        catch {
            Write-ValidationLog "Security audit failed: $_" "ERROR"
            $ValidationResults.Issues += "Security audit execution failed"
        }
    }
    else {
        Write-ValidationLog "Security hardening script not found" "WARN"
        $ValidationResults.Issues += "Security hardening script not found"
    }
    
    return $results
}

function Test-PerformanceValidation {
    Write-ValidationLog "Running performance validation..." "VALIDATE"
    
    $results = @{
        Category = "Performance"
        Passed = $false
        Metrics = @{}
    }
    
    # Run performance analysis
    $perfScript = "$PSScriptRoot\..\production\performance\performance_tuner.ps1"
    if (Test-Path $perfScript) {
        try {
            $analysis = & $perfScript -Action Analyze 2>$null | ConvertFrom-Json
            $results.Metrics = $analysis.CurrentMetrics
            
            # Check thresholds
            $cpuOk = $analysis.CurrentMetrics.CPUUsagePercent -lt 80
            $memoryOk = $analysis.CurrentMetrics.MemoryUsagePercent -lt 85
            
            if ($cpuOk -and $memoryOk) {
                $results.Passed = $true
                Write-ValidationLog "Performance validation passed (CPU: $($analysis.CurrentMetrics.CPUUsagePercent)%, Memory: $($analysis.CurrentMetrics.MemoryUsagePercent)%)" "PASS"
            }
            else {
                Write-ValidationLog "Performance validation failed" "ERROR"
                if (-not $cpuOk) { $ValidationResults.Issues += "CPU usage too high: $($analysis.CurrentMetrics.CPUUsagePercent)%" }
                if (-not $memoryOk) { $ValidationResults.Issues += "Memory usage too high: $($analysis.CurrentMetrics.MemoryUsagePercent)%" }
            }
        }
        catch {
            Write-ValidationLog "Performance analysis failed: $_" "ERROR"
            $ValidationResults.Issues += "Performance analysis execution failed"
        }
    }
    else {
        Write-ValidationLog "Performance tuner script not found" "WARN"
    }
    
    return $results
}

function Test-TestSuiteValidation {
    Write-ValidationLog "Running test suite validation..." "VALIDATE"
    
    $results = @{
        Category = "Tests"
        Passed = $false
        Total = 0
        Passed = 0
        Failed = 0
        PassRate = 0
    }
    
    $testScript = "$PSScriptRoot\..\production\testing\test_suite.ps1"
    if (Test-Path $testScript) {
        try {
            # Run tests and capture results
            & $testScript -TestType All 2>$null
            
            # Check for test results file
            $testResultsFile = Get-ChildItem "$PSScriptRoot\..\logs\testing\test_results_*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($testResultsFile) {
                $testResults = Get-Content $testResultsFile.FullName | ConvertFrom-Json
                $results.Total = $testResults.Total
                $results.Passed = $testResults.Passed
                $results.Failed = $testResults.Failed
                $results.PassRate = if ($testResults.Total -gt 0) { $testResults.Passed / $testResults.Total } else { 0 }
                
                if ($results.PassRate -ge $ValidationConfig.MinTestPassRate) {
                    $results.Passed = $true
                    Write-ValidationLog "Test suite validation passed ($([math]::Round($results.PassRate * 100, 1))% pass rate)" "PASS"
                }
                else {
                    Write-ValidationLog "Test suite validation failed ($([math]::Round($results.PassRate * 100, 1))% pass rate)" "ERROR"
                    $ValidationResults.Issues += "Test pass rate too low: $([math]::Round($results.PassRate * 100, 1))% (minimum $($ValidationConfig.MinTestPassRate * 100)%)"
                }
            }
            else {
                Write-ValidationLog "No test results found" "WARN"
                $ValidationResults.Issues += "No test results available"
            }
        }
        catch {
            Write-ValidationLog "Test suite execution failed: $_" "ERROR"
            $ValidationResults.Issues += "Test suite execution failed"
        }
    }
    else {
        Write-ValidationLog "Test suite script not found" "WARN"
        $ValidationResults.Issues += "Test suite script not found"
    }
    
    return $results
}

function Test-IntegrationValidation {
    Write-ValidationLog "Running integration validation..." "VALIDATE"
    
    $results = @{
        Category = "Integration"
        Passed = $false
        Tests = @()
    }
    
    # Test key integrations
    $integrations = @(
        @{ Name = "Governance Layer"; Path = "$PSScriptRoot\..\governance" },
        @{ Name = "Analytics Layer"; Path = "$PSScriptRoot\..\analytics" },
        @{ Name = "Autonomous Layer"; Path = "$PSScriptRoot\..\autonomous" },
        @{ Name = "Production Layer"; Path = "$PSScriptRoot\..\production" }
    )
    
    $allPassed = $true
    foreach ($integration in $integrations) {
        $exists = Test-Path $integration.Path
        $results.Tests += @{
            Name = $integration.Name
            Exists = $exists
        }
        
        if ($exists) {
            Write-ValidationLog "✓ $($integration.Name)" "PASS"
        }
        else {
            Write-ValidationLog "✗ $($integration.Name) missing" "ERROR"
            $allPassed = $false
            $ValidationResults.Issues += "Integration missing: $($integration.Name)"
        }
    }
    
    $results.Passed = $allPassed
    return $results
}

function Invoke-FullValidation {
    Write-ValidationLog "Starting full system validation..." "VALIDATE"
    
    $startTime = Get-Date
    
    # Run all validations
    $ValidationResults.Categories.Components = Test-ComponentExistence
    $ValidationResults.Categories.Security = Test-SecurityValidation
    $ValidationResults.Categories.Performance = Test-PerformanceValidation
    $ValidationResults.Categories.Tests = Test-TestSuiteValidation
    $ValidationResults.Categories.Integration = Test-IntegrationValidation
    
    # Calculate overall score
    $totalScore = 0
    $categoryCount = 0
    $allPassed = $true
    
    foreach ($category in $ValidationResults.Categories.Keys) {
        $catResults = $ValidationResults.Categories[$category]
        if ($catResults.Passed) {
            $totalScore += 100
        }
        elseif ($category -eq "Components" -and $catResults.SuccessRate) {
            $totalScore += ($catResults.SuccessRate * 100)
        }
        elseif ($category -eq "Security" -and $catResults.Score) {
            $totalScore += $catResults.Score
        }
        elseif ($category -eq "Tests" -and $catResults.PassRate) {
            $totalScore += ($catResults.PassRate * 100)
        }
        else {
            $totalScore += 0
            $allPassed = $false
        }
        $categoryCount++
    }
    
    $ValidationResults.Score = if ($categoryCount -gt 0) { [math]::Round($totalScore / $categoryCount, 1) } else { 0 }
    $ValidationResults.Duration = ((Get-Date) - $startTime).TotalSeconds
    $ValidationResults.Overall = if ($allPassed -and $ValidationResults.Issues.Count -eq 0) { "Passed" } else { "Failed" }
    
    # Save report
    $ValidationResults | ConvertTo-Json -Depth 10 | Out-File $ReportPath -Encoding UTF8
    
    Write-ValidationLog "Validation complete. Score: $($ValidationResults.Score)/100, Overall: $($ValidationResults.Overall), Duration: $([math]::Round($ValidationResults.Duration, 2))s" $(if($ValidationResults.Overall -eq "Passed"){"PASS"}else{"ERROR"})
    
    return $ValidationResults
}

function Show-ValidationReport {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Final Validation Report                      ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Validation Type: $($ValidationResults.Type)" -ForegroundColor Cyan
    Write-Host "║ Timestamp: $($ValidationResults.Timestamp)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Overall: $($ValidationResults.Overall)" -ForegroundColor $(if($ValidationResults.Overall -eq "Passed"){"Green"}else{"Red"})
    Write-Host "║ Score: $($ValidationResults.Score)/100" -ForegroundColor $(if($ValidationResults.Score -ge 80){"Green"}elseif($ValidationResults.Score -ge 60){"Yellow"}else{"Red"})
    Write-Host "║ Duration: $([math]::Round($ValidationResults.Duration, 2))s" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    foreach ($category in $ValidationResults.Categories.Keys) {
        $catResults = $ValidationResults.Categories[$category]
        $status = if ($catResults.Passed) { "✓ PASS" } else { "✗ FAIL" }
        $color = if ($catResults.Passed) { "Green" } else { "Red" }
        Write-Host "║ $category`: $status" -ForegroundColor $color
    }
    
    if ($ValidationResults.Issues.Count -gt 0) {
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║ Issues Found:" -ForegroundColor Red
        foreach ($issue in $ValidationResults.Issues) {
            Write-Host "║   ! $issue" -ForegroundColor Red
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($ValidationType) {
    "Full" {
        $results = Invoke-FullValidation
        Show-ValidationReport
        exit ($results.Overall -eq "Passed" ? 0 : 1)
    }
    "Quick" {
        $results = Test-ComponentExistence
        $results | ConvertTo-Json -Depth 10
    }
    "Security" {
        $results = Test-SecurityValidation
        $results | ConvertTo-Json -Depth 10
    }
    "Performance" {
        $results = Test-PerformanceValidation
        $results | ConvertTo-Json -Depth 10
    }
    "Integration" {
        $results = Test-IntegrationValidation
        $results | ConvertTo-Json -Depth 10
    }
    "ShowReport" {
        if (Test-Path $ReportPath) {
            $ValidationResults = Get-Content $ReportPath | ConvertFrom-Json
            Show-ValidationReport
        }
        else {
            Write-ValidationLog "No validation report found at $ReportPath" "ERROR"
        }
    }
}
