# Gate D Statistical Validation Framework
# Runs telemetry_validation.exe multiple times and captures statistics

param(
    [int]$Iterations = 100,
    [string]$OutputDir = "d:\rawrxd-ci-bootstrap\evidence\gate_d",
    [string]$Executable = "d:\rawrxd-ci-bootstrap\build-ninja\bin\telemetry_validation.exe"
)

$ErrorActionPreference = "Stop"

# Helper function to parse telemetry output
function Parse-TelemetryOutput($output) {
    $result = @{
        SiLU_Scalar = 0
        SiLU_MASM = 0
        RMS_Scalar = 0
        RMS_MASM = 0
        Softmax_Scalar = 0
        Softmax_MASM = 0
    }
    
    # Parse using regex patterns
    $lines = $output -split "`r?`n"
    $currentTest = $null
    
    foreach ($line in $lines) {
        # Detect which test we're in
        if ($line -match "SiLU Activation") { $currentTest = "SiLU" }
        elseif ($line -match "RMS Normalization") { $currentTest = "RMS" }
        elseif ($line -match "Softmax") { $currentTest = "Softmax" }
        
        # Parse scalar cycles
        if ($line -match "Scalar cycles:\s+(\d+)" -and $currentTest) {
            $cycles = [int]$matches[1]
            switch ($currentTest) {
                "SiLU" { $result.SiLU_Scalar = $cycles }
                "RMS" { $result.RMS_Scalar = $cycles }
                "Softmax" { $result.Softmax_Scalar = $cycles }
            }
        }
        
        # Parse MASM cycles
        if ($line -match "MASM cycles:\s+(\d+)" -and $currentTest) {
            $cycles = [int]$matches[1]
            switch ($currentTest) {
                "SiLU" { $result.SiLU_MASM = $cycles }
                "RMS" { $result.RMS_MASM = $cycles }
                "Softmax" { $result.Softmax_MASM = $cycles }
            }
        }
    }
    
    return $result
}

# Calculate statistics
function Calculate-Statistics($data) {
    function Calc-Stats($values) {
        $sorted = $values | Sort-Object
        $n = $values.Count
        if ($n -eq 0) { return $null }
        
        $mean = ($values | Measure-Object -Average).Average
        $median = if ($n % 2 -eq 0) { 
            ($sorted[$n/2 - 1] + $sorted[$n/2]) / 2 
        } else { 
            $sorted[($n-1)/2] 
        }
        
        $variance = ($values | ForEach-Object { [math]::Pow($_ - $mean, 2) } | Measure-Object -Average).Average
        $stddev = [math]::Sqrt($variance)
        
        $min = ($values | Measure-Object -Minimum).Minimum
        $max = ($values | Measure-Object -Maximum).Maximum
        
        $p95 = $sorted[[math]::Floor($n * 0.95)]
        $p99 = $sorted[[math]::Floor($n * 0.99)]
        
        # 95% confidence interval
        $ci95 = 1.96 * ($stddev / [math]::Sqrt($n))
        
        return @{
            Count = $n
            Mean = [math]::Round($mean, 2)
            Median = [math]::Round($median, 2)
            StdDev = [math]::Round($stddev, 2)
            Min = $min
            Max = $max
            P95 = $p95
            P99 = $p99
            CI95Lower = [math]::Round($mean - $ci95, 2)
            CI95Upper = [math]::Round($mean + $ci95, 2)
        }
    }
    
    return @{
        SiLU = @{
            Scalar = Calc-Stats ($data | ForEach-Object { $_.SiLU_ScalarCycles })
            MASM = Calc-Stats ($data | ForEach-Object { $_.SiLU_MASMCycles })
            SpeedupMean = [math]::Round(($data | ForEach-Object { $_.SiLU_Speedup } | Measure-Object -Average).Average, 2)
        }
        RMS = @{
            Scalar = Calc-Stats ($data | ForEach-Object { $_.RMS_ScalarCycles })
            MASM = Calc-Stats ($data | ForEach-Object { $_.RMS_MASMCycles })
            SpeedupMean = [math]::Round(($data | ForEach-Object { $_.RMS_Speedup } | Measure-Object -Average).Average, 2)
        }
        Softmax = @{
            Scalar = Calc-Stats ($data | ForEach-Object { $_.Softmax_ScalarCycles })
            MASM = Calc-Stats ($data | ForEach-Object { $_.Softmax_MASMCycles })
            SpeedupMean = [math]::Round(($data | ForEach-Object { $_.Softmax_Speedup } | Measure-Object -Average).Average, 2)
        }
        Duration = Calc-Stats ($data | ForEach-Object { $_.DurationMs })
        PassRate = [math]::Round((($data | Where-Object { $_.Success }).Count / $data.Count) * 100, 2)
    }
}

# Generate JSON report
function Generate-JsonReport($data, $stats, $outputDir) {
    $report = @{
        Metadata = @{
            ValidationId = "VAL-009-STATISTICAL"
            Title = "Gate D Statistical Validation Report"
            Date = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            TotalRuns = $data.Count
            SuccessfulRuns = ($data | Where-Object { $_.Success }).Count
            FailedRuns = ($data | Where-Object { -not $_.Success }).Count
            PassRate = $stats.PassRate
        }
        Statistics = $stats
        RawData = $data
    }
    
    $report | ConvertTo-Json -Depth 10 | Out-File (Join-Path $outputDir "statistical_report.json")
}

# Generate HTML report
function Generate-HtmlReport($data, $stats, $outputDir) {
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Gate D Statistical Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1, h2 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .metric { font-weight: bold; color: #2196F3; }
        .pass { color: green; }
        .fail { color: red; }
    </style>
</head>
<body>
    <h1>Gate D Statistical Validation Report</h1>
    <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    
    <h2>Summary</h2>
    <table>
        <tr><th>Metric</th><th>Value</th></tr>
        <tr><td>Total Runs</td><td>$($data.Count)</td></tr>
        <tr><td>Successful Runs</td><td class="pass">$(($data | Where-Object { $_.Success }).Count)</td></tr>
        <tr><td>Failed Runs</td><td class="fail">$(($data | Where-Object { -not $_.Success }).Count)</td></tr>
        <tr><td>Pass Rate</td><td class="$(if($stats.PassRate -ge 95){'pass'}else{'fail'})">$($stats.PassRate)%</td></tr>
    </table>
    
    <h2>Speedup Summary</h2>
    <table>
        <tr><th>Kernel</th><th>Mean Speedup</th></tr>
        <tr><td>SiLU Activation</td><td class="metric">$($stats.SiLU.SpeedupMean)x</td></tr>
        <tr><td>RMS Normalization</td><td class="metric">$($stats.RMS.SpeedupMean)x</td></tr>
        <tr><td>Softmax</td><td class="metric">$($stats.Softmax.SpeedupMean)x</td></tr>
    </table>
</body>
</html>
"@
    
    $html | Out-File (Join-Path $outputDir "statistical_report.html")
}

# Generate Markdown summary
function Generate-MarkdownSummary($stats, $outputDir) {
    $md = @"
# Gate D Statistical Validation Summary

**Date:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")  
**Status:** $(if($stats.PassRate -ge 95){'✅ PASS'}else{'⚠️ PARTIAL'})

## Summary Statistics

| Metric | Value |
|--------|-------|
| Total Runs | $($stats.SiLU.Scalar.Count) |
| Pass Rate | $($stats.PassRate)% |
| Mean Duration | $($stats.Duration.Mean) ms |

## Kernel Speedups (Mean)

| Kernel | Speedup | Status |
|--------|---------|--------|
| SiLU Activation | $($stats.SiLU.SpeedupMean)x | $(if($stats.SiLU.SpeedupMean -gt 1){'✅'}else{'❌'}) |
| RMS Normalization | $($stats.RMS.SpeedupMean)x | $(if($stats.RMS.SpeedupMean -gt 1){'✅'}else{'❌'}) |
| Softmax | $($stats.Softmax.SpeedupMean)x | $(if($stats.Softmax.SpeedupMean -gt 1){'✅'}else{'❌'}) |

## Confidence Intervals (95%)

| Kernel | Mean Cycles | CI Lower | CI Upper |
|--------|-------------|----------|----------|
| SiLU Scalar | $($stats.SiLU.Scalar.Mean) | $($stats.SiLU.Scalar.CI95Lower) | $($stats.SiLU.Scalar.CI95Upper) |
| SiLU MASM | $($stats.SiLU.MASM.Mean) | $($stats.SiLU.MASM.CI95Lower) | $($stats.SiLU.MASM.CI95Upper) |

## Gate D Completion

$(if($stats.PassRate -ge 95 -and $stats.SiLU.SpeedupMean -gt 1 -and $stats.RMS.SpeedupMean -gt 1 -and $stats.Softmax.SpeedupMean -gt 1){'✅ **Gate D Complete** - Statistical validation passed with >95% pass rate and measurable speedups'}else{'⚠️ **Gate D Partial** - Additional runs or investigation required'})
"@
    
    $md | Out-File (Join-Path $outputDir "summary.md")
}

# Ensure output directory exists
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "========================================"
Write-Host "Gate D Statistical Validation"
Write-Host "========================================"
Write-Host "Iterations: $Iterations"
Write-Host "Executable: $Executable"
Write-Host "Output: $OutputDir"
Write-Host ""

# Results storage
$results = @()
$failedRuns = 0

# Run iterations
for ($i = 1; $i -le $Iterations; $i++) {
    $progress = [math]::Round(($i / $Iterations) * 100)
    Write-Progress -Activity "Running Statistical Validation" -Status "Iteration $i/$Iterations" -PercentComplete $progress
    
    $runStart = Get-Date
    
    try {
        # Run telemetry_validation and capture output
        $output = & $Executable 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        
        $runEnd = Get-Date
        $duration = ($runEnd - $runStart).TotalMilliseconds
        
        # Parse output for key metrics
        $parsed = Parse-TelemetryOutput $output
        
        $result = [PSCustomObject]@{
            RunId = $i
            Timestamp = $runStart.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            DurationMs = [math]::Round($duration, 2)
            ExitCode = $exitCode
            Success = ($exitCode -eq 0)
            
            # SiLU metrics
            SiLU_ScalarCycles = $parsed.SiLU_Scalar
            SiLU_MASMCycles = $parsed.SiLU_MASM
            SiLU_Speedup = if ($parsed.SiLU_MASM -gt 0) { [math]::Round($parsed.SiLU_Scalar / $parsed.SiLU_MASM, 2) } else { 0 }
            
            # RMS metrics
            RMS_ScalarCycles = $parsed.RMS_Scalar
            RMS_MASMCycles = $parsed.RMS_MASM
            RMS_Speedup = if ($parsed.RMS_MASM -gt 0) { [math]::Round($parsed.RMS_Scalar / $parsed.RMS_MASM, 2) } else { 0 }
            
            # Softmax metrics
            Softmax_ScalarCycles = $parsed.Softmax_Scalar
            Softmax_MASMCycles = $parsed.Softmax_MASM
            Softmax_Speedup = if ($parsed.Softmax_MASM -gt 0) { [math]::Round($parsed.Softmax_Scalar / $parsed.Softmax_MASM, 2) } else { 0 }
            
            # Phase results
            Phase1_Success = $output -match "Phase 1.*PASS|Resource Injection.*✓"
            Phase2_Success = $output -match "Phase 2.*PASS|Buffer Setup.*✓"
            Phase3_Success = $output -match "Phase 3.*PASS|Execution Trace.*✓"
            Phase4_Success = $output -match "Phase 4.*PASS|Integrity Check.*✓"
            Phase5_Success = $output -match "Phase 5.*PASS|Differential Testing.*✓"
        }
        
        $results += $result
        
        # Save individual run log
        $logPath = Join-Path $OutputDir "runs\run_$($i.ToString("000")).log"
        New-Item -ItemType Directory -Force -Path (Split-Path $logPath) | Out-Null
        $output | Out-File -FilePath $logPath
        
    } catch {
        $failedRuns++
        Write-Warning "Run $i failed: $_"
    }
}

Write-Progress -Activity "Running Statistical Validation" -Completed

# Calculate statistics
$stats = Calculate-Statistics $results

# Generate reports
Generate-JsonReport $results $stats $OutputDir
Generate-HtmlReport $results $stats $OutputDir
Generate-MarkdownSummary $stats $OutputDir

# Save raw data
$results | Export-Csv -Path (Join-Path $OutputDir "raw_measurements.csv") -NoTypeInformation

Write-Host ""
Write-Host "========================================"
Write-Host "Statistical Validation Complete"
Write-Host "========================================"
Write-Host "Successful Runs: $($results.Count)"
Write-Host "Failed Runs: $failedRuns"
Write-Host "Pass Rate: $([math]::Round(($results.Count / $Iterations) * 100, 2))%"
Write-Host ""
Write-Host "Speedups (Mean):"
Write-Host "  SiLU: $($stats.SiLU.SpeedupMean)x"
Write-Host "  RMS:  $($stats.RMS.SpeedupMean)x"
Write-Host "  Softmax: $($stats.Softmax.SpeedupMean)x"
Write-Host ""
Write-Host "Reports Generated:"
Write-Host "  - statistical_report.json"
Write-Host "  - statistical_report.html"
Write-Host "  - summary.md"
Write-Host "  - raw_measurements.csv"

# Helper function to parse telemetry output
function Parse-TelemetryOutput($output) {
    $result = @{
        SiLU_Scalar = 0
        SiLU_MASM = 0
        RMS_Scalar = 0
        RMS_MASM = 0
        Softmax_Scalar = 0
        Softmax_MASM = 0
    }
    
    # Parse using regex patterns
    $lines = $output -split "`r?`n"
    $currentTest = $null
    
    foreach ($line in $lines) {
        # Detect which test we're in
        if ($line -match "SiLU Activation") { $currentTest = "SiLU" }
        elseif ($line -match "RMS Normalization") { $currentTest = "RMS" }
        elseif ($line -match "Softmax") { $currentTest = "Softmax" }
        
        # Parse scalar cycles
        if ($line -match "Scalar cycles:\s+(\d+)" -and $currentTest) {
            $cycles = [int]$matches[1]
            switch ($currentTest) {
                "SiLU" { $result.SiLU_Scalar = $cycles }
                "RMS" { $result.RMS_Scalar = $cycles }
                "Softmax" { $result.Softmax_Scalar = $cycles }
            }
        }
        
        # Parse MASM cycles
        if ($line -match "MASM cycles:\s+(\d+)" -and $currentTest) {
            $cycles = [int]$matches[1]
            switch ($currentTest) {
                "SiLU" { $result.SiLU_MASM = $cycles }
                "RMS" { $result.RMS_MASM = $cycles }
                "Softmax" { $result.Softmax_MASM = $cycles }
            }
        }
    }
    
    return $result
}

# Calculate statistics
function Calculate-Statistics($data) {
    function Calc-Stats($values) {
        $sorted = $values | Sort-Object
        $n = $values.Count
        if ($n -eq 0) { return $null }
        
        $mean = ($values | Measure-Object -Average).Average
        $median = if ($n % 2 -eq 0) { 
            ($sorted[$n/2 - 1] + $sorted[$n/2]) / 2 
        } else { 
            $sorted[($n-1)/2] 
        }
        
        $variance = ($values | ForEach-Object { [math]::Pow($_ - $mean, 2) } | Measure-Object -Average).Average
        $stddev = [math]::Sqrt($variance)
        
        $min = ($values | Measure-Object -Minimum).Minimum
        $max = ($values | Measure-Object -Maximum).Maximum
        
        $p95 = $sorted[[math]::Floor($n * 0.95)]
        $p99 = $sorted[[math]::Floor($n * 0.99)]
        
        # 95% confidence interval
        $ci95 = 1.96 * ($stddev / [math]::Sqrt($n))
        
        return @{
            Count = $n
            Mean = [math]::Round($mean, 2)
            Median = [math]::Round($median, 2)
            StdDev = [math]::Round($stddev, 2)
            Min = $min
            Max = $max
            P95 = $p95
            P99 = $p99
            CI95Lower = [math]::Round($mean - $ci95, 2)
            CI95Upper = [math]::Round($mean + $ci95, 2)
        }
    }
    
    return @{
        SiLU = @{
            Scalar = Calc-Stats ($data | ForEach-Object { $_.SiLU_ScalarCycles })
            MASM = Calc-Stats ($data | ForEach-Object { $_.SiLU_MASMCycles })
            SpeedupMean = [math]::Round(($data | ForEach-Object { $_.SiLU_Speedup } | Measure-Object -Average).Average, 2)
        }
        RMS = @{
            Scalar = Calc-Stats ($data | ForEach-Object { $_.RMS_ScalarCycles })
            MASM = Calc-Stats ($data | ForEach-Object { $_.RMS_MASMCycles })
            SpeedupMean = [math]::Round(($data | ForEach-Object { $_.RMS_Speedup } | Measure-Object -Average).Average, 2)
        }
        Softmax = @{
            Scalar = Calc-Stats ($data | ForEach-Object { $_.Softmax_ScalarCycles })
            MASM = Calc-Stats ($data | ForEach-Object { $_.Softmax_MASMCycles })
            SpeedupMean = [math]::Round(($data | ForEach-Object { $_.Softmax_Speedup } | Measure-Object -Average).Average, 2)
        }
        Duration = Calc-Stats ($data | ForEach-Object { $_.DurationMs })
        PassRate = [math]::Round((($data | Where-Object { $_.Success }).Count / $data.Count) * 100, 2)
    }
}

# Generate JSON report
function Generate-JsonReport($data, $stats, $outputDir) {
    $report = @{
        Metadata = @{
            ValidationId = "VAL-009-STATISTICAL"
            Title = "Gate D Statistical Validation Report"
            Date = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            TotalRuns = $data.Count
            SuccessfulRuns = ($data | Where-Object { $_.Success }).Count
            FailedRuns = ($data | Where-Object { -not $_.Success }).Count
            PassRate = $stats.PassRate
        }
        Statistics = $stats
        RawData = $data
    }
    
    $report | ConvertTo-Json -Depth 10 | Out-File (Join-Path $outputDir "statistical_report.json")
}

# Generate HTML report
function Generate-HtmlReport($data, $stats, $outputDir) {
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Gate D Statistical Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1, h2 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .metric { font-weight: bold; color: #2196F3; }
        .pass { color: green; }
        .fail { color: red; }
    </style>
</head>
<body>
    <h1>Gate D Statistical Validation Report</h1>
    <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    
    <h2>Summary</h2>
    <table>
        <tr><th>Metric</th><th>Value</th></tr>
        <tr><td>Total Runs</td><td>$($data.Count)</td></tr>
        <tr><td>Successful Runs</td><td class="pass">$(($data | Where-Object { $_.Success }).Count)</td></tr>
        <tr><td>Failed Runs</td><td class="fail">$(($data | Where-Object { -not $_.Success }).Count)</td></tr>
        <tr><td>Pass Rate</td><td class="$(if($stats.PassRate -ge 95){'pass'}else{'fail'})">$($stats.PassRate)%</td></tr>
    </table>
    
    <h2>Speedup Summary</h2>
    <table>
        <tr><th>Kernel</th><th>Mean Speedup</th></tr>
        <tr><td>SiLU Activation</td><td class="metric">$($stats.SiLU.SpeedupMean)x</td></tr>
        <tr><td>RMS Normalization</td><td class="metric">$($stats.RMS.SpeedupMean)x</td></tr>
        <tr><td>Softmax</td><td class="metric">$($stats.Softmax.SpeedupMean)x</td></tr>
    </table>
</body>
</html>
"@
    
    $html | Out-File (Join-Path $outputDir "statistical_report.html")
}

# Generate Markdown summary
function Generate-MarkdownSummary($stats, $outputDir) {
    $md = @"
# Gate D Statistical Validation Summary

**Date:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")  
**Status:** $(if($stats.PassRate -ge 95){'✅ PASS'}else{'⚠️ PARTIAL'})

## Summary Statistics

| Metric | Value |
|--------|-------|
| Total Runs | $($stats.SiLU.Scalar.Count) |
| Pass Rate | $($stats.PassRate)% |
| Mean Duration | $($stats.Duration.Mean) ms |

## Kernel Speedups (Mean)

| Kernel | Speedup | Status |
|--------|---------|--------|
| SiLU Activation | $($stats.SiLU.SpeedupMean)x | $(if($stats.SiLU.SpeedupMean -gt 1){'✅'}else{'❌'}) |
| RMS Normalization | $($stats.RMS.SpeedupMean)x | $(if($stats.RMS.SpeedupMean -gt 1){'✅'}else{'❌'}) |
| Softmax | $($stats.Softmax.SpeedupMean)x | $(if($stats.Softmax.SpeedupMean -gt 1){'✅'}else{'❌'}) |

## Confidence Intervals (95%)

| Kernel | Mean Cycles | CI Lower | CI Upper |
|--------|-------------|----------|----------|
| SiLU Scalar | $($stats.SiLU.Scalar.Mean) | $($stats.SiLU.Scalar.CI95Lower) | $($stats.SiLU.Scalar.CI95Upper) |
| SiLU MASM | $($stats.SiLU.MASM.Mean) | $($stats.SiLU.MASM.CI95Lower) | $($stats.SiLU.MASM.CI95Upper) |

## Gate D Completion

$(if($stats.PassRate -ge 95 -and $stats.SiLU.SpeedupMean -gt 1 -and $stats.RMS.SpeedupMean -gt 1 -and $stats.Softmax.SpeedupMean -gt 1){'✅ **Gate D Complete** - Statistical validation passed with >95% pass rate and measurable speedups'}else{'⚠️ **Gate D Partial** - Additional runs or investigation required'})
"@
    
    $md | Out-File (Join-Path $outputDir "summary.md")
}
