# Gate D Statistical Analysis Script
# Analyzes telemetry_validation.exe output for statistical significance

param(
    [int]$Iterations = 100,
    [string]$OutputPath = "d:\rawrxd-ci-bootstrap\evidence\gate_d"
)

$results = @()
$buildInfo = @{
    Binary = "telemetry_validation.exe"
    SHA256 = (Get-FileHash -Algorithm SHA256 "$PSScriptRoot\..\..\build-ninja\bin\telemetry_validation.exe" -ErrorAction SilentlyContinue).Hash
    Date = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
}

Write-Host "Gate D Statistical Validation"
Write-Host "Running $Iterations iterations..."
Write-Host ""

for ($i = 1; $i -le $Iterations; $i++) {
    $output = & "$PSScriptRoot\..\..\build-ninja\bin\telemetry_validation.exe" 2>&1 | Out-String
    
    # Parse differential results
    $siluMatch = $output | Select-String "SiLU Activation.*Scalar cycles:\s+(\d+)"
    $rmsMatch = $output | Select-String "RMS Normalization.*Scalar cycles:\s+(\d+)"
    $softmaxMatch = $output | Select-String "Softmax.*Scalar cycles:\s+(\d+)"
    
    $siluMasMatch = $output | Select-String "SiLU Activation.*MASM cycles:\s+(\d+)"
    $rmsMasMatch = $output | Select-String "RMS Normalization.*MASM cycles:\s+(\d+)"
    $softmaxMasMatch = $output | Select-String "Softmax.*MASM cycles:\s+(\d+)"
    
    $result = [PSCustomObject]@{
        Run = $i
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        SiLU_Scalar = if ($siluMatch) { [int]$siluMatch.Matches[0].Groups[1].Value } else { 0 }
        SiLU_MASM = if ($siluMasMatch) { [int]$siluMasMatch.Matches[0].Groups[1].Value } else { 0 }
        RMS_Scalar = if ($rmsMatch) { [int]$rmsMatch.Matches[0].Groups[1].Value } else { 0 }
        RMS_MASM = if ($rmsMasMatch) { [int]$rmsMasMatch.Matches[0].Groups[1].Value } else { 0 }
        Softmax_Scalar = if ($softmaxMatch) { [int]$softmaxMatch.Matches[0].Groups[1].Value } else { 0 }
        Softmax_MASM = if ($softmaxMasMatch) { [int]$softmaxMasMatch.Matches[0].Groups[1].Value } else { 0 }
    }
    
    $results += $result
    
    if ($i % 10 -eq 0) {
        Write-Progress -Activity "Running VAL-009 iterations" -Status "Iteration $i/$Iterations" -PercentComplete ($i / $Iterations * 100)
    }
}

Write-Progress -Activity "Running VAL-009 iterations" -Completed

# Calculate statistics
function Calculate-Stats($values) {
    $sorted = $values | Sort-Object
    $n = $values.Count
    $mean = ($values | Measure-Object -Average).Average
    $median = if ($n % 2 -eq 0) { ($sorted[$n/2 - 1] + $sorted[$n/2]) / 2 } else { $sorted[($n-1)/2] }
    $stddev = [math]::Sqrt((($values | ForEach-Object { ($_ - $mean) * ($_ - $mean) } | Measure-Object -Sum).Sum / $n))
    $min = ($values | Measure-Object -Minimum).Minimum
    $max = ($values | Measure-Object -Maximum).Maximum
    $p95 = $sorted[[math]::Floor($n * 0.95)]
    $p99 = $sorted[[math]::Floor($n * 0.99)]
    
    # Confidence interval (95%)
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
        CI95_Lower = [math]::Round($mean - $ci95, 2)
        CI95_Upper = [math]::Round($mean + $ci95, 2)
    }
}

$stats = @{
    BuildInfo = $buildInfo
    Summary = @{
        TotalRuns = $Iterations
        Date = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    }
    Statistics = @{
        SiLU_Scalar = Calculate-Stats $results.SiLU_Scalar
        SiLU_MASM = Calculate-Stats $results.SiLU_MASM
        RMS_Scalar = Calculate-Stats $results.RMS_Scalar
        RMS_MASM = Calculate-Stats $results.RMS_MASM
        Softmax_Scalar = Calculate-Stats $results.Softmax_Scalar
        Softmax_MASM = Calculate-Stats $results.Softmax_MASM
    }
    Speedups = @{
        SiLU = [math]::Round(($results.SiLU_Scalar | Measure-Object -Average).Average / ($results.SiLU_MASM | Measure-Object -Average).Average, 2)
        RMS = [math]::Round(($results.RMS_Scalar | Measure-Object -Average).Average / ($results.RMS_MASM | Measure-Object -Average).Average, 2)
        Softmax = [math]::Round(($results.Softmax_Scalar | Measure-Object -Average).Average / ($results.Softmax_MASM | Measure-Object -Average).Average, 2)
    }
    RawData = $results
}

# Save results
$stats | ConvertTo-Json -Depth 10 | Out-File "$OutputPath\statistical_report.json"
$results | Export-Csv -Path "$OutputPath\raw_measurements.csv" -NoTypeInformation

# Generate summary
Write-Host ""
Write-Host "========================================"
Write-Host "Gate D Statistical Validation Complete"
Write-Host "========================================"
Write-Host ""
Write-Host "Samples: $Iterations"
Write-Host ""
Write-Host "Speedups (mean):"
Write-Host "  SiLU: $($stats.Speedups.SiLU)x"
Write-Host "  RMS:  $($stats.Speedups.RMS)x"
Write-Host "  Softmax: $($stats.Speedups.Softmax)x"
Write-Host ""
Write-Host "SiLU Scalar Statistics:"
Write-Host "  Mean: $($stats.Statistics.SiLU_Scalar.Mean) cycles"
Write-Host "  StdDev: $($stats.Statistics.SiLU_Scalar.StdDev)"
Write-Host "  95% CI: [$($stats.Statistics.SiLU_Scalar.CI95_Lower), $($stats.Statistics.SiLU_Scalar.CI95_Upper)]"
Write-Host ""
Write-Host "Files saved:"
Write-Host "  - statistical_report.json"
Write-Host "  - raw_measurements.csv"
