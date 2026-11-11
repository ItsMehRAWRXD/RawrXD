# RawrXD Validation Tools

Additional utilities for working with validation results and generating reports.

## Tools Overview

| Tool | Purpose | Usage |
|------|---------|-------|
| `Compare-ValidationResults.ps1` | Compare results across runs | Track improvements/regressions |
| `Generate-ValidationReport.ps1` | Generate formatted reports | Executive/technical/CI reports |
| `Watch-Validation.ps1` | Real-time monitoring | Watch validation progress |
| `Schedule-Validation.ps1` | Schedule periodic runs | Continuous monitoring |

---

## Compare-ValidationResults.ps1

Compares validation results between two runs to track performance improvements or regressions.

### Usage

```powershell
# Basic comparison
.\Compare-ValidationResults.ps1 `
    -BaselinePath "validation_output\run_20260729\final_validation_report.json" `
    -CurrentPath "validation_output\run_20260730\final_validation_report.json"

# Export comparison report
.\Compare-ValidationResults.ps1 `
    -BaselinePath "baseline.json" `
    -CurrentPath "current.json" `
    -OutputPath "comparison.json"

# Generate HTML report
.\Compare-ValidationResults.ps1 `
    -BaselinePath "baseline.json" `
    -CurrentPath "current.json" `
    -GenerateHTML
```

### Output

Console output shows:
- Performance metrics comparison (TPS, latency, TTFT)
- Hardware configuration changes
- Certification status changes
- Summary of improvements vs regressions

Exported reports include:
- `comparison.json` - Machine-readable comparison data
- `comparison.html` - Visual comparison dashboard

### Example Output

```
Performance Metrics Comparison
--------------------------------
  Average TPS: 95.2 → 118.5 TPS ↑ 24.5%
  Average Latency: 4200 → 380 ms ↓ 90.9%
  Average TTFT: 180 → 115 ms ↓ 36.1%
  Success Rate: 0.92 → 0.96 % ↑ 4.3%

Summary
-------
  Total metrics compared: 4
  Improvements: 4
  Regressions: 0
  Significant changes (>5%): 4
```

---

## Generate-ValidationReport.ps1

Generates formatted reports from validation results in multiple formats.

### Usage

```powershell
# Generate all reports (executive + technical + CI)
.\Generate-ValidationReport.ps1 `
    -ValidationOutputPath "validation_output" `
    -ReportType Full

# Generate only executive summary
.\Generate-ValidationReport.ps1 `
    -ValidationOutputPath "validation_output" `
    -ReportType Executive

# Generate technical report with artifacts
.\Generate-ValidationReport.ps1 `
    -ValidationOutputPath "validation_output" `
    -ReportType Technical `
    -IncludeArtifacts

# Generate CI report and open it
.\Generate-ValidationReport.ps1 `
    -ValidationOutputPath "validation_output" `
    -ReportType CI `
    -OpenReport
```

### Report Types

#### Executive Report
- High-level summary for stakeholders
- Key findings and recommendations
- Certification status overview
- Performance grade (A-F)

#### Technical Report
- Detailed metrics analysis
- Latency/throughput breakdowns
- Hardware configuration details
- Bottleneck identification
- Optimization recommendations

#### CI Report
- JSON format for automation
- Pass/fail status
- Metrics in machine-readable format
- Artifact locations

### Report Formats

All reports include:
- Validation timestamp
- Performance metrics vs targets
- Hardware detection results
- Certification status
- Recommendations

## Watch-Validation.ps1

Real-time monitoring of validation progress with live updates.

### Usage

```powershell
# Basic watching
.\Watch-Validation.ps1

# With completion alert
.\Watch-Validation.ps1 -AlertOnCompletion

# Export on completion
.\Watch-Validation.ps1 -ExportOnCompletion

# Custom refresh interval
.\Watch-Validation.ps1 -RefreshIntervalSeconds 10
```

### Features

- **Live Progress:** Shows validation phases in real-time
- **Completion Alerts:** Windows notification or console beep
- **Auto-Export:** Automatically export results on completion
- **Progress Bars:** Visual progress for long-running validations

---

## Schedule-Validation.ps1

Schedule periodic validation runs using Windows Task Scheduler.

### Usage

```powershell
# Install daily validation (requires Administrator)
.\Schedule-Validation.ps1 -Install -Schedule Daily

# Install hourly validation
.\Schedule-Validation.ps1 -Install -Schedule Hourly

# Custom interval (every 30 minutes)
.\Schedule-Validation.ps1 -Install -Schedule Custom -IntervalMinutes 30

# Run validation now
.\Schedule-Validation.ps1 -RunNow

# List scheduled jobs
.\Schedule-Validation.ps1 -ListJobs

# Uninstall scheduled job
.\Schedule-Validation.ps1 -Uninstall
```

### Features

- **Multiple Schedules:** Hourly, Daily, Weekly, or Custom intervals
- **Retention Policy:** Automatic cleanup of old runs
- **Status Monitoring:** List and monitor scheduled jobs
- **Immediate Execution:** Run validation on-demand

---

## Integration Examples

### CI/CD Pipeline

```yaml
# Compare with baseline in CI
- name: Compare with Baseline
  run: |
    $baseline = "baseline/validation_report.json"
    $current = "validation_output/final_validation_report.json"
    
    .\validation\tools\Compare-ValidationResults.ps1 `
        -BaselinePath $baseline `
        -CurrentPath $current `
        -OutputPath "comparison.json"
    
    # Fail if significant regression
    $comp = Get-Content "comparison.json" | ConvertFrom-Json
    $regressions = $comp.metrics | Where-Object { -not $_.Improved -and $_.Significant }
    if ($regressions) {
        throw "Significant performance regressions detected"
    }

- name: Generate Reports
  run: |
    .\validation\tools\Generate-ValidationReport.ps1 `
        -ValidationOutputPath "validation_output" `
        -ReportType Full `
        -IncludeArtifacts
```

### Performance Tracking

```powershell
# Track performance over time
$runs = Get-ChildItem "validation_output\run_*" | Sort-Object Name

for ($i = 1; $i -lt $runs.Count; $i++) {
    $baseline = Join-Path $runs[$i-1].FullName "final_validation_report.json"
    $current = Join-Path $runs[$i].FullName "final_validation_report.json"
    
    .\Compare-ValidationResults.ps1 `
        -BaselinePath $baseline `
        -CurrentPath $current `
        -OutputPath "comparisons\compare_$($i-1)_to_$i.json"
}
```

### Automated Reporting

```powershell
# Daily validation report
$date = Get-Date -Format "yyyy-MM-dd"
$validationPath = "validation_output\$date"

# Run validation
.\Validate-Production.ps1 -OutputPath $validationPath

# Generate reports
.\Generate-ValidationReport.ps1 `
    -ValidationOutputPath $validationPath `
    -ReportType Full `
    -OutputDirectory "reports\$date"

# Email reports (requires additional setup)
Send-MailMessage `
    -To "team@example.com" `
    -Subject "RawrXD Validation Report - $date" `
    -Attachments "reports\$date\validation_report_executive_*.md"
```

---

## Common Workflows

### Before Release

```powershell
# 1. Run full validation
.\Validate-Production.ps1 -BenchmarkRuns 100

# 2. Compare with previous release
.\Compare-ValidationResults.ps1 `
    -BaselinePath "releases\v1.0\validation_report.json" `
    -CurrentPath "validation_output\final_validation_report.json"

# 3. Generate release reports
.\Generate-ValidationReport.ps1 `
    -ValidationOutputPath "validation_output" `
    -ReportType Full `
    -IncludeArtifacts
```

### Performance Investigation

```powershell
# 1. Run validation with detailed telemetry
.\Validate-Production.ps1 -BenchmarkRuns 50

# 2. Generate technical report
.\Generate-ValidationReport.ps1 `
    -ValidationOutputPath "validation_output" `
    -ReportType Technical

# 3. Review bottlenecks section in technical report
```

### Regression Detection

```powershell
# Automated regression detection script
$baseline = "baseline.json"
$current = "validation_output\final_validation_report.json"

.\Compare-ValidationResults.ps1 `
    -BaselinePath $baseline `
    -CurrentPath $current `
    -OutputPath "regression_check.json"

$comparison = Get-Content "regression_check.json" | ConvertFrom-Json
$regressions = $comparison.metrics | Where-Object { -not $_.Improved }

if ($regressions) {
    Write-Error "Performance regressions detected:"
    $regressions | ForEach-Object { Write-Error "  - $($_.Name): $($_.PercentChange)%" }
    exit 1
}
```

---

## Troubleshooting

### Compare-ValidationResults.ps1

| Issue | Solution |
|-------|----------|
| "Baseline report not found" | Verify path to baseline validation report |
| "Current report not found" | Run validation first to generate current report |
| Empty comparison | Check that both reports have same structure |

### Generate-ValidationReport.ps1

| Issue | Solution |
|-------|----------|
| "Validation report not found" | Run validation first or specify correct path |
| "Access denied" | Run with appropriate permissions |
| Reports not opening | Check file associations for .md/.json files |

---

## Requirements

- PowerShell 5.1 or later
- Validation framework artifacts
- Write permissions to output directory

---

## See Also

- [Validation Framework README](../harness/README.md)
- [Quick Start Guide](../QUICKSTART.md)
- [Production Readiness Guide](../../PRODUCTION_READINESS_GUIDE.md)
