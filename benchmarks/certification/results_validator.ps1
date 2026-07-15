#!/usr/bin/env pwsh
#==============================================================================
# RawrXD Sovereign Inferencer - Results Validator
# Phase F.3 Batch 1/5: Results Ingestion & Validation
#==============================================================================
# Validates benchmark outputs against targets and generates validation report
#==============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ResultsPath = "..\results",

    [Parameter()]
    [string]$OutputPath = ".\validation_report.json",

    [Parameter()]
    [switch]$StrictValidation,

    [Parameter()]
    [switch]$GenerateReport
)

# Target specifications from Phase F.2
$script:Targets = @{
    SIS_Minimum = 90
    SIS_Target = 95
    Grade = "A"
    Inference_TPS_Min = 40
    Inference_TPS_Target = 45
    TTFT_Max_ms = 20
    TTFT_Target_ms = 15
    Hotpatch_Deploy_Max_ms = 5
    Hotpatch_Deploy_Target_ms = 3
    SAI_Min = 1.4
    SAI_Target = 1.6
}

# Validation severity levels
enum ValidationSeverity {
    PASS
    WARNING
    FAIL
}

class ValidationResult {
    [string]$Metric
    [double]$Actual
    [double]$Target
    [double]$Tolerance
    [ValidationSeverity]$Severity
    [string]$Message
    [double]$PercentageOfTarget
}

class ResultsValidator {
    [string]$ResultsPath
    [System.Collections.ArrayList]$ValidationResults
    [hashtable]$IngestedData
    [bool]$StrictMode

    ResultsValidator([string]$path, [bool]$strict) {
        $this.ResultsPath = $path
        $this.ValidationResults = @()
        $this.IngestedData = @{}
        $this.StrictMode = $strict
    }

    [bool] IngestHardwareResults() {
        $hwFile = Join-Path $this.ResultsPath "hardware_baseline.json"
        if (-not (Test-Path $hwFile)) {
            Write-Warning "Hardware baseline not found: $hwFile"
            return $false
        }

        try {
            $this.IngestedData.Hardware = Get-Content $hwFile | ConvertFrom-Json
            Write-Host "✓ Hardware results ingested" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Error "Failed to parse hardware results: $_"
            return $false
        }
    }

    [bool] IngestInferenceResults() {
        $infFile = Join-Path $this.ResultsPath "inference_benchmark.json"
        if (-not (Test-Path $infFile)) {
            Write-Warning "Inference benchmark not found: $infFile"
            return $false
        }

        try {
            $this.IngestedData.Inference = Get-Content $infFile | ConvertFrom-Json
            Write-Host "✓ Inference results ingested" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Error "Failed to parse inference results: $_"
            return $false
        }
    }

    [bool] IngestHotpatchResults() {
        $hpFile = Join-Path $this.ResultsPath "hotpatch_benchmark.json"
        if (-not (Test-Path $hpFile)) {
            Write-Warning "Hotpatch benchmark not found: $hpFile"
            return $false
        }

        try {
            $this.IngestedData.Hotpatch = Get-Content $hpFile | ConvertFrom-Json
            Write-Host "✓ Hotpatch results ingested" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Error "Failed to parse hotpatch results: $_"
            return $false
        }
    }

    [bool] IngestSISResults() {
        $sisFile = Join-Path $this.ResultsPath "sis_score.json"
        if (-not (Test-Path $sisFile)) {
            Write-Warning "SIS score not found: $sisFile"
            return $false
        }

        try {
            $this.IngestedData.SIS = Get-Content $sisFile | ConvertFrom-Json
            Write-Host "✓ SIS results ingested" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Error "Failed to parse SIS results: $_"
            return $false
        }
    }

    [void] ValidateMetric([string]$name, [double]$actual, [double]$target, 
                          [double]$tolerance, [string]$comparison = "minimum") {
        $result = [ValidationResult]::new()
        $result.Metric = $name
        $result.Actual = $actual
        $result.Target = $target
        $result.Tolerance = $tolerance

        $toleranceRange = $target * ($tolerance / 100)
        $effectiveTarget = $target

        if ($comparison -eq "maximum") {
            $effectiveTarget = $target + $toleranceRange
            $result.PercentageOfTarget = if ($actual -gt 0) { ($target / $actual) * 100 } else { 0 }
            
            if ($actual -le $target) {
                $result.Severity = [ValidationSeverity]::PASS
                $result.Message = "$name PASS: $actual <= $target (target)"
            }
            elseif ($actual -le $effectiveTarget) {
                $result.Severity = [ValidationSeverity]::WARNING
                $result.Message = "$name WARNING: $actual within tolerance of $target"
            }
            else {
                $result.Severity = [ValidationSeverity]::FAIL
                $result.Message = "$name FAIL: $actual exceeds maximum $effectiveTarget"
            }
        }
        else {
            $effectiveTarget = $target - $toleranceRange
            $result.PercentageOfTarget = if ($target -gt 0) { ($actual / $target) * 100 } else { 0 }
            
            if ($actual -ge $target) {
                $result.Severity = [ValidationSeverity]::PASS
                $result.Message = "$name PASS: $actual >= $target (target)"
            }
            elseif ($actual -ge $effectiveTarget) {
                $result.Severity = [ValidationSeverity]::WARNING
                $result.Message = "$name WARNING: $actual within tolerance of $target"
            }
            else {
                $result.Severity = [ValidationSeverity]::FAIL
                $result.Message = "$name FAIL: $actual below minimum $effectiveTarget"
            }
        }

        $this.ValidationResults.Add($result)
    }

    [void] ValidateAllMetrics() {
        Write-Host "`n=== Validating Metrics Against Targets ===" -ForegroundColor Cyan

        # Validate SIS Score
        if ($this.IngestedData.SIS) {
            $this.ValidateMetric("SIS_Score", 
                $this.IngestedData.SIS.SIS_Score, 
                $script:Targets.SIS_Target, 5, "minimum")
            
            $this.ValidateMetric("SAI_Ratio", 
                $this.IngestedData.SIS.SAI_Ratio, 
                $script:Targets.SAI_Target, 10, "minimum")
        }

        # Validate Inference Metrics
        if ($this.IngestedData.Inference) {
            $avgTps = ($this.IngestedData.Inference.Benchmarks | 
                Measure-Object -Property TokensPerSecond -Average).Average
            $this.ValidateMetric("Inference_TPS", $avgTps, 
                $script:Targets.Inference_TPS_Target, 10, "minimum")

            $avgTtft = ($this.IngestedData.Inference.Benchmarks | 
                Measure-Object -Property TTFT_ms -Average).Average
            $this.ValidateMetric("TTFT_ms", $avgTtft, 
                $script:Targets.TTFT_Target_ms, 20, "maximum")
        }

        # Validate Hotpatch Metrics
        if ($this.IngestedData.Hotpatch) {
            $avgDeploy = ($this.IngestedData.Hotpatch.Results | 
                Measure-Object -Property DeploymentTime_ms -Average).Average
            $this.ValidateMetric("Hotpatch_Deploy_ms", $avgDeploy, 
                $script:Targets.Hotpatch_Deploy_Target_ms, 50, "maximum")
        }
    }

    [hashtable] GenerateValidationReport() {
        $passCount = ($this.ValidationResults | Where-Object { $_.Severity -eq "PASS" }).Count
        $warningCount = ($this.ValidationResults | Where-Object { $_.Severity -eq "WARNING" }).Count
        $failCount = ($this.ValidationResults | Where-Object { $_.Severity -eq "FAIL" }).Count

        $overallStatus = if ($failCount -gt 0) { "FAIL" }
                        elseif ($warningCount -gt 0) { "WARNING" }
                        else { "PASS" }

        $report = @{
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            OverallStatus = $overallStatus
            Summary = @{
                Total = $this.ValidationResults.Count
                Pass = $passCount
                Warning = $warningCount
                Fail = $failCount
            }
            Targets = $script:Targets
            Results = @()
        }

        foreach ($result in $this.ValidationResults) {
            $report.Results += @{
                Metric = $result.Metric
                Actual = $result.Actual
                Target = $result.Target
                Severity = $result.Severity.ToString()
                Message = $result.Message
                PercentageOfTarget = [math]::Round($result.PercentageOfTarget, 2)
            }
        }

        return $report
    }

    [void] DisplayValidationSummary() {
        Write-Host "`n=== Validation Summary ===" -ForegroundColor Cyan
        
        foreach ($result in $this.ValidationResults) {
            $color = switch ($result.Severity) {
                "PASS" { "Green" }
                "WARNING" { "Yellow" }
                "FAIL" { "Red" }
            }
            Write-Host $result.Message -ForegroundColor $color
        }

        $report = $this.GenerateValidationReport()
        Write-Host "`nOverall Status: $($report.OverallStatus)" -ForegroundColor $(
            if ($report.OverallStatus -eq "PASS") { "Green" }
            elseif ($report.OverallStatus -eq "WARNING") { "Yellow" }
            else { "Red" }
        )
    }
}

#==============================================================================
# Main Execution
#==============================================================================

Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Results Validator                               ║
║           Phase F.3 Batch 1/5: Results Ingestion & Validation                ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$validator = [ResultsValidator]::new($ResultsPath, $StrictValidation)

# Ingest all results
$ingestSuccess = $true
$ingestSuccess = $validator.IngestHardwareResults() -and $ingestSuccess
$ingestSuccess = $validator.IngestInferenceResults() -and $ingestSuccess
$ingestSuccess = $validator.IngestHotpatchResults() -and $ingestSuccess
$ingestSuccess = $validator.IngestSISResults() -and $ingestSuccess

if (-not $ingestSuccess) {
    Write-Warning "Some results could not be ingested. Validation may be incomplete."
}

# Validate all metrics
$validator.ValidateAllMetrics()

# Display summary
$validator.DisplayValidationSummary()

# Generate report if requested
if ($GenerateReport) {
    $report = $validator.GenerateValidationReport()
    $report | ConvertTo-Json -Depth 10 | Out-File $OutputPath
    Write-Host "`n✓ Validation report saved to: $OutputPath" -ForegroundColor Green
}

# Exit with appropriate code
$report = $validator.GenerateValidationReport()
if ($report.OverallStatus -eq "FAIL") { exit 1 }
elseif ($report.OverallStatus -eq "WARNING") { exit 2 }
else { exit 0 }
