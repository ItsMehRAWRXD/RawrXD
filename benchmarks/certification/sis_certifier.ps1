#!/usr/bin/env pwsh
#==============================================================================
# RawrXD Sovereign Inferencer - SIS Certifier
# Phase F.3 Batch 2/5: Official SIS/SAI Certification
#==============================================================================
# Calculates final SIS/SAI scores and assigns official Grade A-F
#==============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ValidationReport = ".\validation_report.json",

    [Parameter()]
    [string]$OutputPath = ".\CERTIFICATION.json",

    [Parameter()]
    [string]$EvidencePackagePath = "..\evidence\RawrXD_Sovereign_Evidence",

    [Parameter()]
    [switch]$GenerateCertificate,

    [Parameter()]
    [switch]$SignWithChecksum
)

#==============================================================================
# Certification Configuration
#==============================================================================

$script:CertificationConfig = @{
    Version = "1.0.0"
    Authority = "RawrXD Sovereign Certification Authority"
    ValidityDays = 365
    
    # Grade thresholds
    Grades = @{
        A_Plus = @{ Min = 95; Label = "A+"; Description = "Exceptional" }
        A = @{ Min = 90; Label = "A"; Description = "Excellent" }
        A_Minus = @{ Min = 85; Label = "A-"; Description = "Very Good" }
        B_Plus = @{ Min = 80; Label = "B+"; Description = "Good" }
        B = @{ Min = 75; Label = "B"; Description = "Above Average" }
        B_Minus = @{ Min = 70; Label = "B-"; Description = "Average" }
        C = @{ Min = 60; Label = "C"; Description = "Below Average" }
        D = @{ Min = 50; Label = "D"; Description = "Poor" }
        F = @{ Min = 0; Label = "F"; Description = "Fail" }
    }

    # SIS Category Weights (must sum to 100)
    Weights = @{
        Inference = 25
        Agentic = 20
        Hotpatch = 20
        Security = 15
        Compliance = 10
        Usability = 10
    }
}

#==============================================================================
# Certification Classes
#==============================================================================

class SISCertifier {
    [string]$ValidationReportPath
    [hashtable]$ValidationData
    [hashtable]$CategoryScores
    [double]$FinalSIS
    [string]$Grade
    [string]$CertificationID
    [datetime]$CertificationDate

    SISCertifier([string]$validationPath) {
        $this.ValidationReportPath = $validationPath
        $this.CategoryScores = @{}
        $this.CertificationDate = Get-Date
        $this.CertificationID = $this.GenerateCertificationID()
    }

    [string] GenerateCertificationID() {
        $timestamp = Get-Date -Format "yyyyMMddHHmmss"
        $random = -join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
        return "RSE-CERT-$timestamp-$random"
    }

    [bool] LoadValidationData() {
        if (-not (Test-Path $this.ValidationReportPath)) {
            Write-Error "Validation report not found: $($this.ValidationReportPath)"
            return $false
        }

        try {
            $this.ValidationData = Get-Content $this.ValidationReportPath | ConvertFrom-Json -AsHashtable
            Write-Host "✓ Validation data loaded" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Error "Failed to parse validation report: $_"
            return $false
        }
    }

    [void] CalculateCategoryScores() {
        Write-Host "`n=== Calculating Category Scores ===" -ForegroundColor Cyan

        # Inference Score (25%)
        $infResult = $this.ValidationData.Results | Where-Object { $_.Metric -eq "Inference_TPS" }
        if ($infResult) {
            $this.CategoryScores.Inference = [math]::Min(100, $infResult.PercentageOfTarget)
            Write-Host "  Inference: $($this.CategoryScores.Inference)% (weight: 25%)"
        }

        # Agentic Score (20%) - based on TTFT
        $ttftResult = $this.ValidationData.Results | Where-Object { $_.Metric -eq "TTFT_ms" }
        if ($ttftResult) {
            # Lower TTFT is better, so invert the percentage
            $this.CategoryScores.Agentic = [math]::Min(100, 200 - $ttftResult.PercentageOfTarget)
            Write-Host "  Agentic: $($this.CategoryScores.Agentic)% (weight: 20%)"
        }

        # Hotpatch Score (20%)
        $hpResult = $this.ValidationData.Results | Where-Object { $_.Metric -eq "Hotpatch_Deploy_ms" }
        if ($hpResult) {
            # Lower deployment time is better
            $this.CategoryScores.Hotpatch = [math]::Min(100, 200 - $hpResult.PercentageOfTarget)
            Write-Host "  Hotpatch: $($this.CategoryScores.Hotpatch)% (weight: 20%)"
        }

        # Security Score (15%) - based on validation pass rate
        $passRate = ($this.ValidationData.Results | Where-Object { $_.Severity -eq "PASS" }).Count / 
                    $this.ValidationData.Results.Count * 100
        $this.CategoryScores.Security = $passRate
        Write-Host "  Security: $($this.CategoryScores.Security)% (weight: 15%)"

        # Compliance Score (10%) - all validations must pass
        $failCount = ($this.ValidationData.Results | Where-Object { $_.Severity -eq "FAIL" }).Count
        $this.CategoryScores.Compliance = if ($failCount -eq 0) { 100 } else { [math]::Max(0, 100 - ($failCount * 20)) }
        Write-Host "  Compliance: $($this.CategoryScores.Compliance)% (weight: 10%)"

        # Usability Score (10%) - based on overall status
        $this.CategoryScores.Usability = switch ($this.ValidationData.OverallStatus) {
            "PASS" { 100 }
            "WARNING" { 80 }
            "FAIL" { 50 }
            default { 0 }
        }
        Write-Host "  Usability: $($this.CategoryScores.Usability)% (weight: 10%)"
    }

    [void] CalculateFinalSIS() {
        $weightedSum = 0
        $totalWeight = 0

        foreach ($category in $script:CertificationConfig.Weights.Keys) {
            if ($this.CategoryScores.ContainsKey($category)) {
                $weight = $script:CertificationConfig.Weights[$category]
                $weightedSum += $this.CategoryScores[$category] * $weight
                $totalWeight += $weight
            }
        }

        $this.FinalSIS = if ($totalWeight -gt 0) { [math]::Round($weightedSum / $totalWeight, 2) } else { 0 }
        Write-Host "`n=== Final SIS Score: $($this.FinalSIS) ===" -ForegroundColor Green
    }

    [void] AssignGrade() {
        $grades = $script:CertificationConfig.Grades
        
        foreach ($gradeKey in @("A_Plus", "A", "A_Minus", "B_Plus", "B", "B_Minus", "C", "D", "F")) {
            if ($this.FinalSIS -ge $grades[$gradeKey].Min) {
                $this.Grade = $grades[$gradeKey].Label
                Write-Host "Grade Assigned: $($grades[$gradeKey].Label) - $($grades[$gradeKey].Description)" -ForegroundColor Green
                return
            }
        }

        $this.Grade = "F"
    }

    [hashtable] GenerateCertification() {
        $certification = @{
            CertificationID = $this.CertificationID
            Version = $script:CertificationConfig.Version
            Authority = $script:CertificationConfig.Authority
            IssueDate = $this.CertificationDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
            ExpiryDate = $this.CertificationDate.AddDays($script:CertificationConfig.ValidityDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
            
            SIS = @{
                Score = $this.FinalSIS
                Grade = $this.Grade
                CategoryScores = $this.CategoryScores
                Weights = $script:CertificationConfig.Weights
            }

            ValidationSummary = @{
                OverallStatus = $this.ValidationData.OverallStatus
                TotalMetrics = $this.ValidationData.Summary.Total
                PassCount = $this.ValidationData.Summary.Pass
                WarningCount = $this.ValidationData.Summary.Warning
                FailCount = $this.ValidationData.Summary.Fail
            }

            Status = if ($this.Grade -in @("A+", "A", "A-")) { "CERTIFIED" } else { "CONDITIONAL" }
        }

        return $certification
    }

    [void] DisplayCertification([hashtable]$cert) {
        Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                    OFFICIAL CERTIFICATION                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Certification ID: $($cert.CertificationID.PadRight(55)) ║
║  Issue Date: $($cert.IssueDate.PadRight(61)) ║
║  Valid Until: $($cert.ExpiryDate.PadRight(61)) ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  SOVEREIGN INFERENCER SCORE (SIS): $($cert.SIS.Score.ToString().PadRight(37)) ║
║  GRADE: $($cert.SIS.Grade.PadRight(68)) ║
║  STATUS: $($cert.Status.PadRight(67)) ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

        Write-Host "Category Breakdown:" -ForegroundColor Yellow
        foreach ($cat in $cert.SIS.CategoryScores.Keys) {
            $weight = $script:CertificationConfig.Weights[$cat]
            Write-Host "  $cat`: $($cert.SIS.CategoryScores[$cat])% (weight: $weight%)"
        }
    }

    [string] GenerateCertificateText([hashtable]$cert) {
        $text = @"
================================================================================
                    RAWRXD SOVEREIGN INFERCER CERTIFICATE
================================================================================

This certifies that the RawrXD Sovereign Inferencer has been officially tested
and certified according to the Sovereign Inferencer Standard (SIS) v$($script:CertificationConfig.Version).

CERTIFICATION DETAILS:
  ID: $($cert.CertificationID)
  Issue Date: $($cert.IssueDate)
  Valid Until: $($cert.ExpiryDate)
  Authority: $($cert.Authority)

SOVEREIGN INFERENCER SCORE (SIS):
  Final Score: $($cert.SIS.Score)/100
  Grade: $($cert.SIS.Grade)
  Status: $($cert.Status)

CATEGORY SCORES:
"@

        foreach ($cat in $cert.SIS.CategoryScores.Keys) {
            $text += "`n  $cat`: $($cert.SIS.CategoryScores[$cat])%"
        }

        $text += @"

VALIDATION SUMMARY:
  Overall Status: $($cert.ValidationSummary.OverallStatus)
  Metrics Validated: $($cert.ValidationSummary.TotalMetrics)
  Passed: $($cert.ValidationSummary.PassCount)
  Warnings: $($cert.ValidationSummary.WarningCount)
  Failed: $($cert.ValidationSummary.FailCount)

================================================================================
This certificate is electronically generated and valid without signature.
To verify: Checksum $($this.GenerateCertificationChecksum($cert))
================================================================================
"@

        return $text
    }

    [string] GenerateCertificationChecksum([hashtable]$cert) {
        $json = $cert | ConvertTo-Json -Depth 10 -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
        return [BitConverter]::ToString($hash).Replace("-", "").Substring(0, 16)
    }
}

#==============================================================================
# Main Execution
#==============================================================================

Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - SIS Certifier                                   ║
║           Phase F.3 Batch 2/5: Official Certification                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$certifier = [SISCertifier]::new($ValidationReport)

# Load validation data
if (-not $certifier.LoadValidationData()) {
    exit 1
}

# Calculate scores
$certifier.CalculateCategoryScores()
$certifier.CalculateFinalSIS()
$certifier.AssignGrade()

# Generate certification
$certification = $certifier.GenerateCertification()

# Display certification
$certifier.DisplayCertification($certification)

# Save certification JSON
$certification | ConvertTo-Json -Depth 10 | Out-File $OutputPath
Write-Host "`n✓ Certification saved to: $OutputPath" -ForegroundColor Green

# Generate certificate text if requested
if ($GenerateCertificate) {
    $certText = $certifier.GenerateCertificateText($certification)
    $certPath = Join-Path (Split-Path $OutputPath) "CERTIFICATE.txt"
    $certText | Out-File $certPath
    Write-Host "✓ Certificate text saved to: $certPath" -ForegroundColor Green
}

# Generate checksum
$checksum = $certifier.GenerateCertificationChecksum($certification)
Write-Host "✓ Certification Checksum: $checksum" -ForegroundColor Green

Write-Host "`nCertification Complete!" -ForegroundColor Green

# Exit with appropriate code
if ($certification.Status -eq "CERTIFIED") { exit 0 }
else { exit 2 }
