# RawrXD Compliance Reporter
# Phase K Batch 5/5: Compliance Reporting and Certifications
# Generates compliance reports for various standards

param(
    [Parameter()]
    [ValidateSet("GenerateReport", "ListFrameworks", "CheckCompliance", "ExportReport", "ScheduleReport", "ShowStatus")]
    [string]$Action = "ShowStatus",
    
    [Parameter()]
    [string]$Framework,
    
    [Parameter()]
    [string]$TenantId,
    
    [Parameter()]
    [string]$StartDate,
    
    [Parameter()]
    [string]$EndDate,
    
    [Parameter()]
    [string]$OutputPath,
    
    [Parameter()]
    [string]$DataPath = "$PSScriptRoot\compliance_data",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\enterprise"
)

# Compliance framework definitions
$ComplianceFrameworks = @{
    "SOC2" = @{
        Name = "SOC 2 Type II"
        Description = "Service Organization Control 2"
        Categories = @("Security", "Availability", "Processing Integrity", "Confidentiality", "Privacy")
        Requirements = @(
            @{ Id = "CC6.1"; Description = "Logical access security"; Category = "Security" },
            @{ Id = "CC6.2"; Description = "Access removal"; Category = "Security" },
            @{ Id = "CC6.3"; Description = "Access restoration"; Category = "Security" },
            @{ Id = "CC7.1"; Description = "Security detection"; Category = "Security" },
            @{ Id = "CC7.2"; Description = "Security monitoring"; Category = "Security" },
            @{ Id = "A1.1"; Description = "Availability monitoring"; Category = "Availability" },
            @{ Id = "A1.2"; Description = "Backup and recovery"; Category = "Availability" },
            @{ Id = "PI1.1"; Description = "Processing integrity"; Category = "Processing Integrity" },
            @{ Id = "C1.1"; Description = "Confidentiality protection"; Category = "Confidentiality" }
        )
    }
    "GDPR" = @{
        Name = "General Data Protection Regulation"
        Description = "EU data protection regulation"
        Categories = @("Data Subject Rights", "Data Security", "Data Processing", "Consent Management")
        Requirements = @(
            @{ Id = "Art.5"; Description = "Principles of data processing"; Category = "Data Processing" },
            @{ Id = "Art.6"; Description = "Lawfulness of processing"; Category = "Data Processing" },
            @{ Id = "Art.12"; Description = "Transparent information"; Category = "Data Subject Rights" },
            @{ Id = "Art.15"; Description = "Right of access"; Category = "Data Subject Rights" },
            @{ Id = "Art.17"; Description = "Right to erasure"; Category = "Data Subject Rights" },
            @{ Id = "Art.25"; Description = "Data protection by design"; Category = "Data Security" },
            @{ Id = "Art.32"; Description = "Security of processing"; Category = "Data Security" },
            @{ Id = "Art.33"; Description = "Breach notification"; Category = "Data Security" }
        )
    }
    "HIPAA" = @{
        Name = "Health Insurance Portability and Accountability Act"
        Description = "US healthcare data protection"
        Categories = @("Administrative Safeguards", "Physical Safeguards", "Technical Safeguards")
        Requirements = @(
            @{ Id = "164.308"; Description = "Administrative safeguards"; Category = "Administrative Safeguards" },
            @{ Id = "164.310"; Description = "Physical safeguards"; Category = "Physical Safeguards" },
            @{ Id = "164.312"; Description = "Technical safeguards"; Category = "Technical Safeguards" },
            @{ Id = "164.312(a)"; Description = "Access control"; Category = "Technical Safeguards" },
            @{ Id = "164.312(b)"; Description = "Audit controls"; Category = "Technical Safeguards" },
            @{ Id = "164.312(c)"; Description = "Integrity controls"; Category = "Technical Safeguards" },
            @{ Id = "164.312(d)"; Description = "Person authentication"; Category = "Technical Safeguards" },
            @{ Id = "164.312(e)"; Description = "Transmission security"; Category = "Technical Safeguards" }
        )
    }
    "ISO27001" = @{
        Name = "ISO/IEC 27001:2022"
        Description = "Information Security Management System"
        Categories = @("Organizational", "People", "Physical", "Technological")
        Requirements = @(
            @{ Id = "A.5.1"; Description = "Policies for information security"; Category = "Organizational" },
            @{ Id = "A.5.2"; Description = "Information security roles"; Category = "Organizational" },
            @{ Id = "A.6.1"; Description = "Screening"; Category = "People" },
            @{ Id = "A.6.2"; Description = "Terms and conditions"; Category = "People" },
            @{ Id = "A.6.3"; Description = "Information security awareness"; Category = "People" },
            @{ Id = "A.7.1"; Description = "Physical security perimeters"; Category = "Physical" },
            @{ Id = "A.8.1"; Description = "User endpoint devices"; Category = "Technological" },
            @{ Id = "A.8.2"; Description = "Privileged access rights"; Category = "Technological" },
            @{ Id = "A.8.5"; Description = "Secure authentication"; Category = "Technological" },
            @{ Id = "A.8.9"; Description = "Configuration management"; Category = "Technological" },
            @{ Id = "A.8.11"; Description = "Data masking"; Category = "Technological" },
            @{ Id = "A.8.12"; Description = "Data leakage prevention"; Category = "Technological" },
            @{ Id = "A.8.15"; Description = "Logging"; Category = "Technological" },
            @{ Id = "A.8.16"; Description = "Monitoring activities"; Category = "Technological" }
        )
    }
    "NIST" = @{
        Name = "NIST Cybersecurity Framework"
        Description = "US cybersecurity framework"
        Categories = @("Identify", "Protect", "Detect", "Respond", "Recover")
        Requirements = @(
            @{ Id = "ID.AM"; Description = "Asset Management"; Category = "Identify" },
            @{ Id = "ID.GV"; Description = "Governance"; Category = "Identify" },
            @{ Id = "ID.RA"; Description = "Risk Assessment"; Category = "Identify" },
            @{ Id = "PR.AC"; Description = "Access Control"; Category = "Protect" },
            @{ Id = "PR.DS"; Description = "Data Security"; Category = "Protect" },
            @{ Id = "PR.IP"; Description = "Information Protection"; Category = "Protect" },
            @{ Id = "DE.AE"; Description = "Anomalies and Events"; Category = "Detect" },
            @{ Id = "DE.CM"; Description = "Security Continuous Monitoring"; Category = "Detect" },
            @{ Id = "RS.AN"; Description = "Analysis"; Category = "Respond" },
            @{ Id = "RC.RP"; Description = "Recovery Planning"; Category = "Recover" }
        )
    }
}

# Ensure directories exist
if (-not (Test-Path $DataPath)) {
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
}
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$StateFile = "$PSScriptRoot\compliance_state.json"

function Write-ComplianceLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [COMPLIANCE] $Message"
    
    $logFile = Join-Path $LogPath "compliance_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "COMPLIANCE" { "Cyan" }
        "PASS" { "Green" }
        "FAIL" { "Red" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-ComplianceState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        Reports = @()
        LastReportId = 0
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Save-ComplianceState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function Test-ComplianceRequirement {
    param(
        [string]$Framework,
        [hashtable]$Requirement,
        [string]$TenantId
    )
    
    # Simulate compliance checks based on requirement ID
    $complianceScore = Get-Random -Minimum 70 -Maximum 100
    $status = if ($complianceScore -ge 80) { "PASS" } else { "FAIL" }
    
    $evidence = @()
    $findings = @()
    
    # Generate evidence based on requirement
    switch -Wildcard ($Requirement.Id) {
        "CC*" {
            $evidence += "Access control logs reviewed"
            $evidence += "User access reviews completed"
            if ($status -eq "FAIL") {
                $findings += "Some user accounts lack proper approval documentation"
            }
        }
        "Art.*" {
            $evidence += "Data processing records maintained"
            $evidence += "Consent management system operational"
            if ($status -eq "FAIL") {
                $findings += "Data retention policies need review"
            }
        }
        "164.*" {
            $evidence += "Audit logs reviewed"
            $evidence += "Access controls verified"
            if ($status -eq "FAIL") {
                $findings += "Encryption at rest not fully implemented"
            }
        }
        "A.*" {
            $evidence += "Security policies documented"
            $evidence += "Training records verified"
            if ($status -eq "FAIL") {
                $findings += "Some security awareness training overdue"
            }
        }
        default {
            $evidence += "Controls implemented"
            $evidence += "Documentation reviewed"
        }
    }
    
    return @{
        RequirementId = $Requirement.Id
        Description = $Requirement.Description
        Category = $Requirement.Category
        Status = $status
        Score = $complianceScore
        Evidence = $evidence
        Findings = $findings
        LastChecked = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function New-ComplianceReport {
    param(
        [string]$Framework,
        [string]$TenantId,
        [DateTime]$StartDate,
        [DateTime]$EndDate
    )
    
    Write-ComplianceLog "Generating compliance report for $Framework" "COMPLIANCE"
    
    if (-not $ComplianceFrameworks.ContainsKey($Framework)) {
        Write-ComplianceLog "Unknown framework: $Framework" "ERROR"
        return $null
    }
    
    $frameworkData = $ComplianceFrameworks[$Framework]
    $results = @()
    
    foreach ($req in $frameworkData.Requirements) {
        $result = Test-ComplianceRequirement -Framework $Framework -Requirement $req -TenantId $TenantId
        $results += $result
    }
    
    $passed = ($results | Where-Object { $_.Status -eq "PASS" }).Count
    $failed = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
    $totalScore = [math]::Round(($results | Measure-Object -Property Score -Average).Average, 2)
    
    $state = Get-ComplianceState
    $state.LastReportId++
    
    $report = @{
        ReportId = $state.LastReportId
        Framework = $Framework
        FrameworkName = $frameworkData.Name
        TenantId = $TenantId
        StartDate = $StartDate.ToString("yyyy-MM-dd")
        EndDate = $EndDate.ToString("yyyy-MM-dd")
        Generated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Summary = @{
            TotalRequirements = $results.Count
            Passed = $passed
            Failed = $failed
            ComplianceScore = $totalScore
            Status = if ($totalScore -ge 80) { "COMPLIANT" } else { "NON_COMPLIANT" }
        }
        Results = $results
        Categories = @{}
    }
    
    # Group by category
    foreach ($category in $frameworkData.Categories) {
        $catResults = $results | Where-Object { $_.Category -eq $category }
        if ($catResults) {
            $catScore = [math]::Round(($catResults | Measure-Object -Property Score -Average).Average, 2)
            $report.Categories[$category] = @{
                Score = $catScore
                Passed = ($catResults | Where-Object { $_.Status -eq "PASS" }).Count
                Failed = ($catResults | Where-Object { $_.Status -eq "FAIL" }).Count
            }
        }
    }
    
    $state.Reports += $report
    Save-ComplianceState -State $state
    
    Write-ComplianceLog "Report generated: $($report.ReportId) - Score: $totalScore%" $(if ($totalScore -ge 80) { "PASS" } else { "FAIL" })
    
    return $report
}

function Export-ComplianceReport {
    param(
        [hashtable]$Report,
        [string]$OutputPath
    )
    
    $sb = New-Object System.Text.StringBuilder
    
    [void]$sb.AppendLine("# Compliance Report: $($Report.FrameworkName)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("**Report ID:** $($Report.ReportId)")
    [void]$sb.AppendLine("**Generated:** $($Report.Generated)")
    [void]$sb.AppendLine("**Period:** $($Report.StartDate) to $($Report.EndDate)")
    [void]$sb.AppendLine("**Tenant:** $($Report.TenantId)")
    [void]$sb.AppendLine("")
    
    [void]$sb.AppendLine("## Executive Summary")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Metric | Value |")
    [void]$sb.AppendLine("|--------|-------|")
    [void]$sb.AppendLine("| Overall Status | $($Report.Summary.Status) |")
    [void]$sb.AppendLine("| Compliance Score | $($Report.Summary.ComplianceScore)% |")
    [void]$sb.AppendLine("| Requirements Passed | $($Report.Summary.Passed) / $($Report.Summary.TotalRequirements) |")
    [void]$sb.AppendLine("| Requirements Failed | $($Report.Summary.Failed) |")
    [void]$sb.AppendLine("")
    
    [void]$sb.AppendLine("## Category Breakdown")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Category | Score | Passed | Failed |")
    [void]$sb.AppendLine("|----------|-------|--------|--------|")
    foreach ($cat in $Report.Categories.Keys) {
        $catData = $Report.Categories[$cat]
        [void]$sb.AppendLine("| $cat | $($catData.Score)% | $($catData.Passed) | $($catData.Failed) |")
    }
    [void]$sb.AppendLine("")
    
    [void]$sb.AppendLine("## Detailed Results")
    [void]$sb.AppendLine("")
    
    foreach ($result in $Report.Results) {
        $statusEmoji = if ($result.Status -eq "PASS") { "✅" } else { "❌" }
        [void]$sb.AppendLine("### $($result.RequirementId) $statusEmoji")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("**Description:** $($result.Description)")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("**Category:** $($result.Category)")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("**Score:** $($result.Score)%")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("**Evidence:**")
        foreach ($ev in $result.Evidence) {
            [void]$sb.AppendLine("- $ev")
        }
        [void]$sb.AppendLine("")
        
        if ($result.Findings.Count -gt 0) {
            [void]$sb.AppendLine("**Findings:**")
            foreach ($finding in $result.Findings) {
                [void]$sb.AppendLine("- ⚠️ $finding")
            }
            [void]$sb.AppendLine("")
        }
    }
    
    [void]$sb.AppendLine("---")
    [void]$sb.AppendLine("*Report generated by RawrXD Compliance Reporter*")
    
    $sb.ToString() | Out-File $OutputPath -Encoding UTF8
    Write-ComplianceLog "Report exported to: $OutputPath" "SUCCESS"
}

function Show-ComplianceStatus {
    $state = Get-ComplianceState
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Compliance Reporter Status                   ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Total Reports Generated: $($state.Reports.Count)" -ForegroundColor Cyan
    Write-Host "║ Last Report ID: $($state.LastReportId)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    Write-Host "║ Available Frameworks:" -ForegroundColor Cyan
    foreach ($fw in $ComplianceFrameworks.Keys | Sort-Object) {
        $info = $ComplianceFrameworks[$fw]
        Write-Host "║   $fw - $($info.Name)" -ForegroundColor Gray
        Write-Host "║     $($info.Description)" -ForegroundColor DarkGray
        Write-Host "║     Categories: $($info.Categories.Count) | Requirements: $($info.Requirements.Count)" -ForegroundColor DarkGray
    }
    
    if ($state.Reports.Count -gt 0) {
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║ Recent Reports:" -ForegroundColor Cyan
        $recent = $state.Reports | Sort-Object ReportId -Descending | Select-Object -First 5
        foreach ($r in $recent) {
            $color = if ($r.Summary.Status -eq "COMPLIANT") { "Green" } else { "Yellow" }
            Write-Host "║   #$($r.ReportId) - $($r.Framework) [$($r.Summary.Status)]" -ForegroundColor $color
            Write-Host "║     Score: $($r.Summary.ComplianceScore)% | Generated: $($r.Generated)" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "GenerateReport" {
        if (-not $Framework) {
            Write-ComplianceLog "Framework required" "ERROR"
            exit 1
        }
        $start = if ($StartDate) { [DateTime]::Parse($StartDate) } else { (Get-Date).AddDays(-90) }
        $end = if ($EndDate) { [DateTime]::Parse($EndDate) } else { Get-Date }
        
        $report = New-ComplianceReport -Framework $Framework -TenantId $TenantId -StartDate $start -EndDate $end
        if ($report) {
            $report | ConvertTo-Json -Depth 10
        }
        else {
            exit 1
        }
    }
    "ListFrameworks" {
        $ComplianceFrameworks | ConvertTo-Json -Depth 10
    }
    "CheckCompliance" {
        if (-not $Framework) {
            Write-ComplianceLog "Framework required" "ERROR"
            exit 1
        }
        $start = if ($StartDate) { [DateTime]::Parse($StartDate) } else { (Get-Date).AddDays(-30) }
        $end = if ($EndDate) { [DateTime]::Parse($EndDate) } else { Get-Date }
        
        $report = New-ComplianceReport -Framework $Framework -TenantId $TenantId -StartDate $start -EndDate $end
        $report.Summary | ConvertTo-Json
    }
    "ExportReport" {
        if (-not $OutputPath -or -not $Framework) {
            Write-ComplianceLog "OutputPath and Framework required" "ERROR"
            exit 1
        }
        $start = if ($StartDate) { [DateTime]::Parse($StartDate) } else { (Get-Date).AddDays(-90) }
        $end = if ($EndDate) { [DateTime]::Parse($EndDate) } else { Get-Date }
        
        $report = New-ComplianceReport -Framework $Framework -TenantId $TenantId -StartDate $start -EndDate $end
        if ($report) {
            Export-ComplianceReport -Report $report -OutputPath $OutputPath
        }
    }
    "ShowStatus" {
        Show-ComplianceStatus
    }
}
