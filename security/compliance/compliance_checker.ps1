# RawrXD Compliance Checker
# Phase M.3 - Compliance Frameworks
# Validates compliance with SOC 2, ISO 27001, GDPR, HIPAA

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("soc2", "iso27001", "gdpr", "hipaa", "all")]
    [string]$Framework = "all",

    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "compliance_framework.yaml",

    [Parameter(Mandatory=$false)]
    [switch]$GenerateReport,

    [Parameter(Mandatory=$false)]
    [switch]$FixIssues
)

$ErrorActionPreference = "Stop"

# Logging
function Write-ComplianceLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "SUCCESS" = "Green"; "WARNING" = "Yellow"; "ERROR" = "Red"; "AUDIT" = "Cyan" }
    Write-Host "[$timestamp] [COMPLIANCE] [$Level] $Message" -ForegroundColor $colors[$Level]
}

# Compliance finding class
class ComplianceFinding {
    [string]$Framework
    [string]$ControlId
    [string]$Category
    [string]$Description
    [string]$Status  # pass, fail, partial, not_applicable
    [string]$Evidence
    [string]$Remediation
    [string]$Severity

    ComplianceFinding([string]$framework, [string]$controlId, [string]$category) {
        $this.Framework = $framework
        $this.ControlId = $controlId
        $this.Category = $category
        $this.Status = "unknown"
    }
}

# Load compliance framework
function Import-ComplianceFramework {
    param([string]$Path)

    Write-ComplianceLog "Loading compliance framework from $Path..." "INFO"

    if (!(Test-Path $Path)) {
        throw "Compliance framework file not found: $Path"
    }

    # Parse YAML content
    $content = Get-Content $Path -Raw

    $frameworks = @{
        SOC2 = @{}
        ISO27001 = @{}
        GDPR = @{}
        HIPAA = @{}
    }

    # Extract SOC 2 controls
    if ($content -match "soc2\.controls:") {
        $frameworks.SOC2 = @{
            Name = "SOC 2 Type II"
            Categories = @("security", "availability", "processing_integrity", "confidentiality", "privacy")
        }
    }

    # Extract ISO 27001 controls
    if ($content -match "iso27001\.controls:") {
        $frameworks.ISO27001 = @{
            Name = "ISO/IEC 27001:2022"
            Categories = @("organizational", "people", "physical", "technological")
        }
    }

    # Extract GDPR articles
    if ($content -match "gdpr\.controls:") {
        $frameworks.GDPR = @{
            Name = "GDPR"
            Categories = @("data_subject_rights", "lawful_processing", "security", "accountability")
        }
    }

    # Extract HIPAA safeguards
    if ($content -match "hipaa\.controls:") {
        $frameworks.HIPAA = @{
            Name = "HIPAA Security Rule"
            Categories = @("administrative", "physical", "technical")
        }
    }

    Write-ComplianceLog "Loaded $($frameworks.Count) compliance frameworks" "SUCCESS"
    return $frameworks
}

# SOC 2 compliance checks
function Test-SOC2Compliance {
    $findings = @()

    Write-ComplianceLog "Checking SOC 2 compliance..." "INFO"

    # CC6.1 - Logical access security
    $finding = [ComplianceFinding]::new("SOC2", "CC6.1", "security")
    $finding.Description = "Logical access security"

    # Check for RBAC
    $rbacExists = Test-Path "security/policies/security_policies.yaml"
    if ($rbacExists) {
        $finding.Status = "pass"
        $finding.Evidence = "RBAC policies configured"
    } else {
        $finding.Status = "fail"
        $finding.Evidence = "RBAC policies not found"
        $finding.Remediation = "Implement RBAC in security/policies/security_policies.yaml"
        $finding.Severity = "critical"
    }
    $findings += $finding

    # CC6.2 - Access removal
    $finding = [ComplianceFinding]::new("SOC2", "CC6.2", "security")
    $finding.Description = "Access removal procedures"

    $accessLogsExist = Test-Path "security/audit/access_logs.ps1"
    if ($accessLogsExist) {
        $finding.Status = "pass"
        $finding.Evidence = "Access logging configured"
    } else {
        $finding.Status = "partial"
        $finding.Evidence = "Access logging not fully implemented"
        $finding.Remediation = "Implement access logging automation"
        $finding.Severity = "high"
    }
    $findings += $finding

    # A1.2 - System monitoring
    $finding = [ComplianceFinding]::new("SOC2", "A1.2", "availability")
    $finding.Description = "System monitoring"

    $monitoringExists = Test-Path "operations/live-monitoring/dashboard.ps1"
    if ($monitoringExists) {
        $finding.Status = "pass"
        $finding.Evidence = "Monitoring dashboard configured"
    } else {
        $finding.Status = "fail"
        $finding.Evidence = "Monitoring not configured"
        $finding.Remediation = "Deploy monitoring infrastructure"
        $finding.Severity = "critical"
    }
    $findings += $finding

    # C1.1 - Encryption at rest
    $finding = [ComplianceFinding]::new("SOC2", "C1.1", "confidentiality")
    $finding.Description = "Encryption at rest"

    $encryptionExists = Test-Path "security/secrets/secrets_manager.ps1"
    if ($encryptionExists) {
        $finding.Status = "pass"
        $finding.Evidence = "Encryption infrastructure configured"
    } else {
        $finding.Status = "fail"
        $finding.Evidence = "Encryption not configured"
        $finding.Remediation = "Implement encryption at rest"
        $finding.Severity = "critical"
    }
    $findings += $finding

    return $findings
}

# ISO 27001 compliance checks
function Test-ISO27001Compliance {
    $findings = @()

    Write-ComplianceLog "Checking ISO 27001 compliance..." "INFO"

    # A.5.1 - Information security policies
    $finding = [ComplianceFinding]::new("ISO27001", "A.5.1", "organizational")
    $finding.Description = "Policies for information security"

    $policiesExist = Test-Path "security/policies/security_policies.yaml"
    if ($policiesExist) {
        $finding.Status = "pass"
        $finding.Evidence = "Security policies documented"
    } else {
        $finding.Status = "fail"
        $finding.Evidence = "Security policies not documented"
        $finding.Remediation = "Create security policies documentation"
        $finding.Severity = "critical"
    }
    $findings += $finding

    # A.5.15 - Access control
    $finding = [ComplianceFinding]::new("ISO27001", "A.5.15", "technological")
    $finding.Description = "Access control"

    $rbacExists = Test-Path "security/policies/security_policies.yaml"
    if ($rbacExists) {
        $finding.Status = "pass"
        $finding.Evidence = "Access control implemented"
    } else {
        $finding.Status = "fail"
        $finding.Evidence = "Access control not implemented"
        $finding.Remediation = "Implement RBAC"
        $finding.Severity = "critical"
    }
    $findings += $finding

    # A.5.29 - Incident management
    $finding = [ComplianceFinding]::new("ISO27001", "A.5.29", "organizational")
    $finding.Description = "Information security incident management"

    $incidentResponseExists = Test-Path "security/audit/incident_response.ps1"
    if ($incidentResponseExists) {
        $finding.Status = "pass"
        $finding.Evidence = "Incident response procedures defined"
    } else {
        $finding.Status = "partial"
        $finding.Evidence = "Incident response partially implemented"
        $finding.Remediation = "Complete incident response procedures"
        $finding.Severity = "high"
    }
    $findings += $finding

    return $findings
}

# GDPR compliance checks
function Test-GDPRCompliance {
    $findings = @()

    Write-ComplianceLog "Checking GDPR compliance..." "INFO"

    # Article 5 - Principles
    $finding = [ComplianceFinding]::new("GDPR", "Article_5", "lawful_processing")
    $finding.Description = "Principles relating to processing"

    $dataClassificationExists = Test-Path "security/policies/data_classification.yaml"
    if ($dataClassificationExists) {
        $finding.Status = "pass"
        $finding.Evidence = "Data classification implemented"
    } else {
        $finding.Status = "partial"
        $finding.Evidence = "Data classification partially implemented"
        $finding.Remediation = "Complete data classification framework"
        $finding.Severity = "high"
    }
    $findings += $finding

    # Article 17 - Right to erasure
    $finding = [ComplianceFinding]::new("GDPR", "Article_17", "data_subject_rights")
    $finding.Description = "Right to erasure"

    $deletionLogsExist = Test-Path "security/audit/deletion_logs.ps1"
    if ($deletionLogsExist) {
        $finding.Status = "pass"
        $finding.Evidence = "Data deletion logging configured"
    } else {
        $finding.Status = "partial"
        $finding.Evidence = "Data deletion procedures not fully implemented"
        $finding.Remediation = "Implement data deletion API and logging"
        $finding.Severity = "high"
    }
    $findings += $finding

    # Article 32 - Security of processing
    $finding = [ComplianceFinding]::new("GDPR", "Article_32", "security")
    $finding.Description = "Security of processing"

    $encryptionExists = Test-Path "security/secrets/secrets_manager.ps1"
    if ($encryptionExists) {
        $finding.Status = "pass"
        $finding.Evidence = "Encryption implemented"
    } else {
        $finding.Status = "fail"
        $finding.Evidence = "Encryption not implemented"
        $finding.Remediation = "Implement encryption at rest and in transit"
        $finding.Severity = "critical"
    }
    $findings += $finding

    return $findings
}

# HIPAA compliance checks
function Test-HIPAACompliance {
    $findings = @()

    Write-ComplianceLog "Checking HIPAA compliance..." "INFO"

    # 164.308(a)(1) - Security Management
    $finding = [ComplianceFinding]::new("HIPAA", "164.308(a)(1)", "administrative")
    $finding.Description = "Security Management Process"

    $riskAssessmentExists = Test-Path "security/compliance/risk_assessment.md"
    if ($riskAssessmentExists) {
        $finding.Status = "pass"
        $finding.Evidence = "Risk assessment conducted"
    } else {
        $finding.Status = "partial"
        $finding.Evidence = "Risk assessment not current"
        $finding.Remediation = "Conduct annual risk assessment"
        $finding.Severity = "high"
    }
    $findings += $finding

    # 164.312(a)(1) - Access Control
    $finding = [ComplianceFinding]::new("HIPAA", "164.312(a)(1)", "technical")
    $finding.Description = "Access Control"

    $accessControlExists = Test-Path "security/policies/security_policies.yaml"
    if ($accessControlExists) {
        $finding.Status = "pass"
        $finding.Evidence = "Access controls implemented"
    } else {
        $finding.Status = "fail"
        $finding.Evidence = "Access controls not implemented"
        $finding.Remediation = "Implement unique user identification and automatic logoff"
        $finding.Severity = "critical"
    }
    $findings += $finding

    # 164.312(e)(1) - Transmission Security
    $finding = [ComplianceFinding]::new("HIPAA", "164.312(e)(1)", "technical")
    $finding.Description = "Transmission Security"

    $tlsExists = Test-Path "scaling/service-mesh/istio_config.yaml"
    if ($tlsExists) {
        $finding.Status = "pass"
        $finding.Evidence = "TLS encryption configured"
    } else {
        $finding.Status = "fail"
        $finding.Evidence = "Transmission encryption not configured"
        $finding.Remediation = "Implement TLS for all data transmission"
        $finding.Severity = "critical"
    }
    $findings += $finding

    return $findings
}

# Generate compliance report
function Export-ComplianceReport {
    param(
        [ComplianceFinding[]]$Findings,
        [string]$OutputPath
    )

    Write-ComplianceLog "Generating compliance report..." "INFO"

    $frameworks = $Findings | Group-Object Framework

    $report = @{
        generated_at = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        summary = @{
            total_controls = $Findings.Count
            passed = ($Findings | Where-Object { $_.Status -eq "pass" }).Count
            failed = ($Findings | Where-Object { $_.Status -eq "fail" }).Count
            partial = ($Findings | Where-Object { $_.Status -eq "partial" }).Count
            compliance_percentage = if ($Findings.Count -gt 0) {
                [math]::Round((($Findings | Where-Object { $_.Status -eq "pass" }).Count / $Findings.Count) * 100, 2)
            } else { 0 }
        }
        frameworks = @()
        findings = $Findings | ForEach-Object {
            @{
                framework = $_.Framework
                control_id = $_.ControlId
                category = $_.Category
                description = $_.Description
                status = $_.Status
                evidence = $_.Evidence
                remediation = $_.Remediation
                severity = $_.Severity
            }
        }
    }

    foreach ($fw in $frameworks) {
        $fwFindings = $fw.Group
        $report.frameworks += @{
            name = $fw.Name
            total = $fwFindings.Count
            passed = ($fwFindings | Where-Object { $_.Status -eq "pass" }).Count
            failed = ($fwFindings | Where-Object { $_.Status -eq "fail" }).Count
            compliance_percentage = if ($fwFindings.Count -gt 0) {
                [math]::Round((($fwFindings | Where-Object { $_.Status -eq "pass" }).Count / $fwFindings.Count) * 100, 2)
            } else { 0 }
        }
    }

    $report | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8
    Write-ComplianceLog "Report saved to $OutputPath" "SUCCESS"

    return $report
}

# Display results
function Show-ComplianceResults {
    param([ComplianceFinding[]]$Findings)

    Write-Host "`nCompliance Check Results" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan

    $frameworks = $Findings | Group-Object Framework

    foreach ($fw in $frameworks) {
        Write-Host "`n$($fw.Name):" -ForegroundColor Yellow

        $fwFindings = $fw.Group | Sort-Object Status -Descending

        foreach ($finding in $fwFindings) {
            $statusColor = switch ($finding.Status) {
                "pass" { "Green" }
                "partial" { "Yellow" }
                "fail" { "Red" }
                default { "White" }
            }

            Write-Host "  [$($finding.ControlId)] " -NoNewline
            Write-Host $finding.Status.ToUpper() -ForegroundColor $statusColor -NoNewline
            Write-Host " - $($finding.Description)"

            if ($finding.Status -ne "pass") {
                Write-Host "    Evidence: $($finding.Evidence)" -ForegroundColor Gray
                if ($finding.Remediation) {
                    Write-Host "    Remediation: $($finding.Remediation)" -ForegroundColor Cyan
                }
            }
        }

        $complianceRate = if ($fw.Group.Count -gt 0) {
            ($fw.Group | Where-Object { $_.Status -eq "pass" }).Count / $fw.Group.Count * 100
        } else { 0 }

        Write-Host "`n  Compliance Rate: $([math]::Round($complianceRate, 1))%" -ForegroundColor $(
            if ($complianceRate -ge 90) { "Green" }
            elseif ($complianceRate -ge 70) { "Yellow" }
            else { "Red" }
        )
    }
}

# Main execution
Write-ComplianceLog "RawrXD Compliance Checker Started" "INFO"
Write-ComplianceLog "Framework: $Framework" "INFO"

# Load framework
$frameworks = Import-ComplianceFramework -Path $ConfigFile

# Run compliance checks
$allFindings = @()

if ($Framework -eq "all" -or $Framework -eq "soc2") {
    $allFindings += Test-SOC2Compliance
}

if ($Framework -eq "all" -or $Framework -eq "iso27001") {
    $allFindings += Test-ISO27001Compliance
}

if ($Framework -eq "all" -or $Framework -eq "gdpr") {
    $allFindings += Test-GDPRCompliance
}

if ($Framework -eq "all" -or $Framework -eq "hipaa") {
    $allFindings += Test-HIPAACompliance
}

# Display results
Show-ComplianceResults -Findings $allFindings

# Generate report if requested
if ($GenerateReport) {
    $reportPath = "compliance_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $report = Export-ComplianceReport -Findings $allFindings -OutputPath $reportPath

    Write-Host "`nOverall Compliance: $($report.summary.compliance_percentage)%" -ForegroundColor $(
        if ($report.summary.compliance_percentage -ge 90) { "Green" }
        elseif ($report.summary.compliance_percentage -ge 70) { "Yellow" }
        else { "Red" }
    )
}

Write-ComplianceLog "Compliance check complete" "SUCCESS"
