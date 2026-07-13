#Requires -Version 7.0
<#
.SYNOPSIS
    Compliance Checker for RawrXD Hotpatch System

.DESCRIPTION
    Validates system compliance with security standards (SOC2, ISO27001, NIST).

.PARAMETER Standard
    Compliance standard: SOC2, ISO27001, NIST, ALL

.PARAMETER OutputFormat
    Output format: console, json, html

.PARAMETER GenerateReport
    Generate detailed compliance report

.EXAMPLE
    .\compliance_checker.ps1 -Standard SOC2 -GenerateReport
    .\compliance_checker.ps1 -Standard ALL -OutputFormat html
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("SOC2", "ISO27001", "NIST", "ALL")]
    [string]$Standard = "ALL",

    [Parameter(Mandatory = $false)]
    [ValidateSet("console", "json", "html")]
    [string]$OutputFormat = "console",

    [Parameter(Mandatory = $false)]
    [switch]$GenerateReport
)

# Compliance frameworks
$script:ComplianceFrameworks = @{
    SOC2 = @{
        Name = "SOC 2 Type II"
        Description = "Service Organization Control 2"
        Controls = @(
            @{ ID = "CC6.1"; Description = "Logical access security"; Category = "Security" },
            @{ ID = "CC6.2"; Description = "Access removal"; Category = "Security" },
            @{ ID = "CC6.3"; Description = "Access restoration"; Category = "Security" },
            @{ ID = "CC7.1"; Description = "Security operations monitoring"; Category = "Availability" },
            @{ ID = "CC7.2"; Description = "System monitoring"; Category = "Availability" },
            @{ ID = "CC8.1"; Description = "Change management"; Category = "Processing Integrity" }
        )
    }
    ISO27001 = @{
        Name = "ISO/IEC 27001:2022"
        Description = "Information Security Management"
        Controls = @(
            @{ ID = "A.5.15"; Description = "Access control"; Category = "Organizational" },
            @{ ID = "A.5.18"; Description = "Access rights"; Category = "Organizational" },
            @{ ID = "A.8.1"; Description = "User endpoint devices"; Category = "Technological" },
            @{ ID = "A.8.5"; Description = "Secure authentication"; Category = "Technological" },
            @{ ID = "A.8.9"; Description = "Management of secret authentication information"; Category = "Technological" },
            @{ ID = "A.8.11"; Description = "Data masking"; Category = "Technological" }
        )
    }
    NIST = @{
        Name = "NIST Cybersecurity Framework"
        Description = "NIST CSF 2.0"
        Controls = @(
            @{ ID = "PR.AC-1"; Description = "Identities and credentials"; Category = "Protect" },
            @{ ID = "PR.AC-2"; Description = "Remote access"; Category = "Protect" },
            @{ ID = "PR.AC-3"; Description = "Access permissions"; Category = "Protect" },
            @{ ID = "PR.AC-4"; Description = "Access reviews"; Category = "Protect" },
            @{ ID = "PR.AC-5"; Description = "Access revocation"; Category = "Protect" },
            @{ ID = "PR.AC-6"; Description = "Least privilege"; Category = "Protect" }
        )
    }
}

# Compliance check results
$script:CheckResults = @{
    Timestamp = Get-Date -Format "o"
    Standards = @()
    Summary = @{
        TotalControls = 0
        Passed = 0
        Failed = 0
        Warning = 0
        CompliancePercentage = 0
    }
}

function Write-ComplianceLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "PASS" = "Green"; "FAIL" = "Red"; "WARN" = "Yellow" }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level]
}

# Check RBAC configuration
function Test-RBACCompliance {
    $rbacConfigPath = "$env:RAWRXD_HOME\security\phase_h_enterprise_security\rbac\rbac_config.json"

    if (-not (Test-Path $rbacConfigPath)) {
        return @{ Status = "FAIL"; Message = "RBAC configuration not found"; Details = @{} }
    }

    try {
        $rbacConfig = Get-Content $rbacConfigPath -Raw | ConvertFrom-Json

        $checks = @{
            HasRoles = ($rbacConfig.Roles.PSObject.Properties.Count -gt 0)
            HasUsers = ($rbacConfig.Users.PSObject.Properties.Count -gt 0)
            HasAuditLog = ($rbacConfig.AuditLog -ne $null)
            HasSuperAdmin = ($rbacConfig.Users.PSObject.Properties.Name -contains "system")
        }

        $passed = ($checks.Values | Where-Object { $_ }).Count
        $total = $checks.Count

        if ($passed -eq $total) {
            return @{ Status = "PASS"; Message = "RBAC properly configured"; Details = $checks }
        }
        else {
            return @{ Status = "FAIL"; Message = "RBAC configuration incomplete"; Details = $checks }
        }
    }
    catch {
        return @{ Status = "FAIL"; Message = "RBAC configuration corrupt: $_"; Details = @{} }
    }
}

# Check audit logging
function Test-AuditCompliance {
    $auditLogPath = "$env:RAWRXD_HOME\logs\audit"

    if (-not (Test-Path $auditLogPath)) {
        return @{ Status = "FAIL"; Message = "Audit log directory not found"; Details = @{} }
    }

    $logFiles = Get-ChildItem $auditLogPath -Filter "audit_*.jsonl" -ErrorAction SilentlyContinue
    $todayFile = Join-Path $auditLogPath "audit_$(Get-Date -Format 'yyyy-MM-dd').jsonl"
    $hasTodayLog = Test-Path $todayFile

    $checks = @{
        LogDirectoryExists = $true
        HasLogFiles = ($logFiles.Count -gt 0)
        HasRecentLogs = $hasTodayLog
        LogsWritable = $false
    }

    # Test write access
    try {
        $testFile = Join-Path $auditLogPath "_test_$(Get-Random).tmp"
        "test" | Out-File $testFile -ErrorAction Stop
        Remove-Item $testFile -ErrorAction SilentlyContinue
        $checks.LogsWritable = $true
    }
    catch {
        $checks.LogsWritable = $false
    }

    $passed = ($checks.Values | Where-Object { $_ }).Count
    $total = $checks.Count

    if ($passed -eq $total) {
        return @{ Status = "PASS"; Message = "Audit logging operational"; Details = $checks }
    }
    else {
        return @{ Status = "WARNING"; Message = "Audit logging issues detected"; Details = $checks }
    }
}

# Check backup compliance
function Test-BackupCompliance {
    $backupPath = "$env:RAWRXD_HOME\security\phase_g1_hotpatch\backups"

    $checks = @{
        BackupDirectoryExists = Test-Path $backupPath
        BackupDirectoryWritable = $false
        RecentBackups = $false
    }

    if ($checks.BackupDirectoryExists) {
        # Test write access
        try {
            $testFile = Join-Path $backupPath "_test_$(Get-Random).tmp"
            "test" | Out-File $testFile -ErrorAction Stop
            Remove-Item $testFile -ErrorAction SilentlyContinue
            $checks.BackupDirectoryWritable = $true
        }
        catch {
            $checks.BackupDirectoryWritable = $false
        }

        # Check for recent backups (last 7 days)
        $recentBackups = Get-ChildItem $backupPath -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
        $checks.RecentBackups = ($recentBackups.Count -gt 0)
    }

    $passed = ($checks.Values | Where-Object { $_ }).Count
    $total = $checks.Count

    if ($passed -eq $total) {
        return @{ Status = "PASS"; Message = "Backup system compliant"; Details = $checks }
    }
    else {
        return @{ Status = "WARNING"; Message = "Backup system issues detected"; Details = $checks }
    }
}

# Check encryption
function Test-EncryptionCompliance {
    # Check if sensitive files are encrypted (placeholder)
    $checks = @{
        ConfigEncrypted = $false  # Would check actual encryption
        LogsEncrypted = $false
        RegistryEncrypted = $false
    }

    # In a real implementation, check file encryption status
    # For now, mark as warning since this is a placeholder
    return @{ Status = "WARNING"; Message = "Encryption checks require manual verification"; Details = $checks }
}

# Run compliance check for a standard
function Invoke-ComplianceCheck {
    param([string]$StandardName)

    Write-ComplianceLog "Checking compliance for $StandardName..." -Level "INFO"

    $framework = $script:ComplianceFrameworks[$StandardName]
    $standardResult = @{
        Name = $framework.Name
        Description = $framework.Description
        Controls = @()
        Passed = 0
        Failed = 0
        Warning = 0
    }

    foreach ($control in $framework.Controls) {
        $controlResult = @{ Control = $control }

        # Run appropriate check based on control category
        switch -Wildcard ($control.ID) {
            "CC6.*" { $checkResult = Test-RBACCompliance }
            "CC7.*" { $checkResult = Test-AuditCompliance }
            "CC8.*" { $checkResult = Test-BackupCompliance }
            "A.5.*" { $checkResult = Test-RBACCompliance }
            "A.8.*" { $checkResult = Test-EncryptionCompliance }
            "PR.AC-*" { $checkResult = Test-RBACCompliance }
            default { $checkResult = @{ Status = "WARNING"; Message = "Check not implemented"; Details = @{} } }
        }

        $controlResult.Result = $checkResult
        $controlResult.Status = $checkResult.Status

        $standardResult.Controls += $controlResult

        switch ($checkResult.Status) {
            "PASS" { $standardResult.Passed++ }
            "FAIL" { $standardResult.Failed++ }
            "WARNING" { $standardResult.Warning++ }
        }
    }

    $standardResult.CompliancePercentage = if ($standardResult.Controls.Count -gt 0) {
        [math]::Round(($standardResult.Passed / $standardResult.Controls.Count) * 100, 2)
    } else { 0 }

    return $standardResult
}

# Show compliance report
function Show-ComplianceReport {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║              COMPLIANCE CHECK REPORT                             ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    foreach ($standard in $script:CheckResults.Standards) {
        Write-Host "Standard: $($standard.Name)" -ForegroundColor White
        Write-Host "Description: $($standard.Description)" -ForegroundColor Gray
        Write-Host ""

        Write-Host "Controls:" -ForegroundColor Yellow
        foreach ($control in $standard.Controls) {
            $color = switch ($control.Status) {
                "PASS" { "Green" }
                "FAIL" { "Red" }
                "WARNING" { "Yellow" }
                default { "White" }
            }
            $symbol = switch ($control.Status) {
                "PASS" { "✅" }
                "FAIL" { "❌" }
                "WARNING" { "⚠️" }
                default { "❓" }
            }

            Write-Host "  $symbol [$($control.Control.ID)] $($control.Control.Description)" -ForegroundColor $color
            Write-Host "     Status: $($control.Result.Message)" -ForegroundColor Gray
        }

        Write-Host ""
        Write-Host "Summary: $($standard.Passed) passed, $($standard.Failed) failed, $($standard.Warning) warnings" -ForegroundColor $(if ($standard.CompliancePercentage -ge 80) { "Green" } elseif ($standard.CompliancePercentage -ge 50) { "Yellow" } else { "Red" })
        Write-Host "Compliance: $($standard.CompliancePercentage)%" -ForegroundColor $(if ($standard.CompliancePercentage -ge 80) { "Green" } elseif ($standard.CompliancePercentage -ge 50) { "Yellow" } else { "Red" })
        Write-Host ""
        Write-Host "────────────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host ""
    }

    Write-Host "Overall Summary:" -ForegroundColor Yellow
    Write-Host "  Total Controls: $($script:CheckResults.Summary.TotalControls)" -ForegroundColor White
    Write-Host "  Passed: $($script:CheckResults.Summary.Passed)" -ForegroundColor Green
    Write-Host "  Failed: $($script:CheckResults.Summary.Failed)" -ForegroundColor Red
    Write-Host "  Warnings: $($script:CheckResults.Summary.Warning)" -ForegroundColor Yellow
    Write-Host "  Overall Compliance: $($script:CheckResults.Summary.CompliancePercentage)%" -ForegroundColor $(if ($script:CheckResults.Summary.CompliancePercentage -ge 80) { "Green" } elseif ($script:CheckResults.Summary.CompliancePercentage -ge 50) { "Yellow" } else { "Red" })
    Write-Host ""
}

# Export compliance report
function Export-ComplianceReport {
    param([string]$Format)

    switch ($Format) {
        "json" {
            $reportPath = "compliance_report_$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
            $script:CheckResults | ConvertTo-Json -Depth 10 | Out-File $reportPath -Encoding UTF8
            Write-Host "✅ Report exported to: $reportPath" -ForegroundColor Green
        }
        "html" {
            $reportPath = "compliance_report_$(Get-Date -Format 'yyyyMMdd-HHmmss').html"

            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        h2 { color: #666; border-bottom: 2px solid #ddd; padding-bottom: 10px; }
        .pass { color: green; }
        .fail { color: red; }
        .warning { color: orange; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .summary { background-color: #f9f9f9; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>RawrXD Hotpatch System - Compliance Report</h1>
    <p>Generated: $($script:CheckResults.Timestamp)</p>

    <div class="summary">
        <h2>Overall Summary</h2>
        <p><strong>Total Controls:</strong> $($script:CheckResults.Summary.TotalControls)</p>
        <p><strong>Passed:</strong> <span class="pass">$($script:CheckResults.Summary.Passed)</span></p>
        <p><strong>Failed:</strong> <span class="fail">$($script:CheckResults.Summary.Failed)</span></p>
        <p><strong>Warnings:</strong> <span class="warning">$($script:CheckResults.Summary.Warning)</span></p>
        <p><strong>Compliance:</strong> $($script:CheckResults.Summary.CompliancePercentage)%</p>
    </div>
"@

            foreach ($standard in $script:CheckResults.Standards) {
                $html += "<h2>$($standard.Name)</h2>"
                $html += "<p>$($standard.Description)</p>"
                $html += "<table><tr><th>Control</th><th>Description</th><th>Status</th><th>Message</th></tr>"

                foreach ($control in $standard.Controls) {
                    $statusClass = $control.Status.ToLower()
                    $html += "<tr><td>$($control.Control.ID)</td><td>$($control.Control.Description)</td><td class='$statusClass'>$($control.Status)</td><td>$($control.Result.Message)</td></tr>"
                }

                $html += "</table>"
            }

            $html += "</body></html>"
            $html | Out-File $reportPath -Encoding UTF8
            Write-Host "✅ Report exported to: $reportPath" -ForegroundColor Green
        }
    }
}

# Main execution
Write-Host ""
Write-Host "RawrXD Compliance Checker" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan
Write-Host ""

$standardsToCheck = if ($Standard -eq "ALL") { @("SOC2", "ISO27001", "NIST") } else { @($Standard) }

foreach ($std in $standardsToCheck) {
    $result = Invoke-ComplianceCheck -StandardName $std
    $script:CheckResults.Standards += $result

    $script:CheckResults.Summary.TotalControls += $result.Controls.Count
    $script:CheckResults.Summary.Passed += $result.Passed
    $script:CheckResults.Summary.Failed += $result.Failed
    $script:CheckResults.Summary.Warning += $result.Warning
}

$script:CheckResults.Summary.CompliancePercentage = if ($script:CheckResults.Summary.TotalControls -gt 0) {
    [math]::Round(($script:CheckResults.Summary.Passed / $script:CheckResults.Summary.TotalControls) * 100, 2)
} else { 0 }

# Output results
if ($OutputFormat -eq "console") {
    Show-ComplianceReport
}
else {
    Export-ComplianceReport -Format $OutputFormat
}

# Generate detailed report if requested
if ($GenerateReport) {
    Export-ComplianceReport -Format "html"
}

# Exit code
exit $(if ($script:CheckResults.Summary.CompliancePercentage -ge 80) { 0 } else { 1 })
