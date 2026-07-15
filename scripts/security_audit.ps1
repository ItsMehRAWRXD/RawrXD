#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Security Audit Script for RawrXD

.DESCRIPTION
    Performs comprehensive security audit of RawrXD installation,
    including file permissions, configuration checks, and vulnerability scanning.

.EXAMPLE
    .\security_audit.ps1 -OutputPath audit_report.json
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = "security_audit_report.json",

    [Parameter()]
    [string]$ConfigPath = "config/security.json",

    [Parameter()]
    [switch]$Detailed
)

# Audit configuration
$AuditConfig = @{
    Version = "1.0.0"
    Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    Checks = @(
        "file_permissions"
        "config_security"
        "api_keys"
        "ssl_tls"
        "audit_logging"
        "rate_limits"
        "input_validation"
    )
}

# Results collection
$AuditResults = @{
    Summary = @{
        TotalChecks = 0
        Passed = 0
        Failed = 0
        Warnings = 0
        Score = 0
    }
    Checks = @()
    Recommendations = @()
}

function Write-AuditStatus {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Pass = "Green"; Warning = "Yellow"; Fail = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Test-FilePermissions {
    Write-AuditStatus "Checking file permissions..." "Info"
    
    $result = @{
        Name = "File Permissions"
        Status = "Pass"
        Details = @()
        Issues = @()
    }
    
    # Check config directory permissions
    $configDir = "config"
    if (Test-Path $configDir) {
        $acl = Get-Acl $configDir
        $accessRules = $acl.Access | Where-Object { 
            $_.IdentityReference -notmatch "^(SYSTEM|Administrators|Users)$" 
        }
        
        if ($accessRules) {
            $result.Status = "Warning"
            $result.Issues += "Config directory has non-standard permissions"
        }
        
        $result.Details += "Config directory exists and is accessible"
    } else {
        $result.Status = "Fail"
        $result.Issues += "Config directory not found"
    }
    
    # Check log directory permissions
    $logDir = "logs"
    if (Test-Path $logDir) {
        $result.Details += "Log directory exists"
    } else {
        $result.Status = "Warning"
        $result.Issues += "Log directory not found (will be created)"
    }
    
    # Check for world-writable files
    $worldWritable = Get-ChildItem -Recurse -File | Where-Object { 
        $_.Mode -match "w.$"
    }
    
    if ($worldWritable) {
        $result.Status = "Warning"
        $result.Issues += "Found $($worldWritable.Count) world-writable files"
    }
    
    return $result
}

function Test-ConfigSecurity {
    Write-AuditStatus "Checking configuration security..." "Info"
    
    $result = @{
        Name = "Configuration Security"
        Status = "Pass"
        Details = @()
        Issues = @()
    }
    
    # Check if security config exists
    if (Test-Path $ConfigPath) {
        try {
            $config = Get-Content $ConfigPath | ConvertFrom-Json
            
            # Check authentication settings
            if ($config.require_authentication -eq $false) {
                $result.Status = "Warning"
                $result.Issues += "Authentication is disabled"
            } else {
                $result.Details += "Authentication is enabled"
            }
            
            # Check encryption settings
            if ($config.require_encryption -eq $false) {
                $result.Status = "Warning"
                $result.Issues += "Encryption is disabled"
            } else {
                $result.Details += "Encryption is enabled"
            }
            
            # Check audit logging
            if ($config.audit_all_requests -eq $false) {
                $result.Status = "Warning"
                $result.Issues += "Audit logging is disabled"
            } else {
                $result.Details += "Audit logging is enabled"
            }
            
        } catch {
            $result.Status = "Fail"
            $result.Issues += "Failed to parse security configuration: $_"
        }
    } else {
        $result.Status = "Fail"
        $result.Issues += "Security configuration file not found"
    }
    
    return $result
}

function Test-ApiKeys {
    Write-AuditStatus "Checking API key security..." "Info"
    
    $result = @{
        Name = "API Key Security"
        Status = "Pass"
        Details = @()
        Issues = @()
    }
    
    # Check for hardcoded keys in source
    $sourceFiles = Get-ChildItem -Recurse -Include "*.cpp", "*.hpp", "*.h", "*.c", "*.py", "*.js", "*.ps1"
    $suspiciousPatterns = @("api_key", "apikey", "secret_key", "password", "token")
    
    $foundIssues = $false
    foreach ($file in $sourceFiles) {
        $content = Get-Content $file.FullName -Raw
        foreach ($pattern in $suspiciousPatterns) {
            if ($content -match "$pattern\s*=\s*[\"'][^\"']+[\"']") {
                if (-not $foundIssues) {
                    $result.Status = "Warning"
                    $foundIssues = $true
                }
                $result.Issues += "Potential hardcoded credential in $($file.Name)"
            }
        }
    }
    
    if (-not $foundIssues) {
        $result.Details += "No hardcoded credentials detected"
    }
    
    return $result
}

function Test-SslTls {
    Write-AuditStatus "Checking SSL/TLS configuration..." "Info"
    
    $result = @{
        Name = "SSL/TLS Configuration"
        Status = "Pass"
        Details = @()
        Issues = @()
    }
    
    # Check for SSL certificates
    $certPaths = @(
        "config/server.crt",
        "config/server.key",
        "ssl/server.crt",
        "certs/server.crt"
    )
    
    $certFound = $false
    foreach ($path in $certPaths) {
        if (Test-Path $path) {
            $certFound = $true
            $result.Details += "SSL certificate found: $path"
            
            # Check certificate expiration
            try {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($path)
                $daysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
                
                if ($daysUntilExpiry -lt 30) {
                    $result.Status = "Warning"
                    $result.Issues += "Certificate expires in $daysUntilExpiry days"
                } else {
                    $result.Details += "Certificate valid for $daysUntilExpiry days"
                }
            } catch {
                $result.Status = "Warning"
                $result.Issues += "Could not verify certificate: $path"
            }
            break
        }
    }
    
    if (-not $certFound) {
        $result.Status = "Warning"
        $result.Issues += "No SSL certificates found"
    }
    
    return $result
}

function Test-AuditLogging {
    Write-AuditStatus "Checking audit logging..." "Info"
    
    $result = @{
        Name = "Audit Logging"
        Status = "Pass"
        Details = @()
        Issues = @()
    }
    
    # Check audit log directory
    $auditLogDir = "logs/audit"
    if (Test-Path $auditLogDir) {
        $logFiles = Get-ChildItem $auditLogDir -Filter "*.log"
        $result.Details += "Audit log directory exists with $($logFiles.Count) log files"
        
        # Check log file sizes
        $largeLogs = $logFiles | Where-Object { $_.Length -gt 100MB }
        if ($largeLogs) {
            $result.Status = "Warning"
            $result.Issues += "Found $($largeLogs.Count) large audit log files (>100MB)"
        }
    } else {
        $result.Status = "Warning"
        $result.Issues += "Audit log directory not found"
    }
    
    return $result
}

function Test-RateLimits {
    Write-AuditStatus "Checking rate limiting configuration..." "Info"
    
    $result = @{
        Name = "Rate Limiting"
        Status = "Pass"
        Details = @()
        Issues = @()
    }
    
    if (Test-Path $ConfigPath) {
        try {
            $config = Get-Content $ConfigPath | ConvertFrom-Json
            
            if ($config.rate_limits) {
                $result.Details += "Rate limiting is configured"
                
                if ($config.rate_limits.max_requests_per_minute -lt 60) {
                    $result.Status = "Warning"
                    $result.Issues += "Rate limit may be too restrictive"
                }
            } else {
                $result.Status = "Warning"
                $result.Issues += "Rate limits not configured"
            }
        } catch {
            $result.Status = "Fail"
            $result.Issues += "Failed to check rate limits"
        }
    }
    
    return $result
}

function Test-InputValidation {
    Write-AuditStatus "Checking input validation..." "Info"
    
    $result = @{
        Name = "Input Validation"
        Status = "Pass"
        Details = @()
        Issues = @()
    }
    
    if (Test-Path $ConfigPath) {
        try {
            $config = Get-Content $ConfigPath | ConvertFrom-Json
            
            if ($config.enable_input_validation -eq $true) {
                $result.Details += "Input validation is enabled"
            } else {
                $result.Status = "Warning"
                $result.Issues += "Input validation is disabled"
            }
            
            if ($config.enable_output_filtering -eq $true) {
                $result.Details += "Output filtering is enabled"
            } else {
                $result.Status = "Warning"
                $result.Issues += "Output filtering is disabled"
            }
        } catch {
            $result.Status = "Fail"
            $result.Issues += "Failed to check input validation settings"
        }
    }
    
    return $result
}

# Main execution
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD Security Audit" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Run all checks
$checks = @(
    (Test-FilePermissions)
    (Test-ConfigSecurity)
    (Test-ApiKeys)
    (Test-SslTls)
    (Test-AuditLogging)
    (Test-RateLimits)
    (Test-InputValidation)
)

$AuditResults.Checks = $checks

# Calculate summary
$AuditResults.Summary.TotalChecks = $checks.Count
$AuditResults.Summary.Passed = ($checks | Where-Object { $_.Status -eq "Pass" }).Count
$AuditResults.Summary.Failed = ($checks | Where-Object { $_.Status -eq "Fail" }).Count
$AuditResults.Summary.Warnings = ($checks | Where-Object { $_.Status -eq "Warning" }).Count
$AuditResults.Summary.Score = [math]::Round(($AuditResults.Summary.Passed / $checks.Count) * 100)

# Generate recommendations
foreach ($check in $checks) {
    foreach ($issue in $check.Issues) {
        $AuditResults.Recommendations += @{
            Category = $check.Name
            Issue = $issue
            Severity = if ($check.Status -eq "Fail") { "High" } else { "Medium" }
        }
    }
}

# Output results
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Audit Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Checks:  $($AuditResults.Summary.TotalChecks)" -ForegroundColor White
Write-Host "Passed:        $($AuditResults.Summary.Passed)" -ForegroundColor Green
Write-Host "Failed:        $($AuditResults.Summary.Failed)" -ForegroundColor Red
Write-Host "Warnings:      $($AuditResults.Summary.Warnings)" -ForegroundColor Yellow
Write-Host "Score:         $($AuditResults.Summary.Score)%" -ForegroundColor $(if ($AuditResults.Summary.Score -ge 80) { "Green" } elseif ($AuditResults.Summary.Score -ge 60) { "Yellow" } else { "Red" })

# Save report
$AuditResults.Config = $AuditConfig
$AuditResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "`nReport saved to: $OutputPath" -ForegroundColor Green

# Exit with appropriate code
if ($AuditResults.Summary.Failed -gt 0) {
    exit 1
} elseif ($AuditResults.Summary.Warnings -gt 0) {
    exit 2
} else {
    exit 0
}
