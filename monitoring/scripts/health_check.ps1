# RawrXD System Health Check Script
# Version: 1.0.0
# Performs comprehensive health checks on all components

param(
    [switch]$Detailed,
    [switch]$JsonOutput,
    [string]$OutputFile,
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"

# Health check results
$script:HealthResults = @{
    timestamp = Get-Date -Format "o"
    overall_status = "unknown"
    checks = @()
    summary = @{
        total = 0
        passed = 0
        failed = 0
        warnings = 0
    }
}

# Helper function to add check result
function Add-HealthCheck {
    param(
        [string]$Component,
        [string]$Check,
        [string]$Status,  # pass, fail, warning
        [string]$Message,
        [hashtable]$Details = @{}
    )
    
    $result = @{
        component = $Component
        check = $Check
        status = $Status
        message = $Message
        timestamp = Get-Date -Format "o"
        details = $Details
    }
    
    $script:HealthResults.checks += $result
    $script:HealthResults.summary.total++
    
    switch ($Status) {
        "pass" { $script:HealthResults.summary.passed++ }
        "fail" { $script:HealthResults.summary.failed++ }
        "warning" { $script:HealthResults.summary.warnings++ }
    }
}

# Check 1: PowerShell Version
function Test-PowerShellVersion {
    $version = $PSVersionTable.PSVersion
    $required = [Version]"7.0"
    
    if ($version -ge $required) {
        Add-HealthCheck -Component "Environment" -Check "PowerShell Version" `
            -Status "pass" -Message "PowerShell $version is installed (required: 7.0+)"
    } else {
        Add-HealthCheck -Component "Environment" -Check "PowerShell Version" `
            -Status "fail" -Message "PowerShell $version is too old (required: 7.0+)"
    }
}

# Check 2: RBAC System
function Test-RBACSystem {
    try {
        $rbacPath = "security/phase_h_enterprise_security/rbac/rbac_manager.ps1"
        if (-not (Test-Path $rbacPath)) {
            Add-HealthCheck -Component "Security" -Check "RBAC System" `
                -Status "fail" -Message "RBAC manager not found at $rbacPath"
            return
        }
        
        # Try to get role list
        $output = & $rbacPath -Operation list 2>&1
        if ($LASTEXITCODE -eq 0) {
            Add-HealthCheck -Component "Security" -Check "RBAC System" `
                -Status "pass" -Message "RBAC system is operational"
        } else {
            Add-HealthCheck -Component "Security" -Check "RBAC System" `
                -Status "fail" -Message "RBAC system returned error: $output"
        }
    }
    catch {
        Add-HealthCheck -Component "Security" -Check "RBAC System" `
            -Status "fail" -Message "RBAC check failed: $_"
    }
}

# Check 3: Audit Logger
function Test-AuditLogger {
    try {
        $auditPath = "logs/audit"
        if (-not (Test-Path $auditPath)) {
            Add-HealthCheck -Component "Security" -Check "Audit Logger" `
                -Status "fail" -Message "Audit log directory not found: $auditPath"
            return
        }
        
        # Test write access
        $testFile = Join-Path $auditPath "health_check_$(Get-Random).tmp"
        try {
            "test" | Out-File $testFile -ErrorAction Stop
            Remove-Item $testFile -ErrorAction SilentlyContinue
            
            Add-HealthCheck -Component "Security" -Check "Audit Logger" `
                -Status "pass" -Message "Audit log directory exists and is writable"
        }
        catch {
            Add-HealthCheck -Component "Security" -Check "Audit Logger" `
                -Status "fail" -Message "Cannot write to audit log directory: $_"
        }
    }
    catch {
        Add-HealthCheck -Component "Security" -Check "Audit Logger" `
            -Status "fail" -Message "Audit logger check failed: $_"
    }
}

# Check 4: Compliance Checker
function Test-ComplianceChecker {
    try {
        $compliancePath = "security/phase_h_enterprise_security/compliance/compliance_checker.ps1"
        if (-not (Test-Path $compliancePath)) {
            Add-HealthCheck -Component "Security" -Check "Compliance Checker" `
                -Status "fail" -Message "Compliance checker not found"
            return
        }
        
        # Run compliance check
        $result = & $compliancePath -Operation check -OutputFormat json 2>&1 | ConvertFrom-Json
        
        if ($result.summary.compliance_score -ge 80) {
            Add-HealthCheck -Component "Security" -Check "Compliance" `
                -Status "pass" -Message "Compliance score: $($result.summary.compliance_score)%"
        } elseif ($result.summary.compliance_score -ge 60) {
            Add-HealthCheck -Component "Security" -Check "Compliance" `
                -Status "warning" -Message "Compliance score: $($result.summary.compliance_score)% (below 80%)"
        } else {
            Add-HealthCheck -Component "Security" -Check "Compliance" `
                -Status "fail" -Message "Compliance score: $($result.summary.compliance_score)% (critical)"
        }
    }
    catch {
        Add-HealthCheck -Component "Security" -Check "Compliance" `
            -Status "fail" -Message "Compliance check failed: $_"
    }
}

# Check 5: Patch Registry
function Test-PatchRegistry {
    try {
        $registryPath = "security/phase_g1_hotpatch/registry/patch_registry.json"
        if (-not (Test-Path $registryPath)) {
            Add-HealthCheck -Component "Hotpatch" -Check "Patch Registry" `
                -Status "fail" -Message "Patch registry not found: $registryPath"
            return
        }
        
        # Try to read registry
        $registry = Get-Content $registryPath -Raw | ConvertFrom-Json -ErrorAction Stop
        $patchCount = ($registry.patches).Count
        
        Add-HealthCheck -Component "Hotpatch" -Check "Patch Registry" `
            -Status "pass" -Message "Registry is valid with $patchCount patches" `
            -Details @{ patch_count = $patchCount }
    }
    catch {
        Add-HealthCheck -Component "Hotpatch" -Check "Patch Registry" `
            -Status "fail" -Message "Registry is corrupted: $_"
    }
}

# Check 6: Hotpatch Managers
function Test-HotpatchManagers {
    $managers = @(
        "security/phase_g1_hotpatch/swarm_hotpatch_manager.ps1",
        "security/phase_g1_hotpatch/agent_hotpatch_manager.ps1",
        "security/phase_g1_hotpatch/tools_hotpatch_manager.ps1",
        "security/phase_g1_hotpatch/unified_hotpatch_orchestrator.ps1"
    )
    
    foreach ($manager in $managers) {
        $name = Split-Path $manager -Leaf
        if (Test-Path $manager) {
            Add-HealthCheck -Component "Hotpatch" -Check $name `
                -Status "pass" -Message "$name is present"
        } else {
            Add-HealthCheck -Component "Hotpatch" -Check $name `
                -Status "fail" -Message "$name is missing"
        }
    }
}

# Check 7: Security Integration
function Test-SecurityIntegration {
    try {
        $secureHotpatch = "security/integration/secure_hotpatch.ps1"
        $securityWrapper = "security/integration/security_wrapper.ps1"
        
        $checks = @()
        if (Test-Path $secureHotpatch) { $checks += "secure_hotpatch.ps1" }
        if (Test-Path $securityWrapper) { $checks += "security_wrapper.ps1" }
        
        if ($checks.Count -eq 2) {
            Add-HealthCheck -Component "Integration" -Check "Security Integration" `
                -Status "pass" -Message "Security integration components are present"
        } else {
            Add-HealthCheck -Component "Integration" -Check "Security Integration" `
                -Status "warning" -Message "Some security integration components are missing"
        }
    }
    catch {
        Add-HealthCheck -Component "Integration" -Check "Security Integration" `
            -Status "fail" -Message "Security integration check failed: $_"
    }
}

# Check 8: Backup System
function Test-BackupSystem {
    try {
        $backupDir = "backups"
        if (-not (Test-Path $backupDir)) {
            Add-HealthCheck -Component "Hotpatch" -Check "Backup System" `
                -Status "warning" -Message "Backup directory not found: $backupDir"
            return
        }
        
        $backups = Get-ChildItem $backupDir -File | Select-Object -First 5
        $backupCount = ($backups).Count
        
        Add-HealthCheck -Component "Hotpatch" -Check "Backup System" `
            -Status "pass" -Message "Backup system ready ($backupCount recent backups)" `
            -Details @{ recent_backups = $backupCount }
    }
    catch {
        Add-HealthCheck -Component "Hotpatch" -Check "Backup System" `
            -Status "fail" -Message "Backup system check failed: $_"
    }
}

# Check 9: Documentation
function Test-Documentation {
    $docs = @(
        "docs/operations/HOTPATCH_OPERATIONS_GUIDE.md",
        "docs/runbooks/EMERGENCY_ROLLBACK_RUNBOOK.md",
        "docs/runbooks/STANDARD_PATCH_DEPLOYMENT.md"
    )
    
    $present = 0
    foreach ($doc in $docs) {
        if (Test-Path $doc) { $present++ }
    }
    
    if ($present -eq $docs.Count) {
        Add-HealthCheck -Component "Documentation" -Check "Operations Docs" `
            -Status "pass" -Message "All operational documentation is present"
    } else {
        Add-HealthCheck -Component "Documentation" -Check "Operations Docs" `
            -Status "warning" -Message "Some documentation is missing ($present/$($docs.Count))"
    }
}

# Calculate overall status
function Get-OverallStatus {
    if ($script:HealthResults.summary.failed -gt 0) {
        return "critical"
    } elseif ($script:HealthResults.summary.warnings -gt 0) {
        return "degraded"
    } else {
        return "healthy"
    }
}

# Main execution
function Invoke-HealthCheck {
    Write-Host "RawrXD System Health Check" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    
    # Run all checks
    Test-PowerShellVersion
    Test-RBACSystem
    Test-AuditLogger
    Test-ComplianceChecker
    Test-PatchRegistry
    Test-HotpatchManagers
    Test-SecurityIntegration
    Test-BackupSystem
    Test-Documentation
    
    # Calculate overall status
    $script:HealthResults.overall_status = Get-OverallStatus
    
    # Output results
    if ($JsonOutput) {
        $json = $script:HealthResults | ConvertTo-Json -Depth 10
        if ($OutputFile) {
            $json | Out-File $OutputFile
            Write-Host "Results saved to $OutputFile" -ForegroundColor Green
        } else {
            $json
        }
    } else {
        # Console output
        Write-Host ""
        Write-Host "Results Summary" -ForegroundColor Cyan
        Write-Host "---------------" -ForegroundColor Cyan
        
        foreach ($check in $script:HealthResults.checks) {
            $color = switch ($check.status) {
                "pass" { "Green" }
                "fail" { "Red" }
                "warning" { "Yellow" }
                default { "White" }
            }
            
            $icon = switch ($check.status) {
                "pass" { "✓" }
                "fail" { "✗" }
                "warning" { "⚠" }
                default { "?" }
            }
            
            Write-Host "$icon [$($check.component)] $($check.check): $($check.message)" -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Overall Status: $($script:HealthResults.overall_status.ToUpper())" -ForegroundColor $(
            switch ($script:HealthResults.overall_status) {
                "healthy" { "Green" }
                "degraded" { "Yellow" }
                "critical" { "Red" }
                default { "White" }
            }
        )
        Write-Host ""
        Write-Host "Summary: $($script:HealthResults.summary.passed) passed, $($script:HealthResults.summary.warnings) warnings, $($script:HealthResults.summary.failed) failed (total: $($script:HealthResults.summary.total))"
    }
    
    # Return exit code
    if ($script:HealthResults.summary.failed -gt 0) { return 1 }
    if ($script:HealthResults.summary.warnings -gt 0) { return 2 }
    return 0
}

# Run health check
Invoke-HealthCheck
exit $LASTEXITCODE
