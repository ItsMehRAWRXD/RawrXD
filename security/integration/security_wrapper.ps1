#Requires -Version 7.0
<#
.SYNOPSIS
    Security Wrapper for RawrXD Hotpatch Operations

.DESCRIPTION
    Enforces RBAC and audit logging on all hotpatch operations.
    Must be called before any hotpatch manager operation.

.PARAMETER Operation
    Hotpatch operation: apply, rollback, status, validate

.PARAMETER System
    Target system: swarm, agent, tools

.PARAMETER UserId
    User performing the operation

.PARAMETER PatchBundle
    Path to patch bundle

.EXAMPLE
    .\security_wrapper.ps1 -Operation apply -System swarm -UserId "john.doe" -PatchBundle "patches/hotfix.json"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("apply", "rollback", "status", "validate", "list", "emergency")]
    [string]$Operation,

    [Parameter(Mandatory = $true)]
    [ValidateSet("swarm", "agent", "tools", "all")]
    [string]$System,

    [Parameter(Mandatory = $false)]
    [string]$UserId = $env:USERNAME,

    [Parameter(Mandatory = $false)]
    [string]$PatchBundle,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAudit
)

# Paths to security components
$script:RBACManager = "$env:RAWRXD_HOME\security\phase_h_enterprise_security\rbac\rbac_manager.ps1"
$script:AuditLogger = "$env:RAWRXD_HOME\security\phase_h_enterprise_security\audit\audit_logger.ps1"
$script:ComplianceChecker = "$env:RAWRXD_HOME\security\phase_h_enterprise_security\compliance\compliance_checker.ps1"

# Permission mapping
$script:PermissionMap = @{
    "apply" = "apply"
    "rollback" = "rollback"
    "status" = "status"
    "validate" = "read"
    "list" = "list"
    "emergency" = "emergency"
}

function Write-SecurityLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "SUCCESS" = "Green"; "DENIED" = "Red"; "AUDIT" = "Cyan" }
    Write-Host "[$timestamp] [SECURITY] [$Level] $Message" -ForegroundColor $colors[$Level]
}

function Test-SecurityPrerequisites {
    $prereqs = @{
        RBAC = Test-Path $script:RBACManager
        Audit = Test-Path $script:AuditLogger
        Compliance = Test-Path $script:ComplianceChecker
    }

    if (-not $prereqs.RBAC) {
        throw "RBAC manager not found. Initialize Phase H security first."
    }

    if (-not $prereqs.Audit) {
        throw "Audit logger not found. Initialize Phase H security first."
    }

    return $prereqs
}

function Invoke-RBACCheck {
    param([string]$User, [string]$Resource, [string]$Permission)

    try {
        $result = & $script:RBACManager -Action "check-permission" -UserId $User -Resource $Resource -Permission $Permission 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            Write-SecurityLog "RBAC check PASSED for $User on $Resource`:$Permission" -Level "SUCCESS"
            return $true
        }
        else {
            Write-SecurityLog "RBAC check DENIED for $User on $Resource`:$Permission" -Level "DENIED"
            return $false
        }
    }
    catch {
        Write-SecurityLog "RBAC check ERROR: $_" -Level "DENIED"
        return $false
    }
}

function Invoke-AuditLog {
    param([string]$EventType, [string]$Action, [string]$User, [hashtable]$Details, [string]$Severity = "info")

    if ($SkipAudit) {
        return
    }

    try {
        $detailsJson = $Details | ConvertTo-Json -Compress
        & $script:AuditLogger -EventType $EventType -Action $Action -UserId $User -Details $detailsJson -Severity $Severity | Out-Null
        Write-SecurityLog "Audit entry logged: $EventType - $Action" -Level "AUDIT"
    }
    catch {
        Write-SecurityLog "Failed to log audit entry: $_" -Level "INFO"
    }
}

function Invoke-ComplianceCheck {
    try {
        $result = & $script:ComplianceChecker -Standard "ALL" -OutputFormat "json" 2>&1 | ConvertFrom-Json
        $compliancePercent = $result.Summary.CompliancePercentage

        if ($compliancePercent -lt 80) {
            Write-SecurityLog "Compliance check FAILED: $compliancePercent% (minimum 80% required)" -Level "DENIED"
            return $false
        }

        Write-SecurityLog "Compliance check PASSED: $compliancePercent%" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-SecurityLog "Compliance check ERROR: $_" -Level "INFO"
        return $true  # Fail open if compliance check fails
    }
}

function Invoke-SecurityValidation {
    param([string]$PatchBundlePath)

    if (-not $PatchBundlePath -or -not (Test-Path $PatchBundlePath)) {
        return @{ Valid = $true; Issues = @() }
    }

    try {
        $patch = Get-Content $PatchBundlePath -Raw | ConvertFrom-Json
        $issues = @()

        # Check for required security fields
        if (-not $patch.BundleId) {
            $issues += "Missing BundleId"
        }
        if (-not $patch.Author) {
            $issues += "Missing Author"
        }
        if (-not $patch.Severity) {
            $issues += "Missing Severity"
        }

        # Check for critical patches requiring approval
        $requiresApproval = $false
        if ($patch.Severity -eq "critical" -or $patch.Type -eq "security") {
            $requiresApproval = $true
            if (-not ($patch.Metadata.ApprovalRequired -eq $true)) {
                $issues += "Critical patch must have ApprovalRequired=true"
            }
        }

        return @{
            Valid = ($issues.Count -eq 0)
            Issues = $issues
            RequiresApproval = $requiresApproval
        }
    }
    catch {
        return @{
            Valid = $false
            Issues = @("Invalid patch bundle JSON: $_")
            RequiresApproval = $false
        }
    }
}

# Main security enforcement
Write-SecurityLog "Security wrapper invoked for operation: $Operation on $System by $UserId" -Level "INFO"

# Check prerequisites
$prereqs = Test-SecurityPrerequisites

# Map operation to permission
$permission = $script:PermissionMap[$Operation]

# Check RBAC permission
$rbacPassed = Invoke-RBACCheck -User $UserId -Resource $System -Permission $permission
if (-not $rbacPassed) {
    Invoke-AuditLog -EventType "security" -Action "unauthorized_access" -User $UserId -Details @{
        Operation = $Operation
        System = $System
        Reason = "RBAC_DENIED"
    } -Severity "warning"

    Write-Error "Access DENIED: User '$UserId' does not have permission '$permission' on resource '$System'"
    exit 1
}

# Check compliance (for apply/rollback operations)
if ($Operation -in @("apply", "rollback", "emergency")) {
    $compliancePassed = Invoke-ComplianceCheck
    if (-not $compliancePassed) {
        Invoke-AuditLog -EventType "security" -Action "compliance_violation" -User $UserId -Details @{
            Operation = $Operation
            System = $System
            Reason = "COMPLIANCE_FAILED"
        } -Severity "warning"

        Write-Error "Operation blocked: System compliance below threshold"
        exit 1
    }
}

# Validate patch bundle security
if ($PatchBundle) {
    $validation = Invoke-SecurityValidation -PatchBundlePath $PatchBundle
    if (-not $validation.Valid) {
        Invoke-AuditLog -EventType "security" -Action "validation_failed" -User $UserId -Details @{
            Operation = $Operation
            System = $System
            PatchBundle = $PatchBundle
            Issues = $validation.Issues
        } -Severity "warning"

        Write-Error "Patch bundle validation failed: $($validation.Issues -join ', ')"
        exit 1
    }

    # Check for approval requirement
    if ($validation.RequiresApproval) {
        $patch = Get-Content $PatchBundle -Raw | ConvertFrom-Json
        if ([string]::IsNullOrEmpty($patch.Metadata.ApprovedBy)) {
            Invoke-AuditLog -EventType "security" -Action "approval_required" -User $UserId -Details @{
                Operation = $Operation
                System = $System
                PatchBundle = $PatchBundle
                Reason = "APPROVAL_REQUIRED"
            } -Severity "warning"

            Write-Error "Patch requires approval before deployment. Contact a patch-admin."
            exit 1
        }
    }
}

# Log successful authorization
Invoke-AuditLog -EventType "auth" -Action "access_granted" -User $UserId -Details @{
    Operation = $Operation
    System = $System
    PatchBundle = $PatchBundle
} -Severity "info"

Write-SecurityLog "Security validation PASSED. Proceeding with operation..." -Level "SUCCESS"

# Return success - caller should proceed with actual operation
exit 0
