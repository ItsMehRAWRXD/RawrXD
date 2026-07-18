#Requires -Version 7.0
<#
.SYNOPSIS
    Secure Hotpatch Operations with RBAC and Audit Logging

.DESCRIPTION
    Wrapper script that enforces security on all hotpatch operations.
    Replaces direct calls to hotpatch managers.

.PARAMETER Action
    Operation: apply, rollback, status, validate, list

.PARAMETER System
    Target system: swarm, agent, tools, all

.PARAMETER PatchBundle
    Path to patch bundle (for apply/validate)

.PARAMETER Target
    Specific target within system

.PARAMETER AgentId
    Specific agent ID (for agent operations)

.PARAMETER DryRun
    Perform dry-run only

.PARAMETER Force
    Skip confirmation prompts

.EXAMPLE
    .\secure_hotpatch.ps1 -Action apply -System swarm -PatchBundle "patches/hotfix.json"
    .\secure_hotpatch.ps1 -Action status -System all
    .\secure_hotpatch.ps1 -Action rollback -System agent -Target worker -AgentId "agent-001"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("apply", "rollback", "status", "validate", "list", "emergency")]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [ValidateSet("swarm", "agent", "tools", "all")]
    [string]$System,

    [Parameter(Mandatory = $false)]
    [string]$PatchBundle,

    [Parameter(Mandatory = $false)]
    [string]$Target = "all",

    [Parameter(Mandatory = $false)]
    [string]$AgentId,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# Paths
$script:SecurityWrapper = "$env:RAWRXD_HOME\security\integration\security_wrapper.ps1"
$script:UnifiedOrchestrator = "$env:RAWRXD_HOME\security\phase_g1_hotpatch\unified_hotpatch_orchestrator.ps1"
$script:SwarmManager = "$env:RAWRXD_HOME\security\phase_g1_hotpatch\swarm_hotpatch_manager.ps1"
$script:AgentManager = "$env:RAWRXD_HOME\security\phase_g1_hotpatch\agent_hotpatch_manager.ps1"
$script:ToolsManager = "$env:RAWRXD_HOME\security\phase_g1_hotpatch\tools_hotpatch_manager.ps1"
$script:AuditLogger = "$env:RAWRXD_HOME\security\phase_h_enterprise_security\audit\audit_logger.ps1"

function Write-SecureLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "SUCCESS" = "Green"; "ERROR" = "Red"; "WARN" = "Yellow" }
    Write-Host "[$timestamp] [SECURE] [$Level] $Message" -ForegroundColor $colors[$Level]
}

function Invoke-SecurityCheck {
    # Run security wrapper
    $securityArgs = @{
        Operation = $Action
        System = $System
        UserId = $env:USERNAME
    }

    if ($PatchBundle) {
        $securityArgs.PatchBundle = $PatchBundle
    }

    $argList = @()
    foreach ($key in $securityArgs.Keys) {
        $value = $securityArgs[$key]
        if ($value -is [switch]) {
            if ($value) { $argList += "-$key" }
        }
        else {
            $argList += "-$key `"$value`""
        }
    }

    $securityCommand = "& `"$script:SecurityWrapper`" $argList"
    $result = Invoke-Expression $securityCommand 2>&1
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        Write-SecureLog "Security check FAILED" -Level "ERROR"
        Write-Error $result
        return $false
    }

    Write-SecureLog "Security check PASSED" -Level "SUCCESS"
    return $true
}

function Invoke-HotpatchOperation {
    param([hashtable]$Params)

    $startTime = Get-Date
    $success = $false
    $errorMessage = $null

    try {
        # Determine which manager to use
        $manager = $null
        $managerArgs = @{ Action = $Action }

        switch ($System) {
            "swarm" {
                $manager = $script:SwarmManager
                $managerArgs.Target = $Target
                if ($PatchBundle) { $managerArgs.PatchFile = $PatchBundle }
            }
            "agent" {
                $manager = $script:AgentManager
                $managerArgs.Target = $Target
                if ($AgentId) { $managerArgs.AgentId = $AgentId }
                if ($PatchBundle) { $managerArgs.PatchFile = $PatchBundle }
            }
            "tools" {
                $manager = $script:ToolsManager
                $managerArgs.Target = $Target
                if ($PatchBundle) { $managerArgs.PatchFile = $PatchBundle }
            }
            "all" {
                $manager = $script:UnifiedOrchestrator
                $managerArgs.System = "all"
                if ($PatchBundle) { $managerArgs.PatchBundle = $PatchBundle }
            }
        }

        if ($DryRun) { $managerArgs.DryRun = $true }
        if ($Force) { $managerArgs.Force = $true }

        # Build argument list
        $argList = @()
        foreach ($key in $managerArgs.Keys) {
            $value = $managerArgs[$key]
            if ($value -is [switch]) {
                if ($value) { $argList += "-$key" }
            }
            else {
                $argList += "-$key `"$value`""
            }
        }

        Write-SecureLog "Executing: $([System.IO.Path]::GetFileName($manager)) $argList" -Level "INFO"

        # Execute operation
        $operationCommand = "& `"$manager`" $argList"
        Invoke-Expression $operationCommand

        if ($LASTEXITCODE -eq 0) {
            $success = $true
            Write-SecureLog "Operation completed successfully" -Level "SUCCESS"
        }
        else {
            throw "Operation failed with exit code $LASTEXITCODE"
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-SecureLog "Operation failed: $errorMessage" -Level "ERROR"
        $success = $false
    }

    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds

    # Log to audit
    if (Test-Path $script:AuditLogger) {
        $auditDetails = @{
            Action = $Action
            System = $System
            Target = $Target
            PatchBundle = $PatchBundle
            Success = $success
            Duration = $duration
            Error = $errorMessage
        } | ConvertTo-Json -Compress

        $severity = if ($success) { "info" } else { "error" }
        & $script:AuditLogger -EventType "patch" -Action $Action -UserId $env:USERNAME -Details $auditDetails -Severity $severity | Out-Null
    }

    return $success
}

# Main execution
Write-SecureLog "Secure hotpatch operation initiated" -Level "INFO"
Write-SecureLog "Action: $Action, System: $System, User: $env:USERNAME" -Level "INFO"

# Step 1: Security check
$securityPassed = Invoke-SecurityCheck
if (-not $securityPassed) {
    Write-SecureLog "Operation aborted due to security check failure" -Level "ERROR"
    exit 1
}

# Step 2: Confirmation (unless -Force)
if (-not $Force -and $Action -in @("apply", "rollback", "emergency")) {
    $confirmMessage = switch ($Action) {
        "apply" { "Apply patch to $System" }
        "rollback" { "Rollback patch on $System" }
        "emergency" { "EMERGENCY operation on $System" }
    }

    Write-Host ""
    Write-Host "⚠️  $confirmMessage" -ForegroundColor Yellow
    $confirm = Read-Host "Type 'yes' to confirm"
    if ($confirm -ne "yes") {
        Write-SecureLog "Operation cancelled by user" -Level "WARN"
        exit 0
    }
}

# Step 3: Execute operation
$success = Invoke-HotpatchOperation -Params $PSBoundParameters

# Exit with appropriate code
exit $(if ($success) { 0 } else { 1 })
