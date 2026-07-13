#Requires -Version 7.0
<#
.SYNOPSIS
    Role-Based Access Control (RBAC) Manager for RawrXD Hotpatch System

.DESCRIPTION
    Manages user roles, permissions, and access control for enterprise deployments.

.PARAMETER Action
    Action to perform: init, user-add, user-remove, role-assign, role-revoke, check-permission, list-users, list-roles

.PARAMETER UserId
    User identifier

.PARAMETER Role
    Role to assign/revoke

.PARAMETER Resource
    Resource to check permission for

.PARAMETER Permission
    Permission to check

.EXAMPLE
    .\rbac_manager.ps1 -Action init
    .\rbac_manager.ps1 -Action user-add -UserId "john.doe" -Role "patch-operator"
    .\rbac_manager.ps1 -Action check-permission -UserId "john.doe" -Resource "swarm" -Permission "apply"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("init", "user-add", "user-remove", "role-assign", "role-revoke", "check-permission", "list-users", "list-roles", "audit")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [string]$UserId,

    [Parameter(Mandatory = $false)]
    [string]$Role,

    [Parameter(Mandatory = $false)]
    [string]$Resource,

    [Parameter(Mandatory = $false)]
    [string]$Permission,

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "$env:RAWRXD_HOME\security\phase_h_enterprise_security\rbac\rbac_config.json"
)

# Role definitions with permissions
$script:RoleDefinitions = @{
    "super-admin" = @{
        Description = "Full system access"
        Permissions = @("*:*")
        Level = 100
    }
    "patch-admin" = @{
        Description = "Patch system administration"
        Permissions = @(
            "swarm:*",
            "agent:*",
            "tools:*",
            "registry:*",
            "monitoring:read"
        )
        Level = 80
    }
    "patch-operator" = @{
        Description = "Can apply and rollback patches"
        Permissions = @(
            "swarm:apply", "swarm:rollback", "swarm:status",
            "agent:apply", "agent:rollback", "agent:status",
            "tools:apply", "tools:rollback", "tools:status",
            "registry:read",
            "monitoring:read"
        )
        Level = 60
    }
    "patch-viewer" = @{
        Description = "Read-only access to patch system"
        Permissions = @(
            "swarm:status", "swarm:list",
            "agent:status", "agent:list",
            "tools:status", "tools:list",
            "registry:read",
            "monitoring:read"
        )
        Level = 40
    }
    "security-auditor" = @{
        Description = "Security audit access"
        Permissions = @(
            "audit:read",
            "compliance:read",
            "rbac:audit",
            "monitoring:read"
        )
        Level = 50
    }
}

# Initialize RBAC system
function Initialize-RBAC {
    if (-not (Test-Path $ConfigPath)) {
        $rbacConfig = @{
            Version = "1.0.0"
            CreatedAt = Get-Date -Format "o"
            UpdatedAt = Get-Date -Format "o"
            Roles = $script:RoleDefinitions
            Users = @{
                # Built-in system user
                "system" = @{
                    Roles = @("super-admin")
                    CreatedAt = Get-Date -Format "o"
                    CreatedBy = "system"
                    LastLogin = $null
                }
            }
            AuditLog = @()
        }

        $configDir = Split-Path -Parent $ConfigPath
        if (-not (Test-Path $configDir)) {
            New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        }

        $rbacConfig | ConvertTo-Json -Depth 10 | Out-File $ConfigPath -Encoding UTF8
        Write-Host "✅ RBAC system initialized at $ConfigPath" -ForegroundColor Green
    }
    else {
        Write-Host "ℹ️  RBAC system already initialized" -ForegroundColor Yellow
    }
}

# Load RBAC configuration
function Get-RBACConfig {
    if (-not (Test-Path $ConfigPath)) {
        Initialize-RBAC
    }
    return Get-Content $ConfigPath -Raw | ConvertFrom-Json
}

# Save RBAC configuration
function Save-RBACConfig {
    param([hashtable]$Config)
    $Config.UpdatedAt = Get-Date -Format "o"
    $Config | ConvertTo-Json -Depth 10 | Out-File $ConfigPath -Encoding UTF8
}

# Add audit entry
function Add-AuditEntry {
    param([hashtable]$Config, [string]$Action, [string]$UserId, [hashtable]$Details)
    $Config.AuditLog += @{
        Timestamp = Get-Date -Format "o"
        Action = $Action
        UserId = $UserId
        PerformedBy = $env:USERNAME
        Details = $Details
    }

    # Keep only last 10000 entries
    if ($Config.AuditLog.Count -gt 10000) {
        $Config.AuditLog = $Config.AuditLog | Select-Object -Last 10000
    }
}

# Add user
function Add-User {
    param([string]$Id, [string]$InitialRole)

    $config = Get-RBACConfig

    if ($config.Users.PSObject.Properties.Name -contains $Id) {
        Write-Error "User '$Id' already exists"
        return $false
    }

    $config.Users | Add-Member -NotePropertyName $Id -NotePropertyValue @{
        Roles = @($InitialRole)
        CreatedAt = Get-Date -Format "o"
        CreatedBy = $env:USERNAME
        LastLogin = $null
    }

    Add-AuditEntry -Config $config -Action "user-add" -UserId $Id -Details @{ Role = $InitialRole }
    Save-RBACConfig -Config $config

    Write-Host "✅ User '$Id' added with role '$InitialRole'" -ForegroundColor Green
    return $true
}

# Remove user
function Remove-User {
    param([string]$Id)

    $config = Get-RBACConfig

    if (-not ($config.Users.PSObject.Properties.Name -contains $Id)) {
        Write-Error "User '$Id' not found"
        return $false
    }

    $config.Users.PSObject.Properties.Remove($Id)

    Add-AuditEntry -Config $config -Action "user-remove" -UserId $Id -Details @{}
    Save-RBACConfig -Config $config

    Write-Host "✅ User '$Id' removed" -ForegroundColor Green
    return $true
}

# Assign role to user
function Assign-Role {
    param([string]$Id, [string]$RoleName)

    $config = Get-RBACConfig

    if (-not ($config.Users.PSObject.Properties.Name -contains $Id)) {
        Write-Error "User '$Id' not found"
        return $false
    }

    if (-not ($config.Roles.PSObject.Properties.Name -contains $RoleName)) {
        Write-Error "Role '$RoleName' not found"
        return $false
    }

    $user = $config.Users.$Id
    if ($user.Roles -notcontains $RoleName) {
        $user.Roles += $RoleName

        Add-AuditEntry -Config $config -Action "role-assign" -UserId $Id -Details @{ Role = $RoleName }
        Save-RBACConfig -Config $config

        Write-Host "✅ Role '$RoleName' assigned to user '$Id'" -ForegroundColor Green
    }
    else {
        Write-Host "ℹ️  User '$Id' already has role '$RoleName'" -ForegroundColor Yellow
    }

    return $true
}

# Revoke role from user
function Revoke-Role {
    param([string]$Id, [string]$RoleName)

    $config = Get-RBACConfig

    if (-not ($config.Users.PSObject.Properties.Name -contains $Id)) {
        Write-Error "User '$Id' not found"
        return $false
    }

    $user = $config.Users.$Id
    if ($user.Roles -contains $RoleName) {
        $user.Roles = @($user.Roles | Where-Object { $_ -ne $RoleName })

        Add-AuditEntry -Config $config -Action "role-revoke" -UserId $Id -Details @{ Role = $RoleName }
        Save-RBACConfig -Config $config

        Write-Host "✅ Role '$RoleName' revoked from user '$Id'" -ForegroundColor Green
    }
    else {
        Write-Host "ℹ️  User '$Id' does not have role '$RoleName'" -ForegroundColor Yellow
    }

    return $true
}

# Check permission
function Test-Permission {
    param([string]$Id, [string]$Resource, [string]$Permission)

    $config = Get-RBACConfig

    if (-not ($config.Users.PSObject.Properties.Name -contains $Id)) {
        return $false
    }

    $user = $config.Users.$Id
    $hasPermission = $false

    foreach ($roleName in $user.Roles) {
        $role = $config.Roles.$roleName

        foreach ($perm in $role.Permissions) {
            # Check for wildcard permission
            if ($perm -eq "*:*") {
                $hasPermission = $true
                break
            }

            # Check for resource wildcard
            if ($perm -eq "$Resource:*") {
                $hasPermission = $true
                break
            }

            # Check for exact permission
            if ($perm -eq "$Resource:$Permission") {
                $hasPermission = $true
                break
            }
        }

        if ($hasPermission) { break }
    }

    return $hasPermission
}

# List users
function Get-Users {
    $config = Get-RBACConfig

    Write-Host ""
    Write-Host "Users:" -ForegroundColor Cyan
    Write-Host "------" -ForegroundColor Gray

    foreach ($userProp in $config.Users.PSObject.Properties) {
        $user = $userProp.Value
        Write-Host "User: $($userProp.Name)" -ForegroundColor White
        Write-Host "  Roles: $($user.Roles -join ', ')" -ForegroundColor Gray
        Write-Host "  Created: $($user.CreatedAt)" -ForegroundColor Gray
        if ($user.LastLogin) {
            Write-Host "  Last Login: $($user.LastLogin)" -ForegroundColor Gray
        }
        Write-Host ""
    }
}

# List roles
function Get-Roles {
    $config = Get-RBACConfig

    Write-Host ""
    Write-Host "Roles:" -ForegroundColor Cyan
    Write-Host "------" -ForegroundColor Gray

    foreach ($roleProp in $config.Roles.PSObject.Properties | Sort-Object { $_.Value.Level } -Descending) {
        $role = $roleProp.Value
        Write-Host "Role: $($roleProp.Name) (Level: $($role.Level))" -ForegroundColor White
        Write-Host "  Description: $($role.Description)" -ForegroundColor Gray
        Write-Host "  Permissions:" -ForegroundColor Gray
        foreach ($perm in $role.Permissions) {
            Write-Host "    - $perm" -ForegroundColor DarkGray
        }
        Write-Host ""
    }
}

# Show audit log
function Get-AuditLog {
    param([int]$Limit = 50)

    $config = Get-RBACConfig

    Write-Host ""
    Write-Host "Audit Log (last $Limit entries):" -ForegroundColor Cyan
    Write-Host "--------------------------------" -ForegroundColor Gray

    $entries = $config.AuditLog | Select-Object -Last $Limit
    foreach ($entry in $entries) {
        Write-Host "[$($entry.Timestamp)] $($entry.Action)" -ForegroundColor White -NoNewline
        if ($entry.UserId) {
            Write-Host " - User: $($entry.UserId)" -ForegroundColor Gray -NoNewline
        }
        Write-Host ""
    }
}

# Main execution
switch ($Action) {
    "init" {
        Initialize-RBAC
    }
    "user-add" {
        if (-not $UserId -or -not $Role) {
            Write-Error "UserId and Role parameters required"
            exit 1
        }
        $success = Add-User -Id $UserId -InitialRole $Role
        exit $(if ($success) { 0 } else { 1 })
    }
    "user-remove" {
        if (-not $UserId) {
            Write-Error "UserId parameter required"
            exit 1
        }
        $success = Remove-User -Id $UserId
        exit $(if ($success) { 0 } else { 1 })
    }
    "role-assign" {
        if (-not $UserId -or -not $Role) {
            Write-Error "UserId and Role parameters required"
            exit 1
        }
        $success = Assign-Role -Id $UserId -RoleName $Role
        exit $(if ($success) { 0 } else { 1 })
    }
    "role-revoke" {
        if (-not $UserId -or -not $Role) {
            Write-Error "UserId and Role parameters required"
            exit 1
        }
        $success = Revoke-Role -Id $UserId -RoleName $Role
        exit $(if ($success) { 0 } else { 1 })
    }
    "check-permission" {
        if (-not $UserId -or -not $Resource -or -not $Permission) {
            Write-Error "UserId, Resource, and Permission parameters required"
            exit 1
        }
        $hasPermission = Test-Permission -Id $UserId -Resource $Resource -Permission $Permission
        if ($hasPermission) {
            Write-Host "✅ User '$UserId' HAS permission '$Resource:$Permission'" -ForegroundColor Green
            exit 0
        }
        else {
            Write-Host "❌ User '$UserId' DOES NOT HAVE permission '$Resource:$Permission'" -ForegroundColor Red
            exit 1
        }
    }
    "list-users" {
        Get-Users
    }
    "list-roles" {
        Get-Roles
    }
    "audit" {
        Get-AuditLog
    }
}
