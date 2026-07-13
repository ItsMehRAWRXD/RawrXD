# RawrXD RBAC Manager
# Role-Based Access Control for Security & Hotpatch System
# Requires: PowerShell 7.0+

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("list", "get_role", "assign_role", "revoke_role", "check_permission", "get_user_role", "init")]
    [string]$Operation = "list",
    
    [string]$RoleName,
    [string]$UserId,
    [string]$Permission,
    [string]$ConfigPath = "security/rbac/rbac_config.json",
    [switch]$JsonOutput
)

$ErrorActionPreference = "Stop"

# Default RBAC Configuration
$DefaultRoles = @(
    @{
        name = "super-admin"
        level = 100
        permissions = @("*")
        inherits_from = $null
        description = "Full system access"
    },
    @{
        name = "patch-admin"
        level = 80
        permissions = @("patch:*", "rollback:*", "backup:*", "monitor:view")
        inherits_from = $null
        description = "Patch and deployment administration"
    },
    @{
        name = "patch-operator"
        level = 60
        permissions = @("patch:apply", "patch:view", "monitor:view")
        inherits_from = "patch-viewer"
        description = "Can apply patches with approval"
    },
    @{
        name = "patch-viewer"
        level = 40
        permissions = @("patch:view", "monitor:view")
        inherits_from = $null
        description = "Read-only patch access"
    },
    @{
        name = "security-auditor"
        level = 50
        permissions = @("audit:*", "compliance:*", "security:scan", "patch:view")
        inherits_from = $null
        description = "Security and compliance auditing"
    }
)

function Initialize-RBACConfig {
    param([string]$Path)
    
    $config = @{
        version = "1.0.0"
        last_updated = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        roles = $DefaultRoles
        users = @()
        audit_log = @()
    }
    
    $configDir = Split-Path $Path -Parent
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }
    
    $config | ConvertTo-Json -Depth 10 | Out-File $Path -Force
    Write-Verbose "RBAC configuration initialized at $Path"
}

function Get-RBACConfig {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        Initialize-RBACConfig -Path $Path
    }
    
    return Get-Content $Path | ConvertFrom-Json
}

function Save-RBACConfig {
    param(
        [string]$Path,
        [object]$Config
    )
    
    # Convert PSCustomObject to hashtable for modification
    $configHash = @{}
    $Config.PSObject.Properties | ForEach-Object {
        $configHash[$_.Name] = $_.Value
    }
    
    $configHash['last_updated'] = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    $configHash | ConvertTo-Json -Depth 10 | Out-File $Path -Force
}

function Get-Role {
    param(
        [array]$Roles,
        [string]$Name
    )
    
    return $Roles | Where-Object { $_.name -eq $Name } | Select-Object -First 1
}

function Get-InheritedPermissions {
    param(
        [array]$Roles,
        [string]$RoleName,
        [array]$CollectedPermissions = @()
    )
    
    $role = Get-Role -Roles $Roles -Name $RoleName
    if (-not $role) {
        return $CollectedPermissions
    }
    
    $permissions = $CollectedPermissions + $role.permissions
    
    if ($role.inherits_from) {
        return Get-InheritedPermissions -Roles $Roles -RoleName $role.inherits_from -CollectedPermissions $permissions
    }
    
    return $permissions | Select-Object -Unique
}

function Test-Permission {
    param(
        [array]$UserPermissions,
        [string]$RequiredPermission
    )
    
    # Super-admin wildcard
    if ($UserPermissions -contains "*") {
        return $true
    }
    
    # Exact match
    if ($UserPermissions -contains $RequiredPermission) {
        return $true
    }
    
    # Wildcard match (e.g., "patch:*" matches "patch:apply")
    $permissionParts = $RequiredPermission -split ":"
    if ($permissionParts.Count -eq 2) {
        $wildcardPermission = "$($permissionParts[0]):*"
        if ($UserPermissions -contains $wildcardPermission) {
            return $true
        }
    }
    
    return $false
}

function Add-AuditLogEntry {
    param(
        [object]$Config,
        [string]$Action,
        [string]$UserId,
        [string]$Details
    )
    
    $entry = [PSCustomObject]@{
        timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        action = $Action
        user_id = $UserId
        details = $Details
    }
    
    # Convert to array list for modification
    $auditList = [System.Collections.ArrayList]::new()
    if ($Config.audit_log) {
        $auditList.AddRange(@($Config.audit_log))
    }
    $auditList.Add($entry) | Out-Null
    
    # Keep only last 1000 entries
    if ($auditList.Count -gt 1000) {
        $auditList.RemoveRange(0, $auditList.Count - 1000)
    }
    
    # Update config
    $Config | Add-Member -MemberType NoteProperty -Name "audit_log" -Value $auditList.ToArray() -Force
}

# Main Operations
switch ($Operation) {
    "init" {
        Initialize-RBACConfig -Path $ConfigPath
        $result = @{ status = "success"; message = "RBAC configuration initialized" }
        if ($JsonOutput) { $result | ConvertTo-Json } else { Write-Host "✓ RBAC initialized" -ForegroundColor Green }
    }
    
    "list" {
        $config = Get-RBACConfig -Path $ConfigPath
        $result = $config.roles | ForEach-Object {
            $effectivePerms = Get-InheritedPermissions -Roles $config.roles -RoleName $_.name
            [PSCustomObject]@{
                name = $_.name
                level = $_.level
                permissions = $_.permissions
                effective_permissions = $effectivePerms
                inherits_from = $_.inherits_from
                description = $_.description
            }
        }
        if ($JsonOutput) { $result | ConvertTo-Json -Depth 5 } else { $result | Format-Table -AutoSize }
    }
    
    "get_role" {
        if (-not $RoleName) {
            throw "RoleName parameter required"
        }
        
        $config = Get-RBACConfig -Path $ConfigPath
        $role = Get-Role -Roles $config.roles -Name $RoleName
        
        if (-not $role) {
            throw "Role '$RoleName' not found"
        }
        
        $effectivePerms = Get-InheritedPermissions -Roles $config.roles -RoleName $RoleName
        $result = [PSCustomObject]@{
            name = $role.name
            level = $role.level
            permissions = $role.permissions
            effective_permissions = $effectivePerms
            inherits_from = $role.inherits_from
            description = $role.description
        }
        
        if ($JsonOutput) { $result | ConvertTo-Json -Depth 5 } else { $result | Format-List }
    }
    
    "assign_role" {
        if (-not $UserId -or -not $RoleName) {
            throw "UserId and RoleName parameters required"
        }
        
        $config = Get-RBACConfig -Path $ConfigPath
        
        # Validate role exists
        $role = Get-Role -Roles $config.roles -Name $RoleName
        if (-not $role) {
            throw "Role '$RoleName' not found"
        }
        
        # Remove existing assignment
        $config.users = $config.users | Where-Object { $_.user_id -ne $UserId }
        
        # Add new assignment
        $assignment = @{
            user_id = $UserId
            role = $RoleName
            assigned_at = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            assigned_by = $env:USERNAME
        }
        
        $config.users += $assignment
        Add-AuditLogEntry -Config $config -Action "assign_role" -UserId $UserId -Details "Assigned role: $RoleName"
        Save-RBACConfig -Path $ConfigPath -Config $config
        
        $result = @{ status = "success"; user_id = $UserId; role = $RoleName }
        if ($JsonOutput) { $result | ConvertTo-Json } else { Write-Host "✓ Role '$RoleName' assigned to user '$UserId'" -ForegroundColor Green }
    }
    
    "revoke_role" {
        if (-not $UserId) {
            throw "UserId parameter required"
        }
        
        $config = Get-RBACConfig -Path $ConfigPath
        $existing = $config.users | Where-Object { $_.user_id -eq $UserId } | Select-Object -First 1
        
        if (-not $existing) {
            throw "User '$UserId' has no role assignment"
        }
        
        $config.users = $config.users | Where-Object { $_.user_id -ne $UserId }
        Add-AuditLogEntry -Config $config -Action "revoke_role" -UserId $UserId -Details "Revoked role: $($existing.role)"
        Save-RBACConfig -Path $ConfigPath -Config $config
        
        $result = @{ status = "success"; user_id = $UserId; revoked_role = $existing.role }
        if ($JsonOutput) { $result | ConvertTo-Json } else { Write-Host "✓ Role revoked from user '$UserId'" -ForegroundColor Green }
    }
    
    "get_user_role" {
        if (-not $UserId) {
            throw "UserId parameter required"
        }
        
        $config = Get-RBACConfig -Path $ConfigPath
        $assignment = $config.users | Where-Object { $_.user_id -eq $UserId } | Select-Object -First 1
        
        if (-not $assignment) {
            $result = @{ user_id = $UserId; role = $null; assigned_at = $null }
        } else {
            $role = Get-Role -Roles $config.roles -Name $assignment.role
            $effectivePerms = Get-InheritedPermissions -Roles $config.roles -RoleName $assignment.role
            $result = [PSCustomObject]@{
                user_id = $UserId
                role = $assignment.role
                role_level = $role.level
                permissions = $effectivePerms
                assigned_at = $assignment.assigned_at
                assigned_by = $assignment.assigned_by
            }
        }
        
        if ($JsonOutput) { $result | ConvertTo-Json -Depth 5 } else { $result | Format-List }
    }
    
    "check_permission" {
        if (-not $UserId -or -not $Permission) {
            throw "UserId and Permission parameters required"
        }
        
        $config = Get-RBACConfig -Path $ConfigPath
        $assignment = $config.users | Where-Object { $_.user_id -eq $UserId } | Select-Object -First 1
        
        if (-not $assignment) {
            $result = @{ user_id = $UserId; permission = $Permission; granted = $false; reason = "No role assigned" }
        } else {
            $effectivePerms = Get-InheritedPermissions -Roles $config.roles -RoleName $assignment.role
            $granted = Test-Permission -UserPermissions $effectivePerms -RequiredPermission $Permission
            $result = [PSCustomObject]@{
                user_id = $UserId
                permission = $Permission
                granted = $granted
                role = $assignment.role
                effective_permissions = $effectivePerms
            }
        }
        
        Add-AuditLogEntry -Config $config -Action "check_permission" -UserId $UserId -Details "Permission '$Permission': $($result.granted)"
        Save-RBACConfig -Path $ConfigPath -Config $config
        
        if ($JsonOutput) { $result | ConvertTo-Json -Depth 5 } else { 
            if ($result.granted) {
                Write-Host "✓ Permission granted" -ForegroundColor Green
            } else {
                Write-Host "✗ Permission denied" -ForegroundColor Red
            }
            $result | Format-List
        }
    }
}