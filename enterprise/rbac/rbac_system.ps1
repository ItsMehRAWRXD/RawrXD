# RawrXD RBAC System
# Phase K Batch 2/5: Role-Based Access Control
# Manages roles, permissions, and access control

param(
    [Parameter()]
    [ValidateSet("CreateRole", "DeleteRole", "ListRoles", "AssignRole", "RevokeRole", "CheckPermission", "ShowStatus")]
    [string]$Action = "ListRoles",
    
    [Parameter()]
    [string]$RoleName,
    
    [Parameter()]
    [string]$UserId,
    
    [Parameter()]
    [string]$TenantId,
    
    [Parameter()]
    [string]$Resource,
    
    [Parameter()]
    [string]$Permission,
    
    [Parameter()]
    [array]$Permissions = @(),
    
    [Parameter()]
    [string]$DataPath = "$PSScriptRoot\rbac_data",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\enterprise"
)

# Predefined roles and permissions
$RoleDefinitions = @{
    "SuperAdmin" = @{
        Description = "Full system access"
        Permissions = @("*")
        Level = 100
    }
    "TenantAdmin" = @{
        Description = "Full tenant access"
        Permissions = @("tenant:*", "user:*", "model:*", "analytics:*")
        Level = 80
    }
    "Operator" = @{
        Description = "Operational access"
        Permissions = @("model:read", "model:execute", "analytics:read", "monitoring:read")
        Level = 60
    }
    "Developer" = @{
        Description = "Development access"
        Permissions = @("model:*", "config:read", "logs:read")
        Level = 50
    }
    "Viewer" = @{
        Description = "Read-only access"
        Permissions = @("model:read", "analytics:read", "monitoring:read")
        Level = 20
    }
    "Service" = @{
        Description = "Service account access"
        Permissions = @("model:execute", "internal:*")
        Level = 10
    }
}

# Ensure directories exist
if (-not (Test-Path $DataPath)) {
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
}
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$StateFile = "$PSScriptRoot\rbac_state.json"

function Write-RBACLog {
    param([string]$Message, [string]$Level = "INFO", [string]$User = "system")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [User:$User] $Message"
    
    $logFile = Join-Path $LogPath "rbac_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "RBAC" { "Cyan" }
        "AUDIT" { "Magenta" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-RBACState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        Roles = $RoleDefinitions
        UserRoles = @{}  # UserId -> Array of RoleAssignments
        CustomRoles = @{}
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Save-RBACState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function New-CustomRole {
    param(
        [string]$Name,
        [string]$Description,
        [array]$Permissions,
        [int]$Level = 50
    )
    
    Write-RBACLog "Creating custom role: $Name" "RBAC"
    
    $state = Get-RBACState
    
    $role = @{
        Name = $Name
        Description = $Description
        Permissions = $Permissions
        Level = $Level
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Custom = $true
    }
    
    $state.CustomRoles[$Name] = $role
    Save-RBACState -State $state
    
    Write-RBACLog "Custom role created: $Name" "SUCCESS"
    return $role
}

function Remove-CustomRole {
    param([string]$Name)
    
    Write-RBACLog "Removing custom role: $Name" "RBAC"
    
    $state = Get-RBACState
    
    if ($state.CustomRoles.ContainsKey($Name)) {
        $state.CustomRoles.Remove($Name)
        Save-RBACState -State $state
        Write-RBACLog "Custom role removed: $Name" "SUCCESS"
        return $true
    }
    
    Write-RBACLog "Custom role not found: $Name" "ERROR"
    return $false
}

function Grant-UserRole {
    param(
        [string]$UserId,
        [string]$RoleName,
        [string]$TenantId = "global",
        [string]$GrantedBy = "system"
    )
    
    Write-RBACLog "Granting role $RoleName to user $UserId" "RBAC"
    
    $state = Get-RBACState
    
    # Validate role exists
    $role = $null
    if ($RoleDefinitions.ContainsKey($RoleName)) {
        $role = $RoleDefinitions[$RoleName]
    }
    elseif ($state.CustomRoles.ContainsKey($RoleName)) {
        $role = $state.CustomRoles[$RoleName]
    }
    
    if (-not $role) {
        Write-RBACLog "Role not found: $RoleName" "ERROR"
        return $false
    }
    
    # Create user entry if not exists
    if (-not $state.UserRoles.ContainsKey($UserId)) {
        $state.UserRoles[$UserId] = @()
    }
    
    # Check if already assigned
    $existing = $state.UserRoles[$UserId] | Where-Object { $_.Role -eq $RoleName -and $_.TenantId -eq $TenantId }
    if ($existing) {
        Write-RBACLog "Role already assigned to user" "WARN"
        return $false
    }
    
    # Grant role
    $assignment = @{
        Role = $RoleName
        TenantId = $TenantId
        GrantedBy = $GrantedBy
        GrantedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $state.UserRoles[$UserId] += $assignment
    Save-RBACState -State $state
    
    Write-RBACLog "Role granted: $RoleName to $UserId" "SUCCESS"
    Write-RBACLog "Role assignment: $RoleName to $UserId for tenant $TenantId" "AUDIT"
    
    return $true
}

function Revoke-UserRole {
    param(
        [string]$UserId,
        [string]$RoleName,
        [string]$TenantId = "global"
    )
    
    Write-RBACLog "Revoking role $RoleName from user $UserId" "RBAC"
    
    $state = Get-RBACState
    
    if (-not $state.UserRoles.ContainsKey($UserId)) {
        Write-RBACLog "User has no roles" "WARN"
        return $false
    }
    
    $state.UserRoles[$UserId] = $state.UserRoles[$UserId] | Where-Object { 
        -not ($_.Role -eq $RoleName -and $_.TenantId -eq $TenantId) 
    }
    
    Save-RBACState -State $state
    
    Write-RBACLog "Role revoked: $RoleName from $UserId" "SUCCESS"
    Write-RBACLog "Role revocation: $RoleName from $UserId for tenant $TenantId" "AUDIT"
    
    return $true
}

function Get-UserRoles {
    param([string]$UserId)
    
    $state = Get-RBACState
    
    if ($state.UserRoles.ContainsKey($UserId)) {
        return $state.UserRoles[$UserId]
    }
    
    return @()
}

function Get-UserPermissions {
    param([string]$UserId)
    
    $roles = Get-UserRoles -UserId $UserId
    $permissions = @()
    $state = Get-RBACState
    
    foreach ($assignment in $roles) {
        $roleName = $assignment.Role
        $role = $null
        
        if ($RoleDefinitions.ContainsKey($roleName)) {
            $role = $RoleDefinitions[$roleName]
        }
        elseif ($state.CustomRoles.ContainsKey($roleName)) {
            $role = $state.CustomRoles[$roleName]
        }
        
        if ($role) {
            $permissions += $role.Permissions
        }
    }
    
    return $permissions | Select-Object -Unique
}

function Test-UserPermission {
    param(
        [string]$UserId,
        [string]$RequiredPermission,
        [string]$TenantId = "global"
    )
    
    $permissions = Get-UserPermissions -UserId $UserId
    
    # Check for wildcard permission
    if ($permissions -contains "*") {
        return @{ Allowed = $true; Reason = $null }
    }
    
    # Check for exact permission
    if ($permissions -contains $RequiredPermission) {
        return @{ Allowed = $true; Reason = $null }
    }
    
    # Check for wildcard resource permission
    $parts = $RequiredPermission -split ":"
    if ($parts.Count -eq 2) {
        $wildcard = "$($parts[0]):*"
        if ($permissions -contains $wildcard) {
            return @{ Allowed = $true; Reason = $null }
        }
    }
    
    return @{ 
        Allowed = $false 
        Reason = "User does not have permission: $RequiredPermission"
        UserPermissions = $permissions
    }
}

function Show-RBACStatus {
    $state = Get-RBACState
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD RBAC System Status                           ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Built-in Roles: $($RoleDefinitions.Count)" -ForegroundColor Cyan
    Write-Host "║ Custom Roles: $($state.CustomRoles.Count)" -ForegroundColor Cyan
    Write-Host "║ User Assignments: $($state.UserRoles.Count)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    Write-Host "║ Built-in Roles:" -ForegroundColor Cyan
    foreach ($role in $RoleDefinitions.Keys | Sort-Object) {
        $info = $RoleDefinitions[$role]
        Write-Host "║   $role (Level $($info.Level))" -ForegroundColor Gray
        Write-Host "║     $($info.Description)" -ForegroundColor DarkGray
    }
    
    if ($state.CustomRoles.Count -gt 0) {
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║ Custom Roles:" -ForegroundColor Cyan
        foreach ($role in $state.CustomRoles.Keys) {
            Write-Host "║   $role" -ForegroundColor Gray
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "CreateRole" {
        if (-not $RoleName -or $Permissions.Count -eq 0) {
            Write-RBACLog "RoleName and Permissions required" "ERROR"
            exit 1
        }
        $role = New-CustomRole -Name $RoleName -Description "Custom role" -Permissions $Permissions
        $role | ConvertTo-Json
    }
    "DeleteRole" {
        if (-not $RoleName) {
            Write-RBACLog "RoleName required" "ERROR"
            exit 1
        }
        $success = Remove-CustomRole -Name $RoleName
        if ($success) { exit 0 } else { exit 1 }
    }
    "ListRoles" {
        $state = Get-RBACState
        $allRoles = $RoleDefinitions.Clone()
        foreach ($key in $state.CustomRoles.Keys) {
            $allRoles[$key] = $state.CustomRoles[$key]
        }
        $allRoles | ConvertTo-Json -Depth 10
    }
    "AssignRole" {
        if (-not $UserId -or -not $RoleName) {
            Write-RBACLog "UserId and RoleName required" "ERROR"
            exit 1
        }
        $success = Grant-UserRole -UserId $UserId -RoleName $RoleName -TenantId $TenantId
        if ($success) { exit 0 } else { exit 1 }
    }
    "RevokeRole" {
        if (-not $UserId -or -not $RoleName) {
            Write-RBACLog "UserId and RoleName required" "ERROR"
            exit 1
        }
        $success = Revoke-UserRole -UserId $UserId -RoleName $RoleName -TenantId $TenantId
        if ($success) { exit 0 } else { exit 1 }
    }
    "CheckPermission" {
        if (-not $UserId -or -not $Permission) {
            Write-RBACLog "UserId and Permission required" "ERROR"
            exit 1
        }
        $result = Test-UserPermission -UserId $UserId -RequiredPermission $Permission -TenantId $TenantId
        $result | ConvertTo-Json
    }
    "ShowStatus" {
        Show-RBACStatus
    }
}
