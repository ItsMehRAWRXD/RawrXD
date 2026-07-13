# RawrXD RBAC Quick Start Example
# This script demonstrates basic RBAC operations

param(
    [string]$ConfigPath = "../security/rbac/rbac_config.json"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD RBAC Quick Start Example" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Initialize RBAC
Write-Host "Step 1: Initializing RBAC..." -ForegroundColor Yellow
$RBACManager = "../security/rbac/rbac_manager.ps1"

& $RBACManager -Operation init -ConfigPath $ConfigPath
Write-Host "✓ RBAC initialized" -ForegroundColor Green
Write-Host ""

# Step 2: List all roles
Write-Host "Step 2: Available Roles..." -ForegroundColor Yellow
$roles = & $RBACManager -Operation list -ConfigPath $ConfigPath -JsonOutput | ConvertFrom-Json

foreach ($role in $roles) {
    Write-Host "  Role: $($role.name)" -ForegroundColor White
    Write-Host "    Level: $($role.level)" -ForegroundColor Gray
    Write-Host "    Permissions: $($role.permissions -join ', ')" -ForegroundColor Gray
    Write-Host ""
}

# Step 3: Assign roles to users
Write-Host "Step 3: Assigning Roles to Users..." -ForegroundColor Yellow

$users = @(
    @{ UserId = "admin-user"; RoleName = "super-admin" },
    @{ UserId = "patch-manager"; RoleName = "patch-admin" },
    @{ UserId = "operator-1"; RoleName = "patch-operator" },
    @{ UserId = "viewer-1"; RoleName = "patch-viewer" },
    @{ UserId = "security-auditor-1"; RoleName = "security-auditor" }
)

foreach ($user in $users) {
    & $RBACManager -Operation assign_role `
        -UserId $user.UserId `
        -RoleName $user.RoleName `
        -ConfigPath $ConfigPath | Out-Null
    Write-Host "  ✓ Assigned $($user.RoleName) to $($user.UserId)" -ForegroundColor Green
}
Write-Host ""

# Step 4: Check permissions
Write-Host "Step 4: Checking Permissions..." -ForegroundColor Yellow

$permissionTests = @(
    @{ UserId = "admin-user"; Permission = "patch:apply"; Expected = $true },
    @{ UserId = "operator-1"; Permission = "patch:apply"; Expected = $true },
    @{ UserId = "viewer-1"; Permission = "patch:apply"; Expected = $false },
    @{ UserId = "viewer-1"; Permission = "patch:view"; Expected = $true },
    @{ UserId = "security-auditor-1"; Permission = "audit:view"; Expected = $true }
)

foreach ($test in $permissionTests) {
    $result = & $RBACManager -Operation check_permission `
        -UserId $test.UserId `
        -Permission $test.Permission `
        -ConfigPath $ConfigPath -JsonOutput | ConvertFrom-Json
    
    $status = if ($result.granted -eq $test.Expected) { "✓" } else { "✗" }
    $color = if ($result.granted -eq $test.Expected) { "Green" } else { "Red" }
    
    Write-Host "  $status $($test.UserId) - $($test.Permission): $($result.granted)" -ForegroundColor $color
}
Write-Host ""

# Step 5: Get user role details
Write-Host "Step 5: User Role Details..." -ForegroundColor Yellow

$sampleUsers = @("admin-user", "operator-1", "viewer-1")
foreach ($userId in $sampleUsers) {
    $userRole = & $RBACManager -Operation get_user_role `
        -UserId $userId `
        -ConfigPath $ConfigPath -JsonOutput | ConvertFrom-Json
    
    Write-Host "  User: $userId" -ForegroundColor White
    Write-Host "    Role: $($userRole.role)" -ForegroundColor Gray
    Write-Host "    Level: $($userRole.role_level)" -ForegroundColor Gray
    Write-Host "    Permissions: $($userRole.permissions.Count) total" -ForegroundColor Gray
    Write-Host ""
}

# Step 6: Demonstrate permission inheritance
Write-Host "Step 6: Permission Inheritance Demo..." -ForegroundColor Yellow

# Create a custom role that inherits from patch-viewer
$config = Get-Content $ConfigPath | ConvertFrom-Json
$customRole = @{
    name = "custom-operator"
    level = 50
    permissions = @("patch:dryrun")
    inherits_from = "patch-viewer"
    description = "Custom operator with inherited permissions"
}
$config.roles += $customRole
$config | ConvertTo-Json -Depth 10 | Out-File $ConfigPath

& $RBACManager -Operation assign_role `
    -UserId "custom-user" `
    -RoleName "custom-operator" `
    -ConfigPath $ConfigPath | Out-Null

# Check inherited permission
$inherited = & $RBACManager -Operation check_permission `
    -UserId "custom-user" `
    -Permission "patch:view" `
    -ConfigPath $ConfigPath -JsonOutput | ConvertFrom-Json

Write-Host "  Custom operator inherited 'patch:view': $($inherited.granted)" -ForegroundColor $(if ($inherited.granted) { "Green" } else { "Red" })
Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Quick Start Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Review the RBAC configuration at: $ConfigPath" -ForegroundColor Gray
Write-Host "  2. Customize roles for your organization" -ForegroundColor Gray
Write-Host "  3. Integrate permission checks into your scripts" -ForegroundColor Gray
Write-Host "  4. Set up audit logging" -ForegroundColor Gray
Write-Host ""
Write-Host "Documentation: docs/SECURITY_API_REFERENCE.md" -ForegroundColor Gray