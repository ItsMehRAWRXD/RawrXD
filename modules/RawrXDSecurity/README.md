# RawrXDSecurity PowerShell Module

## Overview

The `RawrXDSecurity` module provides a comprehensive PowerShell interface for the RawrXD Security & Hotpatch System. It enables easy integration of enterprise-grade security features into your PowerShell scripts and automation workflows.

## Features

- **RBAC Management**: Role-based access control with 5-tier hierarchy
- **Audit Logging**: Comprehensive audit trail with filtering
- **Health Monitoring**: System health validation
- **Backup & Recovery**: Automated backup management
- **Compliance Checking**: SOC2/ISO27001/NIST validation
- **Patch Management**: Hotpatch status tracking

## Installation

### Method 1: Direct Import

```powershell
# Import the module
Import-Module "path\to\RawrXDSecurity\RawrXDSecurity.psd1"

# Verify installation
Get-Module RawrXDSecurity
```

### Method 2: Install to PowerShell Modules Directory

```powershell
# Copy module to PowerShell modules directory
$modulePath = "$env:USERPROFILE\Documents\PowerShell\Modules\RawrXDSecurity"
Copy-Item -Path ".\RawrXDSecurity" -Destination $modulePath -Recurse -Force

# Import the module
Import-Module RawrXDSecurity
```

## Quick Start

```powershell
# Initialize the security system
Initialize-RawrXDSecurity -Environment production

# Or use the alias
irxs -Environment production

# List all roles
Get-RawrXDRole

# Assign a role to a user
Set-RawrXDUserRole -UserId "john.doe" -RoleName "patch-operator"

# Check permissions
Test-RawrXDPermission -UserId "john.doe" -Permission "patch:apply"

# Run health check
Invoke-RawrXDHealthCheck
```

## Commands

### Initialization

| Command | Alias | Description |
|---------|-------|-------------|
| `Initialize-RawrXDSecurity` | `irxs` | Initialize the security system |

### RBAC Management

| Command | Alias | Description |
|---------|-------|-------------|
| `Get-RawrXDRole` | `grr` | Get roles |
| `Set-RawrXDUserRole` | `sur` | Assign role to user |
| `Test-RawrXDPermission` | `trp` | Check user permission |
| `Remove-RawrXDUserRole` | `rur` | Revoke user role |

### Audit Logging

| Command | Alias | Description |
|---------|-------|-------------|
| `Get-RawrXDAuditLog` | `gral` | Get audit log entries |
| `Write-RawrXDAuditEvent` | `wxal` | Write audit event |

### System Operations

| Command | Alias | Description |
|---------|-------|-------------|
| `Invoke-RawrXDHealthCheck` | `irhc` | Run health check |
| `New-RawrXDBackup` | `nrb` | Create backup |
| `Invoke-RawrXDComplianceCheck` | `ircc` | Check compliance |

### Patch Management

| Command | Alias | Description |
|---------|-------|-------------|
| `Get-RawrXDPatchStatus` | `grps` | Get patch status |
| `Register-RawrXDPatch` | `regp` | Register new patch |
| `Update-RawrXDPatchStatus` | `upps` | Update patch status |

## Examples

### Example 1: Complete RBAC Setup

```powershell
# Import module
Import-Module RawrXDSecurity

# Initialize
Initialize-RawrXDSecurity -Environment production

# Create users with different roles
$users = @(
    @{ UserId = "admin"; Role = "super-admin" },
    @{ UserId = "operator"; Role = "patch-operator" },
    @{ UserId = "viewer"; Role = "patch-viewer" }
)

foreach ($user in $users) {
    Set-RawrXDUserRole -UserId $user.UserId -RoleName $user.Role
}

# Verify permissions
foreach ($user in $users) {
    $perm = Test-RawrXDPermission -UserId $user.UserId -Permission "patch:apply"
    Write-Host "$($user.UserId): $($perm.Granted)"
}
```

### Example 2: Audit Log Analysis

```powershell
# Get last 24 hours of audit logs
$yesterday = (Get-Date).AddDays(-1)
$logs = Get-RawrXDAuditLog -StartDate $yesterday

# Find failed permission checks
$failed = $logs | Where-Object { 
    $_.action -eq "permission_check" -and 
    $_.details -match "denied" 
}

$failed | Format-Table timestamp, user_id, details
```

### Example 3: Compliance Reporting

```powershell
# Run compliance check
$result = Invoke-RawrXDComplianceCheck -Framework All

# Display results
$result.Summary
$result.Frameworks

# Generate report if needed
if ($result.Summary.ComplianceScore -lt 80) {
    Write-Warning "Compliance below threshold!"
}
```

### Example 4: Health Monitoring

```powershell
# Run health check
$health = Invoke-RawrXDHealthCheck

# Check each component
foreach ($component in $health.Components) {
    if ($component.Status -eq "Error") {
        Write-Error "$($component.Component): $($component.Message)"
    }
}

# Overall status
Write-Host "System Status: $($health.Status)"
```

## Configuration

### Default Paths

| Setting | Default Path |
|---------|--------------|
| Config Directory | `$env:ProgramData\RawrXD\config` |
| RBAC Config | `$env:ProgramData\RawrXD\config\rbac_config.json` |
| Audit Logs | `$env:ProgramData\RawrXD\logs\audit` |
| Backups | `$env:ProgramData\RawrXD\backups` |

### Custom Configuration

```powershell
# Initialize with custom paths
Initialize-RawrXDSecurity -ConfigPath "D:\Custom\Path"

# Use custom paths in commands
Get-RawrXDAuditLog -AuditPath "D:\Custom\Audit"
New-RawrXDBackup -ConfigPath "D:\Custom\Path"
```

## Requirements

- PowerShell 7.0 or higher
- Windows Server 2019+ or Windows 10/11
- Administrative privileges (for some operations)

## Troubleshooting

### Module Not Found

```powershell
# Check module path
$env:PSModulePath -split ';'

# Import with full path
Import-Module "C:\Full\Path\To\RawrXDSecurity\RawrXDSecurity.psd1"
```

### Permission Denied

```powershell
# Run as administrator
Start-Process PowerShell -Verb RunAs

# Or use -Scope CurrentUser
Install-Module RawrXDSecurity -Scope CurrentUser
```

## Support

- **Documentation**: `docs/SECURITY_API_REFERENCE.md`
- **Examples**: `examples/`
- **Issues**: GitHub Issues

## License

MIT License - See LICENSE file

---

*Module Version: 1.0.0*
