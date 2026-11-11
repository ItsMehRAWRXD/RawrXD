# RawrXDSecurity PowerShell Module

## Overview

The `RawrXDSecurity` module provides a professional PowerShell interface for the RawrXD Security & Hotpatch System.

## Quick Start

```powershell
# Install the module
.\modules\Install-RawrXDSecurityModule.ps1

# Import the module
Import-Module RawrXDSecurity

# Initialize
Initialize-RawrXDSecurity -Environment production

# Use aliases for quick access
irxs -Environment production          # Initialize
grr                                     # Get roles
sur -UserId "john" -RoleName "admin"   # Set user role
trp -UserId "john" -Permission "patch" # Test permission
```

## Available Commands

### Initialization
- `Initialize-RawrXDSecurity` (alias: `irxs`)

### RBAC
- `Get-RawrXDRole` (alias: `grr`)
- `Set-RawrXDUserRole` (alias: `sur`)
- `Remove-RawrXDUserRole` (alias: `rur`)
- `Test-RawrXDPermission` (alias: `trp`)

### Audit
- `Get-RawrXDAuditLog` (alias: `gral`)
- `Write-RawrXDAuditEvent` (alias: `wxal`)

### Operations
- `Invoke-RawrXDHealthCheck` (alias: `irhc`)
- `New-RawrXDBackup` (alias: `nrb`)
- `Invoke-RawrXDComplianceCheck` (alias: `ircc`)

### Patch Management
- `Get-RawrXDPatchStatus` (alias: `grps`)
- `Register-RawrXDPatch` (alias: `regp`)
- `Update-RawrXDPatchStatus` (alias: `upps`)

## Installation

See `modules/RawrXDSecurity/README.md` for detailed installation instructions.

## Documentation

- Module docs: `modules/RawrXDSecurity/README.md`
- API reference: `docs/SECURITY_API_REFERENCE.md`
- Quick start: `SECURITY_QUICK_START.md`
