#Requires -Version 7.0
<#
.SYNOPSIS
    Patch Registry System for RawrXD Hotpatch Management

.DESCRIPTION
    Centralized registry for tracking all patches, their status, and history.

.PARAMETER Action
    Action to perform: register, unregister, list, status, history, cleanup

.PARAMETER BundleId
    Patch bundle ID for register/unregister/status actions

.PARAMETER PatchBundle
    Path to patch bundle JSON file

.PARAMETER System
    Filter by system (swarm, agent, tools, all)

.PARAMETER Status
    Filter by status (active, pending, failed, rolled-back)

.EXAMPLE
    .\patch_registry.ps1 -Action register -PatchBundle ..\patches\hotfix.json
    
    .\patch_registry.ps1 -Action list -System swarm -Status active
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("register", "unregister", "list", "status", "history", "cleanup", "validate")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [string]$BundleId,

    [Parameter(Mandatory = $false)]
    [string]$PatchBundle,

    [Parameter(Mandatory = $false)]
    [ValidateSet("swarm", "agent", "tools", "all")]
    [string]$System = "all",

    [Parameter(Mandatory = $false)]
    [ValidateSet("active", "pending", "failed", "rolled-back", "all")]
    [string]$Status = "all",

    [Parameter(Mandatory = $false)]
    [string]$RegistryPath = "$env:RAWRXD_HOME\security\phase_g1_hotpatch\registry\registry.json"
)

# Ensure registry directory exists
$registryDir = Split-Path -Parent $RegistryPath
if (-not (Test-Path $registryDir)) {
    New-Item -ItemType Directory -Path $registryDir -Force | Out-Null
}

# Initialize registry if it doesn't exist
function Initialize-Registry {
    if (-not (Test-Path $RegistryPath)) {
        $initialRegistry = @{
            Version = "1.0.0"
            CreatedAt = Get-Date -Format "o"
            UpdatedAt = Get-Date -Format "o"
            Patches = @()
            Statistics = @{
                TotalPatches = 0
                ActivePatches = 0
                FailedPatches = 0
                RolledBackPatches = 0
            }
        }
        $initialRegistry | ConvertTo-Json -Depth 10 | Out-File $RegistryPath -Encoding UTF8
        Write-Host "Initialized new patch registry at $RegistryPath" -ForegroundColor Green
    }
}

# Load registry
function Get-Registry {
    Initialize-Registry
    return Get-Content $RegistryPath -Raw | ConvertFrom-Json
}

# Save registry
function Save-Registry {
    param([hashtable]$Registry)
    $Registry.UpdatedAt = Get-Date -Format "o"
    $Registry | ConvertTo-Json -Depth 10 | Out-File $RegistryPath -Encoding UTF8
}

# Register a new patch
function Register-Patch {
    param([string]$BundlePath)

    if (-not (Test-Path $BundlePath)) {
        Write-Error "Patch bundle not found: $BundlePath"
        return $false
    }

    try {
        $bundle = Get-Content $BundlePath -Raw | ConvertFrom-Json
        $registry = Get-Registry

        # Check if already registered
        $existing = $registry.Patches | Where-Object { $_.BundleId -eq $bundle.BundleId }
        if ($existing) {
            Write-Warning "Patch $($bundle.BundleId) is already registered"
            return $false
        }

        # Create patch entry
        $patchEntry = @{
            BundleId = $bundle.BundleId
            Version = $bundle.Version
            Type = $bundle.Type
            Severity = $bundle.Severity
            Description = $bundle.Description
            Author = $bundle.Author
            CreatedAt = $bundle.CreatedAt
            ExpiresAt = $bundle.ExpiresAt
            RegisteredAt = Get-Date -Format "o"
            Status = "pending"
            Systems = @($bundle.Patches | ForEach-Object { $_.System } | Select-Object -Unique)
            PatchCount = $bundle.Patches.Count
            Metadata = $bundle.Metadata
            History = @(@{
                Action = "registered"
                Timestamp = Get-Date -Format "o"
                Details = "Patch registered in registry"
            })
        }

        $registry.Patches += $patchEntry
        Update-Statistics -Registry $registry
        Save-Registry -Registry $registry

        Write-Host "✅ Registered patch: $($bundle.BundleId)" -ForegroundColor Green
        Write-Host "   Type: $($bundle.Type), Severity: $($bundle.Severity)" -ForegroundColor Gray
        Write-Host "   Systems: $($patchEntry.Systems -join ', ')" -ForegroundColor Gray
        Write-Host "   Patches: $($bundle.Patches.Count)" -ForegroundColor Gray
        return $true
    }
    catch {
        Write-Error "Failed to register patch: $_"
        return $false
    }
}

# Unregister a patch
function Unregister-Patch {
    param([string]$Id)

    $registry = Get-Registry
    $patch = $registry.Patches | Where-Object { $_.BundleId -eq $Id }

    if (-not $patch) {
        Write-Error "Patch not found: $Id"
        return $false
    }

    if ($patch.Status -eq "active") {
        Write-Warning "Cannot unregister active patch. Rollback first."
        return $false
    }

    $registry.Patches = @($registry.Patches | Where-Object { $_.BundleId -ne $Id })
    Update-Statistics -Registry $registry
    Save-Registry -Registry $registry

    Write-Host "✅ Unregistered patch: $Id" -ForegroundColor Green
    return $true
}

# List patches
function List-Patches {
    param([string]$SystemFilter, [string]$StatusFilter)

    $registry = Get-Registry
    $patches = $registry.Patches

    # Apply filters
    if ($SystemFilter -ne "all") {
        $patches = @($patches | Where-Object { $_.Systems -contains $SystemFilter })
    }

    if ($StatusFilter -ne "all") {
        $patches = @($patches | Where-Object { $_.Status -eq $StatusFilter })
    }

    # Display results
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    PATCH REGISTRY                              ║" -ForegroundColor Cyan
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Filter: System=$SystemFilter, Status=$StatusFilter" -ForegroundColor Gray
    Write-Host "║ Total: $($patches.Count) patches" -ForegroundColor Gray
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    if ($patches.Count -eq 0) {
        Write-Host "No patches found matching criteria." -ForegroundColor Yellow
        return
    }

    # Header
    Write-Host "Bundle ID                 Version  Type        Severity    Status       Systems          " -ForegroundColor Cyan
    Write-Host "─────────────────────────────────────────────────────────────────────────────────────────" -ForegroundColor Gray

    foreach ($patch in $patches | Sort-Object RegisteredAt -Descending) {
        $statusColor = switch ($patch.Status) {
            "active" { "Green" }
            "pending" { "Yellow" }
            "failed" { "Red" }
            "rolled-back" { "Magenta" }
            default { "White" }
        }

        $line = "{0,-25} {1,-8} {2,-11} {3,-11} {4,-12} {5,-17}" -f 
            $patch.BundleId,
            $patch.Version,
            $patch.Type,
            $patch.Severity,
            $patch.Status,
            ($patch.Systems -join ',')

        Write-Host $line -ForegroundColor $statusColor
    }

    Write-Host ""
}

# Get patch status
function Get-PatchStatus {
    param([string]$Id)

    $registry = Get-Registry
    $patch = $registry.Patches | Where-Object { $_.BundleId -eq $Id }

    if (-not $patch) {
        Write-Error "Patch not found: $Id"
        return
    }

    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    PATCH DETAILS                               ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "Bundle ID:    " -NoNewline; Write-Host $patch.BundleId -ForegroundColor Green
    Write-Host "Version:      " -NoNewline; Write-Host $patch.Version
    Write-Host "Type:         " -NoNewline; Write-Host $patch.Type
    Write-Host "Severity:     " -NoNewline; Write-Host $patch.Severity -ForegroundColor $(if ($patch.Severity -eq "critical") { "Red" } elseif ($patch.Severity -eq "high") { "Yellow" } else { "White" })
    Write-Host "Status:       " -NoNewline; Write-Host $patch.Status -ForegroundColor $(switch ($patch.Status) { "active" { "Green" } "failed" { "Red" } "rolled-back" { "Magenta" } default { "Yellow" } })
    Write-Host "Description:  " -NoNewline; Write-Host $patch.Description
    Write-Host "Author:       " -NoNewline; Write-Host $patch.Author
    Write-Host "Created:      " -NoNewline; Write-Host $patch.CreatedAt
    Write-Host "Registered:   " -NoNewline; Write-Host $patch.RegisteredAt
    Write-Host "Expires:      " -NoNewline; Write-Host $patch.ExpiresAt
    Write-Host "Systems:      " -NoNewline; Write-Host ($patch.Systems -join ', ')
    Write-Host "Patch Count:  " -NoNewline; Write-Host $patch.PatchCount

    Write-Host ""
    Write-Host "History:" -ForegroundColor Cyan
    foreach ($entry in $patch.History | Sort-Object Timestamp) {
        Write-Host "  [$($entry.Timestamp)] $($entry.Action): $($entry.Details)" -ForegroundColor Gray
    }

    Write-Host ""
}

# Get registry statistics
function Get-RegistryStatistics {
    $registry = Get-Registry

    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                 REGISTRY STATISTICS                            ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "Total Patches:      " -NoNewline; Write-Host $registry.Statistics.TotalPatches
    Write-Host "Active Patches:     " -NoNewline; Write-Host $registry.Statistics.ActivePatches -ForegroundColor Green
    Write-Host "Failed Patches:     " -NoNewline; Write-Host $registry.Statistics.FailedPatches -ForegroundColor Red
    Write-Host "Rolled Back:        " -NoNewline; Write-Host $registry.Statistics.RolledBackPatches -ForegroundColor Magenta
    Write-Host ""
    Write-Host "Registry Version:   " -NoNewline; Write-Host $registry.Version
    Write-Host "Created:            " -NoNewline; Write-Host $registry.CreatedAt
    Write-Host "Last Updated:       " -NoNewline; Write-Host $registry.UpdatedAt
    Write-Host ""

    # Type breakdown
    Write-Host "Patches by Type:" -ForegroundColor Cyan
    $typeGroups = $registry.Patches | Group-Object Type
    foreach ($group in $typeGroups | Sort-Object Count -Descending) {
        Write-Host "  $($group.Name): $($group.Count)" -ForegroundColor Gray
    }

    Write-Host ""

    # Severity breakdown
    Write-Host "Patches by Severity:" -ForegroundColor Cyan
    $severityGroups = $registry.Patches | Group-Object Severity
    foreach ($group in $severityGroups | Sort-Object Count -Descending) {
        $color = switch ($group.Name) {
            "critical" { "Red" }
            "high" { "Yellow" }
            "medium" { "White" }
            "low" { "Gray" }
            default { "White" }
        }
        Write-Host "  $($group.Name): $($group.Count)" -ForegroundColor $color
    }

    Write-Host ""
}

# Update patch status
function Update-PatchStatus {
    param([string]$Id, [string]$NewStatus, [string]$Details)

    $registry = Get-Registry
    $patch = $registry.Patches | Where-Object { $_.BundleId -eq $Id }

    if (-not $patch) {
        return $false
    }

    $oldStatus = $patch.Status
    $patch.Status = $NewStatus
    $patch.History += @{
        Action = "status-change"
        Timestamp = Get-Date -Format "o"
        Details = "Status changed from $oldStatus to $NewStatus. $Details"
    }

    Update-Statistics -Registry $registry
    Save-Registry -Registry $registry
    return $true
}

# Update statistics
function Update-Statistics {
    param([hashtable]$Registry)

    $Registry.Statistics.TotalPatches = $Registry.Patches.Count
    $Registry.Statistics.ActivePatches = ($Registry.Patches | Where-Object { $_.Status -eq "active" }).Count
    $Registry.Statistics.FailedPatches = ($Registry.Patches | Where-Object { $_.Status -eq "failed" }).Count
    $Registry.Statistics.RolledBackPatches = ($Registry.Patches | Where-Object { $_.Status -eq "rolled-back" }).Count
}

# Cleanup expired patches
function Cleanup-ExpiredPatches {
    $registry = Get-Registry
    $now = Get-Date
    $expired = @($registry.Patches | Where-Object { 
        $_.Status -ne "active" -and 
        $_.ExpiresAt -and 
        [datetime]::Parse($_.ExpiresAt) -lt $now 
    })

    if ($expired.Count -eq 0) {
        Write-Host "No expired patches to cleanup." -ForegroundColor Green
        return
    }

    Write-Host "Found $($expired.Count) expired patches:" -ForegroundColor Yellow
    foreach ($patch in $expired) {
        Write-Host "  - $($patch.BundleId) (expired: $($patch.ExpiresAt))" -ForegroundColor Gray
    }

    $confirm = Read-Host "Remove expired patches from registry? (y/N)"
    if ($confirm -eq 'y') {
        $registry.Patches = @($registry.Patches | Where-Object { 
            $_.Status -eq "active" -or 
            -not $_.ExpiresAt -or 
            [datetime]::Parse($_.ExpiresAt) -ge $now 
        })
        Update-Statistics -Registry $registry
        Save-Registry -Registry $registry
        Write-Host "✅ Removed $($expired.Count) expired patches" -ForegroundColor Green
    }
}

# Validate registry integrity
function Validate-Registry {
    $registry = Get-Registry
    $issues = @()

    # Check for duplicate BundleIds
    $duplicates = $registry.Patches | Group-Object BundleId | Where-Object { $_.Count -gt 1 }
    if ($duplicates) {
        $issues += "Found $($duplicates.Count) duplicate BundleIds"
    }

    # Check for patches with no systems
    $noSystems = $registry.Patches | Where-Object { $_.Systems.Count -eq 0 }
    if ($noSystems) {
        $issues += "Found $($noSystems.Count) patches with no systems"
    }

    # Check for expired active patches
    $now = Get-Date
    $expiredActive = @($registry.Patches | Where-Object { 
        $_.Status -eq "active" -and 
        $_.ExpiresAt -and 
        [datetime]::Parse($_.ExpiresAt) -lt $now 
    })
    if ($expiredActive.Count -gt 0) {
        $issues += "Found $($expiredActive.Count) expired but still active patches"
    }

    if ($issues.Count -eq 0) {
        Write-Host "✅ Registry validation passed" -ForegroundColor Green
        return $true
    }
    else {
        Write-Host "❌ Registry validation failed:" -ForegroundColor Red
        foreach ($issue in $issues) {
            Write-Host "  - $issue" -ForegroundColor Yellow
        }
        return $false
    }
}

# Main execution
switch ($Action) {
    "register" {
        if (-not $PatchBundle) {
            Write-Error "PatchBundle parameter required for register action"
            exit 1
        }
        $success = Register-Patch -BundlePath $PatchBundle
        exit $(if ($success) { 0 } else { 1 })
    }
    "unregister" {
        if (-not $BundleId) {
            Write-Error "BundleId parameter required for unregister action"
            exit 1
        }
        $success = Unregister-Patch -Id $BundleId
        exit $(if ($success) { 0 } else { 1 })
    }
    "list" {
        List-Patches -SystemFilter $System -StatusFilter $Status
    }
    "status" {
        if ($BundleId) {
            Get-PatchStatus -Id $BundleId
        }
        else {
            Get-RegistryStatistics
        }
    }
    "history" {
        Get-RegistryStatistics
    }
    "cleanup" {
        Cleanup-ExpiredPatches
    }
    "validate" {
        $valid = Validate-Registry
        exit $(if ($valid) { 0 } else { 1 })
    }
}
