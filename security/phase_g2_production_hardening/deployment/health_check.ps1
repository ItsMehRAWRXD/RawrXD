#Requires -Version 7.0
<#
.SYNOPSIS
    Health Check Script for RawrXD Hotpatch System

.DESCRIPTION
    Performs comprehensive health checks on the hotpatch system and its components.

.PARAMETER Detailed
    Show detailed health information

.PARAMETER OutputFormat
    Output format: console, json, xml

.EXAMPLE
    .\health_check.ps1 -Detailed -OutputFormat json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Detailed,

    [Parameter(Mandatory = $false)]
    [ValidateSet("console", "json", "xml")]
    [string]$OutputFormat = "console"
)

$script:HealthResults = @{
    OverallStatus = "UNKNOWN"
    Timestamp = Get-Date -Format "o"
    Checks = @()
    Summary = @{
        Total = 0
        Passed = 0
        Failed = 0
        Warning = 0
    }
}

function Add-HealthCheck {
    param(
        [string]$Name,
        [string]$Status,  # PASS, FAIL, WARNING
        [string]$Message,
        [hashtable]$Details = @{}
    )

    $script:HealthResults.Checks += @{
        Name = $Name
        Status = $Status
        Message = $Message
        Details = $Details
        Timestamp = Get-Date -Format "o"
    }

    $script:HealthResults.Summary.Total++
    switch ($Status) {
        "PASS" { $script:HealthResults.Summary.Passed++ }
        "FAIL" { $script:HealthResults.Summary.Failed++ }
        "WARNING" { $script:HealthResults.Summary.Warning++ }
    }
}

function Test-FileIntegrity {
    $requiredFiles = @(
        "swarm_hotpatch_manager.ps1",
        "agent_hotpatch_manager.ps1",
        "tools_hotpatch_manager.ps1",
        "unified_hotpatch_orchestrator.ps1",
        "registry\patch_registry.ps1"
    )

    $hotpatchDir = "$env:RAWRXD_HOME\security\phase_g1_hotpatch"
    $missingFiles = @()
    $corruptFiles = @()

    foreach ($file in $requiredFiles) {
        $filePath = Join-Path $hotpatchDir $file
        if (-not (Test-Path $filePath)) {
            $missingFiles += $file
        }
        else {
            # Check if file is empty or too small (likely corrupt)
            $fileInfo = Get-Item $filePath
            if ($fileInfo.Length -lt 100) {
                $corruptFiles += $file
            }
        }
    }

    if ($missingFiles.Count -eq 0 -and $corruptFiles.Count -eq 0) {
        Add-HealthCheck -Name "File Integrity" -Status "PASS" -Message "All required files present and valid"
    }
    else {
        $message = ""
        if ($missingFiles.Count -gt 0) {
            $message += "Missing files: $($missingFiles -join ', '). "
        }
        if ($corruptFiles.Count -gt 0) {
            $message += "Corrupt files: $($corruptFiles -join ', ')"
        }
        Add-HealthCheck -Name "File Integrity" -Status "FAIL" -Message $message
    }
}

function Test-RegistryHealth {
    $registryPath = "$env:RAWRXD_HOME\security\phase_g1_hotpatch\registry\registry.json"

    if (-not (Test-Path $registryPath)) {
        Add-HealthCheck -Name "Registry Health" -Status "WARNING" -Message "Registry file not found, will be created on first use"
        return
    }

    try {
        $registry = Get-Content $registryPath -Raw | ConvertFrom-Json

        # Check registry structure
        $hasVersion = $registry.PSObject.Properties.Name -contains "Version"
        $hasPatches = $registry.PSObject.Properties.Name -contains "Patches"
        $hasStats = $registry.PSObject.Properties.Name -contains "Statistics"

        if ($hasVersion -and $hasPatches -and $hasStats) {
            $activePatches = ($registry.Patches | Where-Object { $_.Status -eq 'active' }).Count
            Add-HealthCheck -Name "Registry Health" -Status "PASS" -Message "Registry healthy. Active patches: $activePatches"
        }
        else {
            Add-HealthCheck -Name "Registry Health" -Status "WARNING" -Message "Registry structure incomplete"
        }
    }
    catch {
        Add-HealthCheck -Name "Registry Health" -Status "FAIL" -Message "Registry file corrupt: $_"
    }
}

function Test-SystemResources {
    # Check disk space
    $disk = Get-PSDrive C
    $freeSpaceGB = [math]::Round($disk.Free / 1GB, 2)
    $freeSpacePercent = [math]::Round(($disk.Free / $disk.Used) * 100, 2)

    if ($freeSpaceGB -lt 1) {
        Add-HealthCheck -Name "Disk Space" -Status "FAIL" -Message "Critical: Only $freeSpaceGB GB free" -Details @{ FreeGB = $freeSpaceGB; Percent = $freeSpacePercent }
    }
    elseif ($freeSpaceGB -lt 5) {
        Add-HealthCheck -Name "Disk Space" -Status "WARNING" -Message "Low disk space: $freeSpaceGB GB free" -Details @{ FreeGB = $freeSpaceGB; Percent = $freeSpacePercent }
    }
    else {
        Add-HealthCheck -Name "Disk Space" -Status "PASS" -Message "Disk space OK: $freeSpaceGB GB free" -Details @{ FreeGB = $freeSpaceGB; Percent = $freeSpacePercent }
    }

    # Check memory
    $memory = Get-CimInstance Win32_OperatingSystem
    $freeMemoryGB = [math]::Round($memory.FreePhysicalMemory / 1MB, 2)
    $totalMemoryGB = [math]::Round($memory.TotalVisibleMemorySize / 1MB, 2)
    $memoryPercent = [math]::Round(($freeMemoryGB / $totalMemoryGB) * 100, 2)

    if ($memoryPercent -lt 5) {
        Add-HealthCheck -Name "Memory" -Status "FAIL" -Message "Critical: Only $memoryPercent% memory free" -Details @{ FreeGB = $freeMemoryGB; TotalGB = $totalMemoryGB; Percent = $memoryPercent }
    }
    elseif ($memoryPercent -lt 10) {
        Add-HealthCheck -Name "Memory" -Status "WARNING" -Message "Low memory: $memoryPercent% free" -Details @{ FreeGB = $freeMemoryGB; TotalGB = $totalMemoryGB; Percent = $memoryPercent }
    }
    else {
        Add-HealthCheck -Name "Memory" -Status "PASS" -Message "Memory OK: $memoryPercent% free" -Details @{ FreeGB = $freeMemoryGB; TotalGB = $totalMemoryGB; Percent = $memoryPercent }
    }
}

function Test-Permissions {
    $hotpatchDir = "$env:RAWRXD_HOME\security\phase_g1_hotpatch"

    try {
        # Test write access
        $testFile = Join-Path $hotpatchDir "_test_$(Get-Random).tmp"
        "test" | Out-File $testFile -ErrorAction Stop
        Remove-Item $testFile -ErrorAction SilentlyContinue

        Add-HealthCheck -Name "Permissions" -Status "PASS" -Message "Write access verified"
    }
    catch {
        Add-HealthCheck -Name "Permissions" -Status "FAIL" -Message "No write access to hotpatch directory"
    }
}

function Test-BackupSystem {
    $backupDir = "$env:RAWRXD_HOME\security\phase_g1_hotpatch\backups"

    if (-not (Test-Path $backupDir)) {
        try {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
            Add-HealthCheck -Name "Backup System" -Status "PASS" -Message "Backup directory created"
        }
        catch {
            Add-HealthCheck -Name "Backup System" -Status "FAIL" -Message "Cannot create backup directory"
        }
    }
    else {
        # Check if we can write to backup directory
        try {
            $testFile = Join-Path $backupDir "_test_$(Get-Random).tmp"
            "test" | Out-File $testFile -ErrorAction Stop
            Remove-Item $testFile -ErrorAction SilentlyContinue
            Add-HealthCheck -Name "Backup System" -Status "PASS" -Message "Backup system operational"
        }
        catch {
            Add-HealthCheck -Name "Backup System" -Status "FAIL" -Message "Cannot write to backup directory"
        }
    }
}

function Show-HealthReport {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                  HOTPATCH HEALTH CHECK                           ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    foreach ($check in $script:HealthResults.Checks) {
        $color = switch ($check.Status) {
            "PASS" { "Green" }
            "FAIL" { "Red" }
            "WARNING" { "Yellow" }
            default { "White" }
        }

        $symbol = switch ($check.Status) {
            "PASS" { "✅" }
            "FAIL" { "❌" }
            "WARNING" { "⚠️" }
            default { "❓" }
        }

        Write-Host "$symbol $($check.Name): " -NoNewline
        Write-Host $check.Status -ForegroundColor $color -NoNewline
        Write-Host " - $($check.Message)"

        if ($Detailed -and $check.Details.Count -gt 0) {
            foreach ($detail in $check.Details.GetEnumerator()) {
                Write-Host "    $($detail.Key): $($detail.Value)" -ForegroundColor Gray
            }
        }
    }

    Write-Host ""
    Write-Host "Summary: $($script:HealthResults.Summary.Passed) passed, $($script:HealthResults.Summary.Warning) warnings, $($script:HealthResults.Summary.Failed) failed" -ForegroundColor $(if ($script:HealthResults.Summary.Failed -eq 0) { "Green" } else { "Red" })
    Write-Host ""

    # Overall status
    if ($script:HealthResults.Summary.Failed -gt 0) {
        $script:HealthResults.OverallStatus = "UNHEALTHY"
        Write-Host "Overall Status: ❌ UNHEALTHY" -ForegroundColor Red
    }
    elseif ($script:HealthResults.Summary.Warning -gt 0) {
        $script:HealthResults.OverallStatus = "DEGRADED"
        Write-Host "Overall Status: ⚠️  DEGRADED" -ForegroundColor Yellow
    }
    else {
        $script:HealthResults.OverallStatus = "HEALTHY"
        Write-Host "Overall Status: ✅ HEALTHY" -ForegroundColor Green
    }
    Write-Host ""
}

function Export-HealthResults {
    switch ($OutputFormat) {
        "json" {
            $script:HealthResults | ConvertTo-Json -Depth 5
        }
        "xml" {
            $xml = @"
<?xml version="1.0" encoding="UTF-8"?>
<HealthCheck>
    <OverallStatus>$($script:HealthResults.OverallStatus)</OverallStatus>
    <Timestamp>$($script:HealthResults.Timestamp)</Timestamp>
    <Summary>
        <Total>$($script:HealthResults.Summary.Total)</Total>
        <Passed>$($script:HealthResults.Summary.Passed)</Passed>
        <Failed>$($script:HealthResults.Summary.Failed)</Failed>
        <Warning>$($script:HealthResults.Summary.Warning)</Warning>
    </Summary>
    <Checks>
"@
            foreach ($check in $script:HealthResults.Checks) {
                $xml += @"
        <Check>
            <Name>$([System.Security.SecurityElement]::Escape($check.Name))</Name>
            <Status>$($check.Status)</Status>
            <Message>$([System.Security.SecurityElement]::Escape($check.Message))</Message>
        </Check>
"@
            }
            $xml += @"
    </Checks>
</HealthCheck>
"@
            return $xml
        }
        default {
            Show-HealthReport
        }
    }
}

# Run health checks
Test-FileIntegrity
Test-RegistryHealth
Test-SystemResources
Test-Permissions
Test-BackupSystem

# Output results
Export-HealthResults

# Exit code
exit $(if ($script:HealthResults.Summary.Failed -gt 0) { 1 } elseif ($script:HealthResults.Summary.Warning -gt 0) { 0 } else { 0 })
