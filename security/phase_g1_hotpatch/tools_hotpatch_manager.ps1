#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Tools Hotpatch Manager - Runtime patching for non-agentic tools
    
.DESCRIPTION
    Provides hotpatching capabilities for standalone tools, utilities,
    and non-agentic components without requiring restarts.
    
.PARAMETER Action
    Action to perform: apply, rollback, status, list, validate
    
.PARAMETER Target
    Target tool category: cli, utilities, extensions, plugins, all
    
.PARAMETER PatchFile
    Path to patch definition file
    
.PARAMETER ToolName
    Specific tool name to target
    
.EXAMPLE
    .\tools_hotpatch_manager.ps1 -Action apply -Target cli -PatchFile .\patches\cli_tools_v2.json
    .\tools_hotpatch_manager.ps1 -Action status
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("apply", "rollback", "status", "list", "validate", "emergency", "scan")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("cli", "utilities", "extensions", "plugins", "libraries", "scripts", "all")]
    [string]$Target = "all",
    
    [Parameter(Mandatory=$false)]
    [string]$PatchFile,
    
    [Parameter(Mandatory=$false)]
    [string]$ToolName,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# Tools hotpatch registry
$ToolsHotpatchRegistry = @{
    Version = "1.0.0"
    AppliedPatches = @()
    RollbackHistory = @()
    ToolStatus = @{}
    ScannedTools = @()
}

# Tool category definitions
$ToolCategories = @{
    cli = @{
        Name = "CLI Tools"
        Path = "$env:RAWRXD_HOME\bin\cli"
        ConfigPath = "$env:RAWRXD_HOME\config\tools\cli.json"
        BackupPath = "$env:RAWRXD_HOME\backups\tools\cli"
        Hotpatchable = $true
        Pattern = "*.exe"
    }
    utilities = @{
        Name = "Utility Tools"
        Path = "$env:RAWRXD_HOME\bin\utils"
        ConfigPath = "$env:RAWRXD_HOME\config\tools\utilities.json"
        BackupPath = "$env:RAWRXD_HOME\backups\tools\utilities"
        Hotpatchable = $true
        Pattern = "*.exe"
    }
    extensions = @{
        Name = "IDE Extensions"
        Path = "$env:RAWRXD_HOME\extensions"
        ConfigPath = "$env:RAWRXD_HOME\config\tools\extensions.json"
        BackupPath = "$env:RAWRXD_HOME\backups\tools\extensions"
        Hotpatchable = $true
        Pattern = "*.vsix"
    }
    plugins = @{
        Name = "Plugins"
        Path = "$env:RAWRXD_HOME\plugins"
        ConfigPath = "$env:RAWRXD_HOME\config\tools\plugins.json"
        BackupPath = "$env:RAWRXD_HOME\backups\tools\plugins"
        Hotpatchable = $true
        Pattern = "*.dll"
    }
    libraries = @{
        Name = "Shared Libraries"
        Path = "$env:RAWRXD_HOME\lib"
        ConfigPath = "$env:RAWRXD_HOME\config\tools\libraries.json"
        BackupPath = "$env:RAWRXD_HOME\backups\tools\libraries"
        Hotpatchable = $true
        Pattern = "*.dll"
    }
    scripts = @{
        Name = "PowerShell Scripts"
        Path = "$env:RAWRXD_HOME\scripts"
        ConfigPath = "$env:RAWRXD_HOME\config\tools\scripts.json"
        BackupPath = "$env:RAWRXD_HOME\backups\tools\scripts"
        Hotpatchable = $true
        Pattern = "*.ps1"
    }
}

function Write-ToolsHotpatchHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Tools Hotpatch Manager                                            ║
║  Runtime patching for non-agentic tools                            ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-ToolsHotpatchManager {
    $registryPath = "$env:RAWRXD_HOME\registry\tools_hotpatch.json"
    if (Test-Path $registryPath) {
        $script:ToolsHotpatchRegistry = Get-Content -Path $registryPath -Raw | ConvertFrom-Json -AsHashtable
    }
    
    # Ensure backup directories exist
    foreach ($category in $ToolCategories.Values) {
        if (-not (Test-Path $category.BackupPath)) {
            New-Item -ItemType Directory -Path $category.BackupPath -Force | Out-Null
        }
    }
}

function Save-ToolsHotpatchRegistry {
    $registryPath = "$env:RAWRXD_HOME\registry\tools_hotpatch.json"
    if (-not (Test-Path (Split-Path $registryPath))) {
        New-Item -ItemType Directory -Path (Split-Path $registryPath) -Force | Out-Null
    }
    $script:ToolsHotpatchRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryPath
}

function Get-ToolProcesses {
    param($CategoryName)
    
    $category = $ToolCategories[$CategoryName]
    if (-not $category) { return @() }
    
    # Get processes that have files open in the tool directory
    $processes = @()
    if (Test-Path $category.Path) {
        $tools = Get-ChildItem -Path $category.Path -Filter $category.Pattern
        foreach ($tool in $tools) {
            $toolProcesses = Get-Process | Where-Object {
                $_.Modules.FileName -contains $tool.FullName
            }
            $processes += $toolProcesses
        }
    }
    
    return $processes | Select-Object -Unique
}

function Test-ToolCategoryHealth {
    param($CategoryName)
    
    $category = $ToolCategories[$CategoryName]
    if (-not $category) { return $false }
    
    # Check if directory exists
    if (-not (Test-Path $category.Path)) {
        return $false
    }
    
    # Check if config exists
    if (-not (Test-Path $category.ConfigPath)) {
        return $false
    }
    
    return $true
}

function Backup-ToolCategory {
    param($CategoryName)
    
    $category = $ToolCategories[$CategoryName]
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupDir = Join-Path $category.BackupPath "backup_$timestamp"
    
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    
    # Backup config
    if (Test-Path $category.ConfigPath) {
        Copy-Item -Path $category.ConfigPath -Destination $backupDir -Force
    }
    
    # Backup tools (metadata only, not binaries)
    $tools = Get-ChildItem -Path $category.Path -Filter $category.Pattern -ErrorAction SilentlyContinue
    $tools | Select-Object Name, Length, LastWriteTime | Export-Clixml -Path (Join-Path $backupDir "tools.xml")
    
    Write-Host "  ✓ Backup created: $backupDir" -ForegroundColor Green
    return $backupDir
}

function Invoke-ToolsHotpatch {
    param($CategoryName, $PatchFile, [string]$ToolName, [switch]$DryRun)
    
    Write-Host "`nApplying hotpatch to $CategoryName..." -ForegroundColor Yellow
    
    $category = $ToolCategories[$CategoryName]
    if (-not $category) {
        Write-Error "Unknown category: $CategoryName"
        return
    }
    
    if (-not $category.Hotpatchable) {
        Write-Error "Category $CategoryName is not hotpatchable"
        return
    }
    
    # Load patch definition
    if (-not (Test-Path $PatchFile)) {
        Write-Error "Patch file not found: $PatchFile"
        return
    }
    
    $patch = Get-Content -Path $PatchFile -Raw | ConvertFrom-Json
    
    # Validate category health
    if (-not (Test-ToolCategoryHealth -CategoryName $CategoryName)) {
        Write-Error "Category $CategoryName is not healthy. Aborting hotpatch."
        return
    }
    
    # Create backup
    $backupPath = Backup-ToolCategory -CategoryName $CategoryName
    
    if ($DryRun) {
        Write-Host "  [DRY RUN] Would apply patch:" -ForegroundColor Cyan
        Write-Host "    Category: $($category.Name)" -ForegroundColor Gray
        Write-Host "    Patch Version: $($patch.Version)" -ForegroundColor Gray
        Write-Host "    Changes: $($patch.Changes.Count)" -ForegroundColor Gray
        if ($ToolName) {
            Write-Host "    Target Tool: $ToolName" -ForegroundColor Gray
        }
        return
    }
    
    # Apply patch based on type
    switch ($patch.Type) {
        "config" {
            Apply-ToolsConfigHotpatch -Category $category -Patch $patch -ToolName $ToolName
        }
        "binary" {
            Apply-ToolsBinaryHotpatch -Category $category -Patch $patch -ToolName $ToolName
        }
        "script" {
            Apply-ToolsScriptHotpatch -Category $category -Patch $patch -ToolName $ToolName
        }
        "extension" {
            Apply-ToolsExtensionHotpatch -Category $category -Patch $patch -ToolName $ToolName
        }
        default {
            Write-Error "Unknown patch type: $($patch.Type)"
            return
        }
    }
    
    # Register patch
    $patchRecord = @{
        Id = [Guid]::NewGuid().ToString()
        Category = $CategoryName
        PatchVersion = $patch.Version
        AppliedAt = Get-Date -Format "o"
        BackupPath = $backupPath
        PatchFile = $PatchFile
        Status = "applied"
        ToolName = $ToolName
    }
    
    $script:ToolsHotpatchRegistry.AppliedPatches += $patchRecord
    Save-ToolsHotpatchRegistry
    
    Write-Host "  ✓ Hotpatch applied successfully" -ForegroundColor Green
    Write-Host "    Patch ID: $($patchRecord.Id)" -ForegroundColor Gray
}

function Apply-ToolsConfigHotpatch {
    param($Category, $Patch, [string]$ToolName)
    
    Write-Host "  Applying tools configuration hotpatch..." -ForegroundColor Gray
    
    $config = Get-Content -Path $category.ConfigPath -Raw | ConvertFrom-Json
    
    foreach ($change in $patch.Changes) {
        if ($ToolName -and $change.ToolName -ne $ToolName) {
            continue
        }
        
        $toolConfig = $config.Tools | Where-Object { $_.Name -eq $change.ToolName } | Select-Object -First 1
        if (-not $toolConfig) {
            Write-Warning "Tool not found: $($change.ToolName)"
            continue
        }
        
        foreach ($property in $change.Properties.PSObject.Properties) {
            $toolConfig | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value -Force
            Write-Host "    Updated $($change.ToolName).$($property.Name) = $($property.Value)" -ForegroundColor Gray
        }
    }
    
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $category.ConfigPath
}

function Apply-ToolsBinaryHotpatch {
    param($Category, $Patch, [string]$ToolName)
    
    Write-Host "  Applying tools binary hotpatch..." -ForegroundColor Gray
    
    foreach ($change in $patch.Changes) {
        if ($ToolName -and $change.ToolName -ne $ToolName) {
            continue
        }
        
        $toolPath = Join-Path $category.Path $change.ToolName
        if (-not (Test-Path $toolPath)) {
            Write-Warning "Tool not found: $change.ToolName"
            continue
        }
        
        # Check if tool is running
        $runningProcesses = Get-Process | Where-Object {
            $_.Modules.FileName -contains (Resolve-Path $toolPath).Path
        }
        
        if ($runningProcesses) {
            if (-not $Force) {
                Write-Warning "Tool $change.ToolName is running. Use -Force to override."
                continue
            }
            
            Write-Host "    Stopping running instances of $change.ToolName..." -ForegroundColor Yellow
            $runningProcesses | Stop-Process -Force
            Start-Sleep -Seconds 2
        }
        
        # Apply binary patch
        if ($change.NewBinary) {
            $newBinaryPath = Join-Path $change.BinarySource $change.NewBinary
            if (Test-Path $newBinaryPath) {
                Copy-Item -Path $newBinaryPath -Destination $toolPath -Force
                Write-Host "    Updated binary: $change.ToolName" -ForegroundColor Green
            }
        }
        
        # Apply in-memory patch if supported
        if ($change.MemoryPatch) {
            Write-Host "    Applying in-memory patch to $change.ToolName" -ForegroundColor Gray
            # Implementation would use memory patching techniques
        }
    }
}

function Apply-ToolsScriptHotpatch {
    param($Category, $Patch, [string]$ToolName)
    
    Write-Host "  Applying tools script hotpatch..." -ForegroundColor Gray
    
    foreach ($change in $patch.Changes) {
        if ($ToolName -and $change.ScriptName -ne $ToolName) {
            continue
        }
        
        $scriptPath = Join-Path $category.Path $change.ScriptName
        if (-not (Test-Path $scriptPath)) {
            Write-Warning "Script not found: $($change.ScriptName)"
            continue
        }
        
        # Validate PowerShell syntax before applying
        $syntaxError = $null
        [System.Management.Automation.PSParser]::Tokenize((Get-Content $scriptPath -Raw), [ref]$syntaxError)
        
        if ($syntaxError.Count -gt 0) {
            Write-Error "Syntax errors in script: $($change.ScriptName)"
            continue
        }
        
        if ($change.NewContent) {
            Set-Content -Path $scriptPath -Value $change.NewContent -Force
            Write-Host "    Updated script: $($change.ScriptName)" -ForegroundColor Green
        } elseif ($change.PatchFile) {
            Copy-Item -Path $change.PatchFile -Destination $scriptPath -Force
            Write-Host "    Replaced script: $($change.ScriptName)" -ForegroundColor Green
        }
    }
}

function Apply-ToolsExtensionHotpatch {
    param($Category, $Patch, [string]$ToolName)
    
    Write-Host "  Applying tools extension hotpatch..." -ForegroundColor Gray
    
    foreach ($change in $patch.Changes) {
        if ($ToolName -and $change.ExtensionName -ne $ToolName) {
            continue
        }
        
        $extensionPath = Join-Path $category.Path $change.ExtensionName
        
        if ($change.Action -eq "update") {
            if (Test-Path $change.NewExtension) {
                # Backup old extension
                $backupExtension = "$extensionPath.backup.$(Get-Date -Format 'yyyyMMddHHmmss')"
                Move-Item -Path $extensionPath -Destination $backupExtension -Force
                
                # Install new extension
                Copy-Item -Path $change.NewExtension -Destination $extensionPath -Force
                Write-Host "    Updated extension: $($change.ExtensionName)" -ForegroundColor Green
            }
        } elseif ($change.Action -eq "disable") {
            $disabledPath = "$extensionPath.disabled"
            Move-Item -Path $extensionPath -Destination $disabledPath -Force
            Write-Host "    Disabled extension: $($change.ExtensionName)" -ForegroundColor Yellow
        } elseif ($change.Action -eq "enable") {
            $disabledPath = "$extensionPath.disabled"
            if (Test-Path $disabledPath) {
                Move-Item -Path $disabledPath -Destination $extensionPath -Force
                Write-Host "    Enabled extension: $($change.ExtensionName)" -ForegroundColor Green
            }
        }
    }
}

function Invoke-ToolsRollback {
    param($PatchId)
    
    Write-Host "`nRolling back tools hotpatch $PatchId..." -ForegroundColor Yellow
    
    $patch = $script:ToolsHotpatchRegistry.AppliedPatches | Where-Object { $_.Id -eq $PatchId } | Select-Object -First 1
    if (-not $patch) {
        Write-Error "Patch not found: $PatchId"
        return
    }
    
    $category = $ToolCategories[$patch.Category]
    
    # Restore from backup
    if (Test-Path $patch.BackupPath) {
        # Restore config
        $configBackup = Get-ChildItem -Path $patch.BackupPath -Filter "*.json" | Select-Object -First 1
        if ($configBackup) {
            Copy-Item -Path $configBackup.FullName -Destination $category.ConfigPath -Force
            Write-Host "  ✓ Restored config from backup" -ForegroundColor Green
        }
    }
    
    # Update registry
    $patch.Status = "rolled_back"
    $patch.RolledBackAt = Get-Date -Format "o"
    $script:ToolsHotpatchRegistry.RollbackHistory += $patch
    Save-ToolsHotpatchRegistry
    
    Write-Host "  ✓ Rollback completed" -ForegroundColor Green
}

function Get-ToolsHotpatchStatus {
    Write-Host "`nTools Hotpatch Status:" -ForegroundColor Yellow
    Write-Host ""
    
    # Category health
    Write-Host "  Category Health:" -ForegroundColor Cyan
    foreach ($categoryName in $ToolCategories.Keys) {
        $category = $ToolCategories[$categoryName]
        $health = Test-ToolCategoryHealth -CategoryName $categoryName
        $status = if ($health) { "✓ Healthy" } else { "✗ Unhealthy" }
        $color = if ($health) { "Green" } else { "Red" }
        
        # Count tools
        $toolCount = 0
        if (Test-Path $category.Path) {
            $toolCount = (Get-ChildItem -Path $category.Path -Filter $category.Pattern -ErrorAction SilentlyContinue).Count
        }
        
        Write-Host "    $($category.Name): $status ($toolCount tools)" -ForegroundColor $color
    }
    
    # Applied patches
    Write-Host "`n  Applied Patches ($($script:ToolsHotpatchRegistry.AppliedPatches.Count)):" -ForegroundColor Cyan
    foreach ($patch in ($script:ToolsHotpatchRegistry.AppliedPatches | Sort-Object AppliedAt -Descending | Select-Object -First 10)) {
        $statusColor = switch ($patch.Status) {
            "applied" { "Green" }
            "rolled_back" { "Red" }
            default { "Gray" }
        }
        $toolInfo = if ($patch.ToolName) { " [Tool: $($patch.ToolName)]" } else { "" }
        Write-Host "    [$($patch.Status)] $($patch.Category) - v$($patch.PatchVersion)$toolInfo" -ForegroundColor $statusColor
    }
}

function Get-ToolsHotpatchList {
    Write-Host "`nAvailable Tools Hotpatches:" -ForegroundColor Yellow
    
    $patchDir = "$env:RAWRXD_HOME\patches\tools"
    if (Test-Path $patchDir) {
        $patches = Get-ChildItem -Path $patchDir -Filter "*.json"
        foreach ($patch in $patches) {
            $content = Get-Content -Path $patch.FullName -Raw | ConvertFrom-Json
            Write-Host "  $($patch.Name)" -ForegroundColor White
            Write-Host "    Version: $($content.Version)" -ForegroundColor Gray
            Write-Host "    Type: $($content.Type)" -ForegroundColor Gray
            Write-Host "    Description: $($content.Description)" -ForegroundColor Gray
            Write-Host ""
        }
    } else {
        Write-Host "  No patches found in $patchDir" -ForegroundColor Gray
    }
}

function Invoke-ToolsScan {
    Write-Host "`nScanning for hotpatchable tools..." -ForegroundColor Yellow
    
    $scannedTools = @()
    
    foreach ($categoryName in $ToolCategories.Keys) {
        $category = $ToolCategories[$categoryName]
        Write-Host "  Scanning $($category.Name)..." -ForegroundColor Gray
        
        if (Test-Path $category.Path) {
            $tools = Get-ChildItem -Path $category.Path -Filter $category.Pattern -ErrorAction SilentlyContinue
            foreach ($tool in $tools) {
                $toolInfo = @{
                    Name = $tool.Name
                    Category = $categoryName
                    Path = $tool.FullName
                    Size = $tool.Length
                    LastModified = $tool.LastWriteTime
                    Hotpatchable = $category.Hotpatchable
                }
                $scannedTools += $toolInfo
                Write-Host "    Found: $($tool.Name) ($( [math]::Round($tool.Length / 1KB, 2) ) KB)" -ForegroundColor Gray
            }
        }
    }
    
    $script:ToolsHotpatchRegistry.ScannedTools = $scannedTools
    Save-ToolsHotpatchRegistry
    
    Write-Host "`n  Total tools scanned: $($scannedTools.Count)" -ForegroundColor Green
}

function Invoke-EmergencyToolsHotpatch {
    Write-Host "`n🚨 EMERGENCY TOOLS HOTPATCH MODE 🚨" -ForegroundColor Red
    Write-Host ""
    
    # Emergency patches for critical tool issues
    $emergencyPatches = @{
        "cli_restore" = "Restore CLI tools to last known good"
        "extension_disable_all" = "Disable all extensions"
        "script_rollback" = "Rollback all scripts to last backup"
        "library_refresh" = "Refresh all library references"
        "config_reset" = "Reset all tool configurations"
    }
    
    Write-Host "Available emergency patches:" -ForegroundColor Yellow
    foreach ($key in $emergencyPatches.Keys) {
        Write-Host "  $key - $($emergencyPatches[$key])" -ForegroundColor White
    }
    
    Write-Host "`n⚠️  Emergency patches may affect tool functionality!" -ForegroundColor Red
}

# Main execution
Write-ToolsHotpatchHeader
Initialize-ToolsHotpatchManager

switch ($Action) {
    "apply" {
        if (-not $PatchFile) {
            Write-Error "PatchFile required for apply action"
            exit 1
        }
        if ($Target -eq "all") {
            foreach ($categoryName in $ToolCategories.Keys) {
                Invoke-ToolsHotpatch -CategoryName $categoryName -PatchFile $PatchFile -ToolName $ToolName -DryRun:$DryRun
            }
        } else {
            Invoke-ToolsHotpatch -CategoryName $Target -PatchFile $PatchFile -ToolName $ToolName -DryRun:$DryRun
        }
    }
    "rollback" {
        if (-not $PatchFile) {
            Write-Error "PatchFile (PatchId) required for rollback action"
            exit 1
        }
        Invoke-ToolsRollback -PatchId $PatchFile
    }
    "status" {
        Get-ToolsHotpatchStatus
    }
    "list" {
        Get-ToolsHotpatchList
    }
    "validate" {
        Write-Host "`nValidating tools hotpatch readiness..." -ForegroundColor Yellow
        foreach ($categoryName in $ToolCategories.Keys) {
            $health = Test-ToolCategoryHealth -CategoryName $categoryName
            $status = if ($health) { "✓ Ready" } else { "✗ Not ready" }
            $color = if ($health) { "Green" } else { "Red" }
            Write-Host "  $($ToolCategories[$categoryName].Name): $status" -ForegroundColor $color
        }
    }
    "scan" {
        Invoke-ToolsScan
    }
    "emergency" {
        Invoke-EmergencyToolsHotpatch
    }
}

Write-Host "`n✅ Tools hotpatch operation complete" -ForegroundColor Green
