# RawrXD Workspace Manager
# Manages development workspaces and environments

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Create", "Switch", "List", "Delete", "Backup", "Clone")]
    [string]$Action = "List",
    
    [string]$WorkspaceName = "",
    [string]$Template = "default",
    [string]$SourceWorkspace = "",
    [string]$BackupPath = "workspaces/backups",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$script:WorkspacesRoot = "$env:USERPROFILE\RawrXD-Workspaces"
$script:CurrentWorkspaceFile = "$env:USERPROFILE\.rawrxd-workspace"

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Initialize-WorkspaceManager {
    Write-Status "Workspace Manager initialized"
    Write-Status "Action: $Action"
    
    # Ensure workspaces root exists
    if (-not (Test-Path $script:WorkspacesRoot)) {
        New-Item -ItemType Directory -Path $script:WorkspacesRoot -Force | Out-Null
        Write-Status "Created workspaces root: $script:WorkspacesRoot"
    }
}

function Get-CurrentWorkspace {
    if (Test-Path $script:CurrentWorkspaceFile) {
        return Get-Content $script:CurrentWorkspaceFile
    }
    return $null
}

function Set-CurrentWorkspace {
    param([string]$Name)
    $Name | Out-File $script:CurrentWorkspaceFile
}

function New-Workspace {
    if (-not $WorkspaceName) {
        $WorkspaceName = Read-Host "Enter workspace name"
    }
    
    $workspacePath = "$script:WorkspacesRoot\$WorkspaceName"
    
    if (Test-Path $workspacePath) {
        Write-Error "Workspace '$WorkspaceName' already exists"
        return
    }
    
    Write-Status "Creating workspace: $WorkspaceName"
    
    # Create workspace structure
    New-Item -ItemType Directory -Path $workspacePath -Force | Out-Null
    New-Item -ItemType Directory -Path "$workspacePath\src" -Force | Out-Null
    New-Item -ItemType Directory -Path "$workspacePath\build" -Force | Out-Null
    New-Item -ItemType Directory -Path "$workspacePath\data" -Force | Out-Null
    New-Item -ItemType Directory -Path "$workspacePath\logs" -Force | Out-Null
    New-Item -ItemType Directory -Path "$workspacePath\models" -Force | Out-Null
    New-Item -ItemType Directory -Path "$workspacePath\config" -Force | Out-Null
    
    # Create workspace configuration
    $config = @{
        name = $WorkspaceName
        created = Get-Date -Format "o"
        template = $Template
        rawrxdVersion = "3.2.0"
    }
    
    $config | ConvertTo-Json -Depth 3 | Out-File "$workspacePath\workspace.json"
    
    # Create default config files based on template
    switch ($Template) {
        "development" {
            @{
                debug = $true
                logLevel = "verbose"
                hotReload = $true
            } | ConvertTo-Json | Out-File "$workspacePath\config\settings.json"
        }
        "production" {
            @{
                debug = $false
                logLevel = "error"
                hotReload = $false
            } | ConvertTo-Json | Out-File "$workspacePath\config\settings.json"
        }
        default {
            @{
                debug = $true
                logLevel = "info"
                hotReload = $false
            } | ConvertTo-Json | Out-File "$workspacePath\config\settings.json"
        }
    }
    
    Write-Success "Workspace '$WorkspaceName' created at: $workspacePath"
    
    # Optionally switch to new workspace
    $switchNow = Read-Host "Switch to new workspace now? (y/n)"
    if ($switchNow -eq "y") {
        Switch-Workspace -Name $WorkspaceName
    }
}

function Switch-Workspace {
    param([string]$Name)
    
    if (-not $Name) {
        $Name = $WorkspaceName
    }
    
    if (-not $Name) {
        Write-Error "Workspace name required"
        return
    }
    
    $workspacePath = "$script:WorkspacesRoot\$Name"
    
    if (-not (Test-Path $workspacePath)) {
        Write-Error "Workspace '$Name' not found"
        return
    }
    
    Write-Status "Switching to workspace: $Name"
    
    # Save current workspace
    Set-CurrentWorkspace -Name $Name
    
    # Create symlink or update environment
    $env:RAWRXD_WORKSPACE = $workspacePath
    
    Write-Success "Switched to workspace: $Name"
    Write-Status "Workspace path: $workspacePath"
    Write-Status "Set environment variable: RAWRXD_WORKSPACE"
}

function Get-Workspaces {
    Write-Host ""
    Write-Host "Available Workspaces" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    
    $current = Get-CurrentWorkspace
    $workspaces = Get-ChildItem -Path $script:WorkspacesRoot -Directory -ErrorAction SilentlyContinue
    
    if ($workspaces.Count -eq 0) {
        Write-Warning "No workspaces found"
        Write-Status "Create one with: workspace-manager.ps1 -Action Create -WorkspaceName <name>"
        return
    }
    
    foreach ($ws in $workspaces) {
        $isCurrent = ($ws.Name -eq $current)
        $marker = if ($isCurrent) { "* " } else { "  " }
        $color = if ($isCurrent) { "Green" } else { "White" }
        
        $configPath = "$($ws.FullName)\workspace.json"
        $created = "Unknown"
        if (Test-Path $configPath) {
            $config = Get-Content $configPath | ConvertFrom-Json
            $created = $config.created
        }
        
        Write-Host "$marker$($ws.Name)" -ForegroundColor $color
        Write-Host "    Created: $created"
        Write-Host "    Path: $($ws.FullName)"
    }
    
    Write-Host ""
    Write-Host "Current: $current" -ForegroundColor Green
}

function Remove-Workspace {
    if (-not $WorkspaceName) {
        $WorkspaceName = Read-Host "Enter workspace name to delete"
    }
    
    $workspacePath = "$script:WorkspacesRoot\$WorkspaceName"
    
    if (-not (Test-Path $workspacePath)) {
        Write-Error "Workspace '$WorkspaceName' not found"
        return
    }
    
    # Check if current workspace
    $current = Get-CurrentWorkspace
    if ($current -eq $WorkspaceName) {
        Write-Warning "Cannot delete current workspace. Switch to another workspace first."
        return
    }
    
    if (-not $Force) {
        $confirm = Read-Host "Are you sure you want to delete '$WorkspaceName'? This cannot be undone. (yes/no)"
        if ($confirm -ne "yes") {
            Write-Status "Deletion cancelled"
            return
        }
    }
    
    try {
        Remove-Item -Path $workspacePath -Recurse -Force
        Write-Success "Workspace '$WorkspaceName' deleted"
    }
    catch {
        Write-Error "Failed to delete workspace: $_"
    }
}

function Backup-Workspace {
    if (-not $WorkspaceName) {
        $WorkspaceName = Get-CurrentWorkspace
    }
    
    if (-not $WorkspaceName) {
        Write-Error "No workspace specified"
        return
    }
    
    $workspacePath = "$script:WorkspacesRoot\$WorkspaceName"
    
    if (-not (Test-Path $workspacePath)) {
        Write-Error "Workspace '$WorkspaceName' not found"
        return
    }
    
    if (-not (Test-Path $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupFile = "$BackupPath\$WorkspaceName-$timestamp.zip"
    
    Write-Status "Backing up workspace: $WorkspaceName"
    
    try {
        Compress-Archive -Path "$workspacePath\*" -DestinationPath $backupFile -Force
        Write-Success "Workspace backed up to: $backupFile"
    }
    catch {
        Write-Error "Backup failed: $_"
    }
}

function Copy-Workspace {
    if (-not $SourceWorkspace) {
        $SourceWorkspace = Get-CurrentWorkspace
    }
    
    if (-not $SourceWorkspace) {
        Write-Error "Source workspace not specified"
        return
    }
    
    if (-not $WorkspaceName) {
        $WorkspaceName = Read-Host "Enter name for new workspace"
    }
    
    $sourcePath = "$script:WorkspacesRoot\$SourceWorkspace"
    $destPath = "$script:WorkspacesRoot\$WorkspaceName"
    
    if (-not (Test-Path $sourcePath)) {
        Write-Error "Source workspace not found: $SourceWorkspace"
        return
    }
    
    if (Test-Path $destPath) {
        Write-Error "Destination workspace already exists: $WorkspaceName"
        return
    }
    
    Write-Status "Cloning workspace: $SourceWorkspace -> $WorkspaceName"
    
    try {
        Copy-Item -Path $sourcePath -Destination $destPath -Recurse
        
        # Update workspace config
        $configPath = "$destPath\workspace.json"
        if (Test-Path $configPath) {
            $config = Get-Content $configPath | ConvertFrom-Json
            $config.name = $WorkspaceName
            $config.created = Get-Date -Format "o"
            $config.clonedFrom = $SourceWorkspace
            $config | ConvertTo-Json -Depth 3 | Out-File $configPath
        }
        
        Write-Success "Workspace cloned successfully"
    }
    catch {
        Write-Error "Clone failed: $_"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Workspace Manager" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-WorkspaceManager
    
    switch ($Action) {
        "Create" { New-Workspace }
        "Switch" { Switch-Workspace }
        "List" { Get-Workspaces }
        "Delete" { Remove-Workspace }
        "Backup" { Backup-Workspace }
        "Clone" { Copy-Workspace }
    }
    
    Write-Host ""
}

Main
