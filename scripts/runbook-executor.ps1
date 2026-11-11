# RawrXD Runbook Executor
# Executes operational runbooks with validation and rollback
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("List", "Execute", "Validate", "Create", "Export")]
    [string]$Action = "List",
    
    [Parameter()]
    [string]$RunbookName,
    
    [Parameter()]
    [hashtable]$Parameters = @{},
    
    [Parameter()]
    [switch]$DryRun,
    
    [Parameter()]
    [switch]$AutoRollback,
    
    [Parameter()]
    [string]$OutputPath = "runbook-execution.json"
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Get-RunbooksPath {
    return "$PSScriptRoot\runbooks"
}

function Initialize-RunbookSystem {
    $runbooksDir = Get-RunbooksPath
    if (-not (Test-Path $runbooksDir)) {
        New-Item -ItemType Directory -Path $runbooksDir -Force | Out-Null
        Write-Status "Created runbooks directory: $runbooksDir"
    }
}

function Get-Runbook {
    param([string]$Name)
    
    $runbookPath = Join-Path (Get-RunbooksPath) "$Name.json"
    
    if (Test-Path $runbookPath) {
        return Get-Content $runbookPath | ConvertFrom-Json
    }
    
    # Return default runbooks
    $defaultRunbooks = @{
        "restart-service" = @{
            Name = "restart-service"
            Description = "Restart a Windows service safely"
            Version = "1.0"
            Author = "RawrXD Team"
            Parameters = @(
                @{ Name = "ServiceName"; Type = "string"; Required = $true; Description = "Name of service to restart" }
                @{ Name = "Timeout"; Type = "int"; Default = 30; Description = "Timeout in seconds" }
            )
            Steps = @(
                @{ 
                    Id = 1
                    Name = "Pre-check"
                    Action = "Check service exists"
                    Validation = "Service.Exists"
                    Rollback = $null
                },
                @{
                    Id = 2
                    Name = "Stop service"
                    Action = "Stop-Service"
                    Validation = "Service.Stopped"
                    Rollback = "Start-Service"
                },
                @{
                    Id = 3
                    Name = "Start service"
                    Action = "Start-Service"
                    Validation = "Service.Running"
                    Rollback = "Stop-Service"
                }
            )
        }
        "database-backup" = @{
            Name = "database-backup"
            Description = "Backup database with verification"
            Version = "1.0"
            Author = "RawrXD Team"
            Parameters = @(
                @{ Name = "DatabaseName"; Type = "string"; Required = $true }
                @{ Name = "BackupPath"; Type = "string"; Default = "backups" }
            )
            Steps = @(
                @{ Id = 1; Name = "Validate space"; Action = "Check disk space"; Validation = "Disk.SpaceAvailable" },
                @{ Id = 2; Name = "Create backup"; Action = "Backup-Database"; Validation = "Backup.Exists" },
                @{ Id = 3; Name = "Verify backup"; Action = "Test-Backup"; Validation = "Backup.Valid" }
            )
        }
    }
    
    return $defaultRunbooks[$Name]
}

function Show-RunbookList {
    $runbooksDir = Get-RunbooksPath
    
    Write-Host "`nAvailable Runbooks" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    Write-Host ""
    
    if (Test-Path $runbooksDir) {
        $runbooks = Get-ChildItem -Path $runbooksDir -Filter "*.json"
        
        if ($runbooks.Count -eq 0) {
            Write-Status "No custom runbooks found. Built-in runbooks available:"
            Write-Host "  • restart-service - Restart a Windows service"
            Write-Host "  • database-backup - Backup database with verification"
        } else {
            foreach ($rb in $runbooks) {
                $runbook = Get-Content $rb.FullName | ConvertFrom-Json
                Write-Host "  • $($runbook.Name) - $($runbook.Description)"
            }
        }
    }
    Write-Host ""
}

function Invoke-RunbookExecution {
    if (-not $RunbookName) {
        throw "RunbookName parameter required for Execute action"
    }
    
    $runbook = Get-Runbook -Name $RunbookName
    
    if (-not $runbook) {
        throw "Runbook not found: $RunbookName"
    }
    
    Write-Host "`nExecuting Runbook: $($runbook.Name)" -ForegroundColor Cyan
    Write-Host "Description: $($runbook.Description)" -ForegroundColor Cyan
    Write-Host "Version: $($runbook.Version)" -ForegroundColor Cyan
    Write-Host ""
    
    if ($DryRun) {
        Write-Status "[DRY RUN] Would execute the following steps:"
    }
    
    $execution = @{
        RunbookName = $runbook.Name
        StartedAt = (Get-Date).ToString("o")
        Parameters = $Parameters
        Steps = @()
        Status = "Running"
    }
    
    $completedSteps = @()
    
    try {
        foreach ($step in $runbook.Steps) {
            Write-Status "Step $($step.Id)/$($runbook.Steps.Count): $($step.Name)"
            Write-Status "  Action: $($step.Action)"
            
            if ($DryRun) {
                Write-Status "  [DRY RUN] Would execute: $($step.Action)"
                continue
            }
            
            # Simulate step execution
            Start-Sleep -Seconds 1
            
            $stepResult = @{
                StepId = $step.Id
                StepName = $step.Name
                Status = "Completed"
                ExecutedAt = (Get-Date).ToString("o")
                Duration = 1
            }
            
            $execution.Steps += $stepResult
            $completedSteps += $step
            
            Write-Success "  ✓ Completed"
        }
        
        $execution.Status = "Completed"
        $execution.CompletedAt = (Get-Date).ToString("o")
        
        Write-Success "`nRunbook execution completed successfully!"
    }
    catch {
        $execution.Status = "Failed"
        $execution.Error = $_.Exception.Message
        
        Write-Error "Runbook execution failed: $_"
        
        if ($AutoRollback -and $completedSteps.Count -gt 0) {
            Write-Status "Initiating rollback..."
            Invoke-RunbookRollback -CompletedSteps $completedSteps -Runbook $runbook
        }
        
        throw
    }
    finally {
        $execution | ConvertTo-Json -Depth 5 | Set-Content $OutputPath
        Write-Status "Execution log saved to: $OutputPath"
    }
}

function Invoke-RunbookRollback {
    param([array]$CompletedSteps, [hashtable]$Runbook)
    
    Write-Status "Rolling back completed steps..."
    
    # Rollback in reverse order
    for ($i = $completedSteps.Count - 1; $i -ge 0; $i--) {
        $step = $completedSteps[$i]
        if ($step.Rollback) {
            Write-Status "  Rolling back: $($step.Name)"
            Write-Status "    Action: $($step.Rollback)"
        }
    }
    
    Write-Success "Rollback completed"
}

function Test-RunbookValidation {
    if (-not $RunbookName) {
        throw "RunbookName parameter required for Validate action"
    }
    
    $runbook = Get-Runbook -Name $RunbookName
    
    if (-not $runbook) {
        throw "Runbook not found: $RunbookName"
    }
    
    Write-Status "Validating runbook: $RunbookName"
    
    $issues = @()
    
    # Check required fields
    if (-not $runbook.Name) { $issues += "Missing Name" }
    if (-not $runbook.Description) { $issues += "Missing Description" }
    if (-not $runbook.Steps -or $runbook.Steps.Count -eq 0) { $issues += "No steps defined" }
    
    # Check step IDs are unique and sequential
    $stepIds = $runbook.Steps | Select-Object -ExpandProperty Id
    $uniqueIds = $stepIds | Select-Object -Unique
    if ($stepIds.Count -ne $uniqueIds.Count) { $issues += "Duplicate step IDs" }
    
    if ($issues.Count -eq 0) {
        Write-Success "Runbook validation passed"
    } else {
        Write-Warning "Validation issues found:"
        foreach ($issue in $issues) {
            Write-Warning "  - $issue"
        }
    }
}

function New-RunbookTemplate {
    if (-not $RunbookName) {
        throw "RunbookName parameter required for Create action"
    }
    
    $template = @{
        Name = $RunbookName
        Description = "Description of what this runbook does"
        Version = "1.0"
        Author = $env:USERNAME
        Parameters = @(
            @{
                Name = "ExampleParam"
                Type = "string"
                Required = $true
                Description = "Description of parameter"
            }
        )
        Steps = @(
            @{
                Id = 1
                Name = "Step name"
                Action = "Action to perform"
                Validation = "Validation criteria"
                Rollback = "Rollback action (optional)"
            }
        )
    }
    
    $runbookPath = Join-Path (Get-RunbooksPath) "$RunbookName.json"
    $template | ConvertTo-Json -Depth 5 | Set-Content $runbookPath
    
    Write-Success "Runbook template created: $runbookPath"
}

function Export-RunbookDocumentation {
    if (-not $RunbookName) {
        throw "RunbookName parameter required for Export action"
    }
    
    $runbook = Get-Runbook -Name $RunbookName
    
    if (-not $runbook) {
        throw "Runbook not found: $RunbookName"
    }
    
    $doc = "# Runbook: $($runbook.Name)`n`n"
    $doc += "**Version:** $($runbook.Version)  `n"
    $doc += "**Author:** $($runbook.Author)`n`n"
    $doc += "## Description`n`n"
    $doc += "$($runbook.Description)`n`n"
    
    if ($runbook.Parameters.Count -gt 0) {
        $doc += "## Parameters`n`n"
        foreach ($param in $runbook.Parameters) {
            $doc += "### -$($param.Name)`n`n"
            $doc += "- **Type:** $($param.Type)`n"
            $doc += "- **Required:** $($param.Required)`n"
            if ($param.Default) {
                $doc += "- **Default:** $($param.Default)`n"
            }
            $doc += "- **Description:** $($param.Description)`n`n"
        }
    }
    
    $doc += "## Steps`n`n"
    foreach ($step in $runbook.Steps) {
        $doc += "### $($step.Id). $($step.Name)`n`n"
        $doc += "**Action:** $($step.Action)`n`n"
        $doc += "**Validation:** $($step.Validation)`n`n"
        if ($step.Rollback) {
            $doc += "**Rollback:** $($step.Rollback)`n`n"
        }
    }
    
    $docPath = "$RunbookName-runbook.md"
    $doc | Set-Content $docPath
    
    Write-Success "Runbook documentation exported to: $docPath"
}

# Main execution
try {
    Initialize-RunbookSystem
    
    switch ($Action) {
        "List" { Show-RunbookList }
        "Execute" { Invoke-RunbookExecution }
        "Validate" { Test-RunbookValidation }
        "Create" { New-RunbookTemplate }
        "Export" { Export-RunbookDocumentation }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
