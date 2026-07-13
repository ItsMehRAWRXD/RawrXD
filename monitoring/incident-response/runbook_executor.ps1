# runbook_executor.ps1
# Phase H.5 Batch 5/5: Automated Incident Response Runbooks

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("service-down", "high-latency", "low-tps", "memory-pressure", "disk-full", "custom")]
    [string]$IncidentType,
    
    [string]$CustomRunbook = $null,
    [switch]$DryRun,
    [switch]$AutoApprove
)

$ErrorActionPreference = "Stop"

$Runbooks = @{
    "service-down" = @{
        Name = "Service Down Recovery"
        Description = "Automatically recovers from service outage"
        Severity = "critical"
        AutoExecute = $true
        Steps = @(
            @{ 
                Name = "Check Service Status"
                Command = "Get-Service -Name 'RawrXD' | Select-Object Status"
                Verify = "return `$result.Status -eq 'Running'"
            },
            @{
                Name = "Restart Service"
                Command = "Restart-Service -Name 'RawrXD' -Force"
                Condition = "`$service.Status -ne 'Running'"
                Verify = "Start-Sleep 5; return (Get-Service -Name 'RawrXD').Status -eq 'Running'"
            },
            @{
                Name = "Verify Health"
                Command = "Invoke-RestMethod -Uri 'http://localhost:8080/health' -TimeoutSec 10"
                Verify = "return `$result.status -eq 'healthy'"
            }
        )
    }
    
    "high-latency" = @{
        Name = "High Latency Mitigation"
        Description = "Reduces inference latency by scaling resources"
        Severity = "warning"
        AutoExecute = $false
        Steps = @(
            @{
                Name = "Check Current Load"
                Command = "Invoke-RestMethod -Uri 'http://localhost:8080/metrics' -TimeoutSec 5"
            },
            @{
                Name = "Scale Workers"
                Command = "Invoke-RestMethod -Uri 'http://localhost:8080/admin/scale' -Method POST -Body '{\"workers\": 8}' -ContentType 'application/json'"
                Condition = "`$metrics.active_requests -gt 50"
            },
            @{
                Name = "Clear Cache"
                Command = "Invoke-RestMethod -Uri 'http://localhost:8080/admin/cache/clear' -Method POST"
            }
        )
    }
    
    "low-tps" = @{
        Name = "Low TPS Recovery"
        Description = "Investigates and resolves low throughput issues"
        Severity = "warning"
        AutoExecute = $false
        Steps = @(
            @{
                Name = "Check GPU Status"
                Command = "nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits"
            },
            @{
                Name = "Check Model Cache"
                Command = "Get-ChildItem -Path '${env:ProgramData}\RawrXD\cache\models' | Measure-Object"
            },
            @{
                Name = "Restart Inference Engine"
                Command = "Invoke-RestMethod -Uri 'http://localhost:8080/admin/restart-engine' -Method POST"
            }
        )
    }
    
    "memory-pressure" = @{
        Name = "Memory Pressure Relief"
        Description = "Frees memory when usage is critically high"
        Severity = "critical"
        AutoExecute = $true
        Steps = @(
            @{
                Name = "Clear Model Cache"
                Command = "Invoke-RestMethod -Uri 'http://localhost:8080/admin/cache/clear' -Method POST"
            },
            @{
                Name = "Reduce Batch Size"
                Command = "Invoke-RestMethod -Uri 'http://localhost:8080/admin/config' -Method POST -Body '{\"batch_size\": 1}' -ContentType 'application/json'"
            },
            @{
                Name = "Force GC"
                Command = "Invoke-RestMethod -Uri 'http://localhost:8080/admin/gc' -Method POST"
            }
        )
    }
    
    "disk-full" = @{
        Name = "Disk Space Recovery"
        Description = "Frees disk space when critically low"
        Severity = "critical"
        AutoExecute = $true
        Steps = @(
            @{
                Name = "Clear Old Logs"
                Command = "Get-ChildItem -Path '${env:ProgramData}\RawrXD\logs' -File | Where-Object { `$_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force"
            },
            @{
                Name = "Clear Temp Files"
                Command = "Remove-Item -Path '${env:TEMP}\RawrXD*' -Recurse -Force -ErrorAction SilentlyContinue"
            },
            @{
                Name = "Archive Old Models"
                Command = "Get-ChildItem -Path '${env:ProgramData}\RawrXD\models' -File | Where-Object { `$_.LastAccessTime -lt (Get-Date).AddDays(-30) } | Compress-Archive -DestinationPath '${env:ProgramData}\RawrXD\archived_models.zip' -Update"
            }
        )
    }
}

function Write-Log($Message, $Level = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        "STEP" { "Cyan" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Invoke-RunbookStep($Step, $StepNumber, $TotalSteps) {
    Write-Log "Step $StepNumber/$TotalSteps`: $($Step.Name)" "STEP"
    
    if ($DryRun) {
        Write-Log "DRY RUN: Would execute: $($Step.Command)"
        return @{ Success = $true; Output = "DRY RUN" }
    }
    
    try {
        # Execute the command
        $result = Invoke-Expression $Step.Command
        
        # Verify if verification script provided
        if ($Step.Verify) {
            $verifyScript = $Step.Verify -replace '`$result', '$result'
            $verified = Invoke-Expression $verifyScript
            
            if (-not $verified) {
                return @{ Success = $false; Output = $result; Error = "Verification failed" }
            }
        }
        
        return @{ Success = $true; Output = $result }
    }
    catch {
        return @{ Success = $false; Output = $null; Error = $_.Exception.Message }
    }
}

function Invoke-Runbook($Runbook) {
    Write-Log "Executing Runbook: $($Runbook.Name)"
    Write-Log "Description: $($Runbook.Description)"
    Write-Log "Severity: $($Runbook.Severity)"
    Write-Log ""
    
    $executionLog = @{
        RunbookName = $Runbook.Name
        StartTime = Get-Date -Format "o"
        Steps = @()
        Success = $false
    }
    
    $stepNumber = 1
    foreach ($step in $Runbook.Steps) {
        # Check condition if present
        if ($step.Condition) {
            $conditionMet = Invoke-Expression $step.Condition
            if (-not $conditionMet) {
                Write-Log "Skipping step (condition not met): $($step.Name)"
                $stepNumber++
                continue
            }
        }
        
        $result = Invoke-RunbookStep -Step $step -StepNumber $stepNumber -TotalSteps $Runbook.Steps.Count
        
        $stepLog = @{
            Name = $step.Name
            Success = $result.Success
            Output = $result.Output
            Error = $result.Error
            Timestamp = Get-Date -Format "o"
        }
        
        $executionLog.Steps += $stepLog
        
        if (-not $result.Success) {
            Write-Log "Step failed: $($step.Name)" "ERROR"
            if ($result.Error) {
                Write-Log "Error: $($result.Error)" "ERROR"
            }
            break
        }
        
        Write-Log "Step completed successfully" "SUCCESS"
        $stepNumber++
    }
    
    $executionLog.EndTime = Get-Date -Format "o"
    $executionLog.Success = ($executionLog.Steps | Where-Object { $_.Success }).Count -eq $executionLog.Steps.Count
    
    # Save execution log
    $logFile = Join-Path $env:ProgramData "RawrXD\logs\runbook_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $executionLog | ConvertTo-Json -Depth 5 | Out-File $logFile
    
    Write-Log ""
    if ($executionLog.Success) {
        Write-Log "Runbook completed successfully" "SUCCESS"
        Write-Log "Log saved: $logFile"
        return $true
    }
    else {
        Write-Log "Runbook failed" "ERROR"
        Write-Log "Log saved: $logFile"
        return $false
    }
}

function Show-RunbookMenu {
    Write-Host ""
    Write-Host "Available Runbooks:" -ForegroundColor Cyan
    Write-Host ""
    
    $index = 1
    foreach ($runbook in $Runbooks.GetEnumerator()) {
        $color = switch ($runbook.Value.Severity) {
            "critical" { "Red" }
            "warning" { "Yellow" }
            default { "White" }
        }
        Write-Host "  $index. [$($runbook.Value.Severity.ToUpper())] $($runbook.Value.Name)" -ForegroundColor $color
        Write-Host "     $($runbook.Value.Description)"
        Write-Host ""
        $index++
    }
}

# Main execution
Write-Log "RawrXD Incident Response Runbook Executor v1.0"
Write-Log ""

if ($IncidentType -eq "custom") {
    if (-not $CustomRunbook) {
        Write-Log "Custom runbook path required for 'custom' incident type" "ERROR"
        exit 1
    }
    
    if (-not (Test-Path $CustomRunbook)) {
        Write-Log "Custom runbook not found: $CustomRunbook" "ERROR"
        exit 1
    }
    
    $runbook = Get-Content $CustomRunbook | ConvertFrom-Json
}
else {
    $runbook = $Runbooks[$IncidentType]
}

if (-not $runbook) {
    Write-Log "Unknown incident type: $IncidentType" "ERROR"
    Show-RunbookMenu
    exit 1
}

# Confirm execution
if (-not $AutoApprove -and -not $DryRun) {
    Write-Host ""
    Write-Host "Runbook: $($runbook.Name)" -ForegroundColor Cyan
    Write-Host "Description: $($runbook.Description)" -ForegroundColor Gray
    Write-Host "Severity: $($runbook.Severity)" -ForegroundColor $(if ($runbook.Severity -eq "critical") { "Red" } else { "Yellow" })
    Write-Host ""
    Write-Host "Steps to execute:" -ForegroundColor Cyan
    $stepNum = 1
    foreach ($step in $runbook.Steps) {
        Write-Host "  $stepNum. $($step.Name)"
        $stepNum++
    }
    Write-Host ""
    
    $confirm = Read-Host "Execute this runbook? (yes/no)"
    if ($confirm -ne "yes") {
        Write-Log "Execution cancelled by user"
        exit 0
    }
}

# Execute runbook
$success = Invoke-Runbook -Runbook $runbook

if ($success) {
    exit 0
}
else {
    exit 1
}
