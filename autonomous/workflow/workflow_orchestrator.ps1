# RawrXD Workflow Orchestrator
# Phase G.3 Batch 3/5: Complex Multi-Step Workflow Automation
# Orchestrates complex workflows with dependencies, retries, and rollback

param(
    [Parameter()]
    [switch]$Daemon,
    
    [Parameter()]
    [int]$PollIntervalSeconds = 10,
    
    [Parameter()]
    [string]$WorkflowsPath = "$PSScriptRoot\workflows",
    
    [Parameter()]
    [string]$StatePath = "$PSScriptRoot\workflow_state",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\autonomous\workflow",
    
    [Parameter()]
    [string]$Action,
    
    [Parameter()]
    [string]$WorkflowName,
    
    [Parameter()]
    [hashtable]$Parameters = @{}
)

# Workflow step types
$StepTypes = @{
    Command = @{
        Description = "Execute PowerShell command or script"
        Executor = {
            param($Step, $Context)
            
            try {
                $output = $null
                if ($Step.ScriptBlock) {
                    $sb = [ScriptBlock]::Create($Step.ScriptBlock)
                    $output = & $sb @Context.Parameters
                }
                elseif ($Step.Command) {
                    $output = Invoke-Expression $Step.Command
                }
                
                return @{
                    Success = $true
                    Output = $output
                    ExitCode = 0
                }
            }
            catch {
                return @{
                    Success = $false
                    Output = $null
                    Error = $_.Exception.Message
                    ExitCode = 1
                }
            }
        }
    }
    
    Decision = @{
        Description = "Branch based on condition"
        Executor = {
            param($Step, $Context)
            
            try {
                $condition = $Step.Condition
                $result = $false
                
                # Evaluate condition
                if ($condition.Expression) {
                    $sb = [ScriptBlock]::Create($condition.Expression)
                    $result = & $sb @Context.Results
                }
                elseif ($condition.Variable) {
                    $result = $Context.Results[$condition.Variable] -eq $condition.ExpectedValue
                }
                
                $branch = if ($result) { $Step.TrueBranch } else { $Step.FalseBranch }
                
                return @{
                    Success = $true
                    Output = @{ Branch = $branch; ConditionResult = $result }
                    ExitCode = 0
                }
            }
            catch {
                return @{
                    Success = $false
                    Output = $null
                    Error = $_.Exception.Message
                    ExitCode = 1
                }
            }
        }
    }
    
    Wait = @{
        Description = "Wait for condition or time"
        Executor = {
            param($Step, $Context)
            
            try {
                if ($Step.Duration) {
                    Start-Sleep -Seconds $Step.Duration
                }
                elseif ($Step.Condition) {
                    $timeout = $Step.TimeoutSeconds -or 300
                    $elapsed = 0
                    $interval = $Step.CheckIntervalSeconds -or 5
                    
                    while ($elapsed -lt $timeout) {
                        $sb = [ScriptBlock]::Create($Step.Condition)
                        if (& $sb @Context.Results) {
                            return @{
                                Success = $true
                                Output = @{ Waited = $elapsed }
                                ExitCode = 0
                            }
                        }
                        Start-Sleep -Seconds $interval
                        $elapsed += $interval
                    }
                    
                    return @{
                        Success = $false
                        Output = @{ Waited = $elapsed }
                        Error = "Timeout waiting for condition"
                        ExitCode = 1
                    }
                }
                
                return @{ Success = $true; Output = $null; ExitCode = 0 }
            }
            catch {
                return @{
                    Success = $false
                    Output = $null
                    Error = $_.Exception.Message
                    ExitCode = 1
                }
            }
        }
    }
    
    Parallel = @{
        Description = "Execute steps in parallel"
        Executor = {
            param($Step, $Context)
            
            try {
                $jobs = @()
                foreach ($subStep in $Step.Steps) {
                    $job = Start-Job -ScriptBlock {
                        param($StepType, $StepDef, $Ctx)
                        $executor = $StepTypes[$StepType].Executor
                        & $executor $StepDef $Ctx
                    } -ArgumentList $subStep.Type, $subStep, $Context
                    $jobs += $job
                }
                
                # Wait for all jobs with timeout
                $timeout = $Step.TimeoutSeconds -or 300
                $completed = $jobs | Wait-Job -Timeout $timeout
                
                $results = @()
                $allSuccess = $true
                
                foreach ($job in $jobs) {
                    if ($job.State -eq "Completed") {
                        $result = Receive-Job $job
                        $results += $result
                        if (-not $result.Success) { $allSuccess = $false }
                    }
                    else {
                        Stop-Job $job
                        $results += @{ Success = $false; Error = "Timeout or failed"; ExitCode = 1 }
                        $allSuccess = $false
                    }
                    Remove-Job $job
                }
                
                return @{
                    Success = $allSuccess
                    Output = @{ Results = $results }
                    ExitCode = if ($allSuccess) { 0 } else { 1 }
                }
            }
            catch {
                return @{
                    Success = $false
                    Output = $null
                    Error = $_.Exception.Message
                    ExitCode = 1
                }
            }
        }
    }
    
    SubWorkflow = @{
        Description = "Execute another workflow"
        Executor = {
            param($Step, $Context)
            
            try {
                $subWorkflow = Get-Workflow -Name $Step.WorkflowName
                if ($null -eq $subWorkflow) {
                    return @{
                        Success = $false
                        Error = "Sub-workflow not found: $($Step.WorkflowName)"
                        ExitCode = 1
                    }
                }
                
                # Merge parameters
                $subParams = @{}
                if ($Step.Parameters) {
                    foreach ($key in $Step.Parameters.Keys) {
                        $subParams[$key] = $Step.Parameters[$key]
                    }
                }
                if ($Context.Parameters) {
                    foreach ($key in $Context.Parameters.Keys) {
                        if (-not $subParams.ContainsKey($key)) {
                            $subParams[$key] = $Context.Parameters[$key]
                        }
                    }
                }
                
                $result = Execute-Workflow -Workflow $subWorkflow -Parameters $subParams
                
                return @{
                    Success = $result.Success
                    Output = $result
                    ExitCode = if ($result.Success) { 0 } else { 1 }
                }
            }
            catch {
                return @{
                    Success = $false
                    Output = $null
                    Error = $_.Exception.Message
                    ExitCode = 1
                }
            }
        }
    }
    
    Notification = @{
        Description = "Send notification"
        Executor = {
            param($Step, $Context)
            
            try {
                $message = $Step.Message
                if ($Step.Template) {
                    # Simple template substitution
                    foreach ($key in $Context.Results.Keys) {
                        $message = $message -replace "{{$key}}", $Context.Results[$key]
                    }
                }
                
                Write-WorkflowLog "Notification: $message" "NOTIFY"
                
                # Send to monitoring if configured
                if ($Step.SendToMonitoring) {
                    $monitor = "$PSScriptRoot\..\..\governance\monitoring\health_monitor.ps1"
                    if (Test-Path $monitor) {
                        & $monitor -Action alert -Message $message -Severity $Step.Severity
                    }
                }
                
                return @{ Success = $true; Output = @{ Message = $message }; ExitCode = 0 }
            }
            catch {
                return @{
                    Success = $false
                    Output = $null
                    Error = $_.Exception.Message
                    ExitCode = 1
                }
            }
        }
    }
}

# Ensure directories exist
if (-not (Test-Path $WorkflowsPath)) {
    New-Item -ItemType Directory -Path $WorkflowsPath -Force | Out-Null
}
if (-not (Test-Path $StatePath)) {
    New-Item -ItemType Directory -Path $StatePath -Force | Out-Null
}
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

function Write-WorkflowLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $logFile = Join-Path $LogPath "workflow_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "ACTION" { "Green" }
        "NOTIFY" { "Cyan" }
        "STEP" { "Magenta" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-WorkflowState {
    param([string]$WorkflowId)
    
    $stateFile = Join-Path $StatePath "$WorkflowId.json"
    if (Test-Path $stateFile) {
        return Get-Content $stateFile | ConvertFrom-Json
    }
    return $null
}

function Save-WorkflowState {
    param($State)
    
    $stateFile = Join-Path $StatePath "$($State.WorkflowId).json"
    $State | ConvertTo-Json -Depth 10 | Out-File $stateFile -Encoding UTF8
}

function Get-Workflow {
    param([string]$Name)
    
    $workflowFile = Join-Path $WorkflowsPath "$Name.json"
    if (Test-Path $workflowFile) {
        return Get-Content $workflowFile | ConvertFrom-Json
    }
    return $null
}

function Get-DefaultWorkflows {
    return @{
        "deployment" = @{
            Name = "deployment"
            Description = "Full deployment workflow"
            Version = "1.0"
            Parameters = @{
                Environment = @{ Type = "string"; Default = "staging"; Required = $true }
                Version = @{ Type = "string"; Required = $true }
                SkipTests = @{ Type = "boolean"; Default = $false }
            }
            Steps = @(
                @{ 
                    Id = "validate"
                    Name = "Validate Parameters"
                    Type = "Command"
                    ScriptBlock = @"
param(`$Params)
if (-not `$Params.Version) { throw "Version is required" }
Write-Host "Validating deployment of version `$(`$Params.Version) to `$(`$Params.Environment)"
@{ Valid = `$true; Environment = `$Params.Version }
"@
                },
                @{
                    Id = "backup"
                    Name = "Backup Current State"
                    Type = "Command"
                    ScriptBlock = @"
param(`$Params)
Write-Host "Backing up current state..."
@{ BackupId = [Guid]::NewGuid().ToString(); Timestamp = Get-Date }
"@
                },
                @{
                    Id = "deploy"
                    Name = "Deploy New Version"
                    Type = "Command"
                    DependsOn = @("validate")
                    ScriptBlock = @"
param(`$Params)
Write-Host "Deploying version `$(`$Params.Version)..."
Start-Sleep -Seconds 2
@{ Deployed = `$true; Version = `$Params.Version }
"@
                },
                @{
                    Id = "health_check"
                    Name = "Health Check"
                    Type = "Command"
                    DependsOn = @("deploy")
                    ScriptBlock = @"
param(`$Params)
Write-Host "Running health checks..."
@{ Healthy = `$true; ChecksPassed = 5 }
"@
                },
                @{
                    Id = "notify"
                    Name = "Send Notification"
                    Type = "Notification"
                    DependsOn = @("health_check")
                    Message = "Deployment of {{Version}} to {{Environment}} completed successfully"
                    Template = $true
                    Severity = "Info"
                    SendToMonitoring = $true
                }
            )
            OnFailure = @{
                Action = "rollback"
                Steps = @(
                    @{ 
                        Id = "rollback_deploy"
                        Name = "Rollback Deployment"
                        Type = "Command"
                        ScriptBlock = "Write-Host 'Rolling back deployment...'; @{ RolledBack = `$true }"
                    }
                )
            }
        }
        
        "maintenance" = @{
            Name = "maintenance"
            Description = "System maintenance workflow"
            Version = "1.0"
            Parameters = @{
                MaintenanceType = @{ Type = "string"; Default = "routine"; Required = $true }
            }
            Steps = @(
                @{
                    Id = "notify_start"
                    Name = "Notify Maintenance Start"
                    Type = "Notification"
                    Message = "Starting {{MaintenanceType}} maintenance"
                    Template = $true
                    Severity = "Warning"
                    SendToMonitoring = $true
                },
                @{
                    Id = "drain"
                    Name = "Drain Traffic"
                    Type = "Command"
                    ScriptBlock = @"
param(`$Params)
Write-Host "Draining traffic..."
@{ Drained = `$true; Connections = 0 }
"@
                },
                @{
                    Id = "maintenance_tasks"
                    Name = "Run Maintenance Tasks"
                    Type = "Parallel"
                    DependsOn = @("drain")
                    TimeoutSeconds = 600
                    Steps = @(
                        @{ Type = "Command"; ScriptBlock = "Write-Host 'Task 1'; Start-Sleep 1; @{ Task = 1 }" },
                        @{ Type = "Command"; ScriptBlock = "Write-Host 'Task 2'; Start-Sleep 1; @{ Task = 2 }" },
                        @{ Type = "Command"; ScriptBlock = "Write-Host 'Task 3'; Start-Sleep 1; @{ Task = 3 }" }
                    )
                },
                @{
                    Id = "restore"
                    Name = "Restore Traffic"
                    Type = "Command"
                    DependsOn = @("maintenance_tasks")
                    ScriptBlock = "Write-Host 'Restoring traffic...'; @{ Restored = `$true }"
                },
                @{
                    Id = "notify_complete"
                    Name = "Notify Maintenance Complete"
                    Type = "Notification"
                    DependsOn = @("restore")
                    Message = "{{MaintenanceType}} maintenance completed successfully"
                    Template = $true
                    Severity = "Info"
                    SendToMonitoring = $true
                }
            )
        }
        
        "scaling" = @{
            Name = "scaling"
            Description = "Auto-scaling workflow"
            Version = "1.0"
            Parameters = @{
                Direction = @{ Type = "string"; Required = $true }
                Amount = @{ Type = "int"; Default = 1 }
                Reason = @{ Type = "string"; Default = "capacity" }
            }
            Steps = @(
                @{
                    Id = "evaluate"
                    Name = "Evaluate Scaling Need"
                    Type = "Decision"
                    Condition = @{ Expression = "`$Params.Direction -eq 'up'" }
                    TrueBranch = "scale_up"
                    FalseBranch = "scale_down"
                },
                @{
                    Id = "scale_up"
                    Name = "Scale Up"
                    Type = "Command"
                    ScriptBlock = @"
param(`$Params)
Write-Host "Scaling up by `$(`$Params.Amount) units..."
@{ Scaled = `$true; Direction = "up"; NewCapacity = 10 + `$Params.Amount }
"@
                },
                @{
                    Id = "scale_down"
                    Name = "Scale Down"
                    Type = "Command"
                    ScriptBlock = @"
param(`$Params)
Write-Host "Scaling down by `$(`$Params.Amount) units..."
@{ Scaled = `$true; Direction = "down"; NewCapacity = 10 - `$Params.Amount }
"@
                },
                @{
                    Id = "verify"
                    Name = "Verify Scaling"
                    Type = "Wait"
                    Condition = "`$Results.scaled -eq `$true"
                    TimeoutSeconds = 120
                    CheckIntervalSeconds = 5
                },
                @{
                    Id = "notify"
                    Name = "Notify Scaling Complete"
                    Type = "Notification"
                    Message = "Scaling {{Direction}} completed. New capacity: {{NewCapacity}}"
                    Template = $true
                    Severity = "Info"
                    SendToMonitoring = $true
                }
            )
        }
    }
}

function Initialize-DefaultWorkflows {
    $defaults = Get-DefaultWorkflows
    foreach ($name in $defaults.Keys) {
        $workflowFile = Join-Path $WorkflowsPath "$name.json"
        if (-not (Test-Path $workflowFile)) {
            $defaults[$name] | ConvertTo-Json -Depth 10 | Out-File $workflowFile -Encoding UTF8
            Write-WorkflowLog "Created default workflow: $name"
        }
    }
}

function Execute-Step {
    param($Step, $Context)
    
    $stepType = $StepTypes[$Step.Type]
    if ($null -eq $stepType) {
        return @{
            Success = $false
            Error = "Unknown step type: $($Step.Type)"
            ExitCode = 1
        }
    }
    
    Write-WorkflowLog "Executing step: $($Step.Name) [$($Step.Type)]" "STEP"
    
    $startTime = Get-Date
    $result = & $stepType.Executor $Step $Context
    $endTime = Get-Date
    
    $result.Duration = ($endTime - $startTime).TotalSeconds
    $result.StepId = $Step.Id
    $result.StepName = $Step.Name
    $result.StartTime = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
    $result.EndTime = $endTime.ToString("yyyy-MM-dd HH:mm:ss")
    
    if ($result.Success) {
        Write-WorkflowLog "Step completed: $($Step.Name) ($([math]::Round($result.Duration, 2))s)" "ACTION"
    }
    else {
        Write-WorkflowLog "Step failed: $($Step.Name) - $($result.Error)" "ERROR"
    }
    
    return $result
}

function Execute-Workflow {
    param($Workflow, [hashtable]$Parameters = @{})
    
    $workflowId = [Guid]::NewGuid().ToString()
    $startTime = Get-Date
    
    Write-WorkflowLog "Starting workflow: $($Workflow.Name) [ID: $workflowId]"
    
    # Initialize state
    $state = @{
        WorkflowId = $workflowId
        WorkflowName = $Workflow.Name
        Status = "Running"
        StartTime = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
        EndTime = $null
        Parameters = $Parameters
        Steps = @()
        Results = @{}
        CurrentStep = $null
        RetryCount = 0
    }
    
    Save-WorkflowState -State $state
    
    try {
        # Build execution graph
        $stepMap = @{}
        $dependencyGraph = @{}
        
        foreach ($step in $Workflow.Steps) {
            $stepMap[$step.Id] = $step
            $dependencyGraph[$step.Id] = if ($step.DependsOn) { $step.DependsOn } else { @() }
        }
        
        # Topological sort for execution order
        $executionOrder = @()
        $visited = @{}
        $visiting = @{}
        
        function Visit-Step {
            param([string]$StepId)
            
            if ($visiting[$StepId]) {
                throw "Circular dependency detected involving step: $StepId"
            }
            if ($visited[$StepId]) { return }
            
            $visiting[$StepId] = $true
            
            foreach ($dep in $dependencyGraph[$StepId]) {
                Visit-Step $dep
            }
            
            $visiting[$StepId] = $false
            $visited[$StepId] = $true
            $executionOrder += $StepId
        }
        
        foreach ($stepId in $stepMap.Keys) {
            Visit-Step $stepId
        }
        
        # Execute steps
        $context = @{
            Parameters = $Parameters
            Results = @{}
            Workflow = $Workflow
        }
        
        foreach ($stepId in $executionOrder) {
            $step = $stepMap[$stepId]
            $state.CurrentStep = $stepId
            Save-WorkflowState -State $state
            
            # Execute with retry logic
            $maxRetries = $step.RetryCount -or 0
            $retryDelay = $step.RetryDelaySeconds -or 5
            $stepResult = $null
            $attempt = 0
            
            do {
                $stepResult = Execute-Step -Step $step -Context $context
                $attempt++
                
                if (-not $stepResult.Success -and $attempt -le $maxRetries) {
                    Write-WorkflowLog "Retrying step $($step.Name) (attempt $attempt/$maxRetries)" "WARN"
                    Start-Sleep -Seconds $retryDelay
                }
            } while (-not $stepResult.Success -and $attempt -le $maxRetries)
            
            # Store result
            $context.Results[$stepId] = $stepResult.Output
            $state.Results[$stepId] = $stepResult.Output
            $state.Steps += $stepResult
            Save-WorkflowState -State $state
            
            # Handle failure
            if (-not $stepResult.Success) {
                if ($Workflow.OnFailure) {
                    Write-WorkflowLog "Executing failure handler..." "WARN"
                    foreach ($rollbackStep in $Workflow.OnFailure.Steps) {
                        $rollbackResult = Execute-Step -Step $rollbackStep -Context $context
                        $state.Steps += $rollbackResult
                    }
                }
                
                $state.Status = "Failed"
                $state.EndTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Save-WorkflowState -State $state
                
                Write-WorkflowLog "Workflow failed at step: $($step.Name)" "ERROR"
                return @{ Success = $false; WorkflowId = $workflowId; State = $state }
            }
            
            # Handle decision branches
            if ($step.Type -eq "Decision" -and $stepResult.Output.Branch) {
                # Skip steps not in the selected branch
                $branchSteps = $Workflow.Steps | Where-Object { $_.Id -eq $stepResult.Output.Branch }
                # This is simplified - full implementation would handle branch skipping
            }
        }
        
        # Success
        $state.Status = "Completed"
        $state.EndTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Save-WorkflowState -State $state
        
        $duration = ([DateTime]::Parse($state.EndTime) - $startTime).TotalSeconds
        Write-WorkflowLog "Workflow completed: $($Workflow.Name) ($([math]::Round($duration, 2))s)" "ACTION"
        
        return @{ Success = $true; WorkflowId = $workflowId; State = $state }
    }
    catch {
        $state.Status = "Error"
        $state.EndTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $state.Error = $_.Exception.Message
        Save-WorkflowState -State $state
        
        Write-WorkflowLog "Workflow error: $_" "ERROR"
        return @{ Success = $false; WorkflowId = $workflowId; State = $state; Error = $_.Exception.Message }
    }
}

function Show-WorkflowStatus {
    $states = Get-ChildItem $StatePath -Filter "*.json" | ForEach-Object {
        Get-Content $_.FullName | ConvertFrom-Json
    } | Sort-Object StartTime -Descending
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║         RawrXD Workflow Orchestrator Status                     ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Total Workflows: $($states.Count)" -ForegroundColor Cyan
    Write-Host "║ Running: $(($states | Where-Object { $_.Status -eq 'Running' }).Count)" -ForegroundColor Yellow
    Write-Host "║ Completed: $(($states | Where-Object { $_.Status -eq 'Completed' }).Count)" -ForegroundColor Green
    Write-Host "║ Failed: $(($states | Where-Object { $_.Status -eq 'Failed' -or $_.Status -eq 'Error' }).Count)" -ForegroundColor Red
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    $recent = $states | Select-Object -First 10
    if ($recent.Count -gt 0) {
        Write-Host "║ Recent Workflows:" -ForegroundColor Cyan
        foreach ($wf in $recent) {
            $color = switch ($wf.Status) {
                "Completed" { "Green" }
                "Failed" { "Red" }
                "Running" { "Yellow" }
                default { "Gray" }
            }
            Write-Host "║   [$($wf.Status)] $($wf.WorkflowName) - $($wf.StartTime)" -ForegroundColor $color
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Initialize default workflows
Initialize-DefaultWorkflows

# Main execution
if ($Action -eq "list") {
    $workflows = Get-ChildItem $WorkflowsPath -Filter "*.json" | ForEach-Object {
        $wf = Get-Content $_.FullName | ConvertFrom-Json
        [PSCustomObject]@{
            Name = $wf.Name
            Description = $wf.Description
            Version = $wf.Version
            Steps = $wf.Steps.Count
        }
    }
    $workflows | Format-Table -AutoSize
    exit 0
}

if ($Action -eq "run" -and $WorkflowName) {
    $workflow = Get-Workflow -Name $WorkflowName
    if ($null -eq $workflow) {
        Write-WorkflowLog "Workflow not found: $WorkflowName" "ERROR"
        exit 1
    }
    
    $result = Execute-Workflow -Workflow $workflow -Parameters $Parameters
    exit ($result.Success ? 0 : 1)
}

if ($Action -eq "status" -or $Action -eq "show") {
    Show-WorkflowStatus
    exit 0
}

Write-WorkflowLog "RawrXD Workflow Orchestrator Started"

if ($Daemon) {
    Write-WorkflowLog "Running in daemon mode..."
    while ($true) {
        # Check for queued workflows
        Start-Sleep -Seconds $PollIntervalSeconds
    }
}
else {
    Write-WorkflowLog "Use -Action run -WorkflowName <name> to execute a workflow"
    Write-WorkflowLog "Use -Action list to see available workflows"
    Write-WorkflowLog "Use -Action status to see workflow status"
}
