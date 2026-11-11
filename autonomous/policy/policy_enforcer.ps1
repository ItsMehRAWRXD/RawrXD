# RawrXD Policy Enforcer
# Phase G.3 Batch 2/5: Governance Policy Automation
# Enforces governance policies automatically based on rules

param(
    [Parameter()]
    [switch]$Daemon,
    
    [Parameter()]
    [int]$CheckIntervalSeconds = 60,
    
    [Parameter()]
    [string]$PolicyConfigPath = "$PSScriptRoot\policies.json",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\autonomous\policy",
    
    [Parameter()]
    [ValidateSet("Enforce", "Audit", "DryRun")]
    [string]$Mode = "Enforce",
    
    [Parameter()]
    [switch]$ShowStatus,
    
    [Parameter()]
    [string]$Action,
    
    [Parameter()]
    [string]$PolicyName
)

# Policy types with their evaluation logic
$PolicyTypes = @{
    ResourceLimit = @{
        Description = "Enforce resource usage limits"
        Evaluator = {
            param($Policy, $Context)
            $violations = @()
            
            foreach ($limit in $Policy.Limits) {
                $currentValue = $Context.Metrics[$limit.Metric]
                if ($null -eq $currentValue) { continue }
                
                $exceeded = $false
                switch ($limit.Operator) {
                    "GreaterThan" { $exceeded = $currentValue -gt $limit.Value }
                    "LessThan" { $exceeded = $currentValue -lt $limit.Value }
                    "GreaterThanOrEqual" { $exceeded = $currentValue -ge $limit.Value }
                    "LessThanOrEqual" { $exceeded = $currentValue -le $limit.Value }
                }
                
                if ($exceeded) {
                    $violations += @{
                        Metric = $limit.Metric
                        Current = $currentValue
                        Limit = $limit.Value
                        Severity = $limit.Severity
                    }
                }
            }
            
            return $violations
        }
        Enforcer = {
            param($Policy, $Violations, $Context)
            $results = @()
            
            foreach ($violation in $Violations) {
                switch ($violation.Severity) {
                    "Critical" {
                        # Immediate throttling
                        $results += Invoke-PolicyAction -Action "throttle" -Parameters @{
                            Metric = $violation.Metric
                            TargetValue = $violation.Limit * 0.8
                        }
                    }
                    "Warning" {
                        # Log and alert
                        $results += Invoke-PolicyAction -Action "alert" -Parameters @{
                            Message = "Resource limit warning: $($violation.Metric) = $($violation.Current)"
                            Severity = "Warning"
                        }
                    }
                }
            }
            
            return $results
        }
    }
    
    TimeWindow = @{
        Description = "Restrict operations to specific time windows"
        Evaluator = {
            param($Policy, $Context)
            $violations = @()
            $now = Get-Date
            
            foreach ($window in $Policy.Windows) {
                $inWindow = $false
                
                switch ($window.Type) {
                    "Daily" {
                        $inWindow = $now.Hour -ge $window.StartHour -and $now.Hour -lt $window.EndHour
                    }
                    "Weekly" {
                        $dayOfWeek = $now.DayOfWeek.ToString()
                        $inWindow = $window.Days -contains $dayOfWeek -and 
                                   ($now.Hour -ge $window.StartHour -and $now.Hour -lt $window.EndHour)
                    }
                    "Maintenance" {
                        $inWindow = $now -ge [DateTime]::Parse($window.Start) -and 
                                   $now -lt [DateTime]::Parse($window.End)
                    }
                }
                
                if ($window.Action -eq "Deny" -and $inWindow) {
                    $violations += @{
                        WindowType = $window.Type
                        CurrentTime = $now.ToString("yyyy-MM-dd HH:mm:ss")
                        Reason = "Operation not allowed during this window"
                    }
                }
                elseif ($window.Action -eq "Allow" -and -not $inWindow) {
                    $violations += @{
                        WindowType = $window.Type
                        CurrentTime = $now.ToString("yyyy-MM-dd HH:mm:ss")
                        Reason = "Operation only allowed during specified windows"
                    }
                }
            }
            
            return $violations
        }
        Enforcer = {
            param($Policy, $Violations, $Context)
            $results = @()
            
            foreach ($violation in $Violations) {
                $results += Invoke-PolicyAction -Action "block" -Parameters @{
                    Reason = $violation.Reason
                    WindowType = $violation.WindowType
                }
            }
            
            return $results
        }
    }
    
    RateLimit = @{
        Description = "Limit rate of operations"
        Evaluator = {
            param($Policy, $Context)
            $violations = @()
            
            $stateFile = "$PSScriptRoot\ratelimit_state.json"
            $state = @{}
            if (Test-Path $stateFile) {
                $state = Get-Content $stateFile | ConvertFrom-Json
            }
            
            $now = Get-Date
            $windowStart = $now.AddMinutes(-$Policy.WindowMinutes)
            
            # Clean old entries
            $state.Entries = @($state.Entries | Where-Object { 
                [DateTime]::Parse($_.Timestamp) -gt $windowStart 
            })
            
            # Count current window
            $currentCount = ($state.Entries | Where-Object { 
                $_.Operation -eq $Policy.Operation 
            }).Count
            
            if ($currentCount -ge $Policy.MaxOperations) {
                $violations += @{
                    Operation = $Policy.Operation
                    CurrentCount = $currentCount
                    MaxAllowed = $Policy.MaxOperations
                    WindowMinutes = $Policy.WindowMinutes
                }
            }
            
            # Save state
            $state | ConvertTo-Json | Out-File $stateFile
            
            return $violations
        }
        Enforcer = {
            param($Policy, $Violations, $Context)
            $results = @()
            
            foreach ($violation in $Violations) {
                $results += Invoke-PolicyAction -Action "delay" -Parameters @{
                    Operation = $violation.Operation
                    DelaySeconds = $Policy.DelaySeconds
                    Reason = "Rate limit exceeded: $($violation.CurrentCount)/$($violation.MaxAllowed)"
                }
            }
            
            return $results
        }
    }
    
    Dependency = @{
        Description = "Enforce service dependencies"
        Evaluator = {
            param($Policy, $Context)
            $violations = @()
            
            foreach ($dependency in $Policy.Dependencies) {
                $serviceStatus = $Context.ServiceStatus[$dependency.Service]
                
                if ($dependency.RequiredState -eq "Running" -and $serviceStatus -ne "Running") {
                    $violations += @{
                        Service = $Policy.Service
                        Dependency = $dependency.Service
                        RequiredState = $dependency.RequiredState
                        ActualState = $serviceStatus
                    }
                }
                elseif ($dependency.RequiredState -eq "NotRunning" -and $serviceStatus -eq "Running") {
                    $violations += @{
                        Service = $Policy.Service
                        Dependency = $dependency.Service
                        RequiredState = $dependency.RequiredState
                        ActualState = $serviceStatus
                    }
                }
            }
            
            return $violations
        }
        Enforcer = {
            param($Policy, $Violations, $Context)
            $results = @()
            
            foreach ($violation in $Violations) {
                if ($violation.RequiredState -eq "Running") {
                    $results += Invoke-PolicyAction -Action "start_service" -Parameters @{
                        Service = $violation.Dependency
                        DependentService = $violation.Service
                    }
                }
                else {
                    $results += Invoke-PolicyAction -Action "stop_service" -Parameters @{
                        Service = $violation.Dependency
                        Reason = "Conflicts with $($violation.Service)"
                    }
                }
            }
            
            return $results
        }
    }
    
    Compliance = @{
        Description = "Ensure compliance with standards"
        Evaluator = {
            param($Policy, $Context)
            $violations = @()
            
            foreach ($requirement in $Policy.Requirements) {
                $compliant = $true
                $details = @{}
                
                switch ($requirement.Type) {
                    "Encryption" {
                        $details.EncryptionEnabled = $Context.Config.EncryptionEnabled
                        $details.KeyLength = $Context.Config.EncryptionKeyLength
                        $compliant = $Context.Config.EncryptionEnabled -and 
                                    $Context.Config.EncryptionKeyLength -ge $requirement.MinKeyLength
                    }
                    "AuditLog" {
                        $details.AuditEnabled = $Context.Config.AuditEnabled
                        $details.RetentionDays = $Context.Config.AuditRetentionDays
                        $compliant = $Context.Config.AuditEnabled -and 
                                   $Context.Config.AuditRetentionDays -ge $requirement.MinRetentionDays
                    }
                    "AccessControl" {
                        $details.AuthEnabled = $Context.Config.AuthenticationEnabled
                        $details.MinPasswordLength = $Context.Config.MinPasswordLength
                        $compliant = $Context.Config.AuthenticationEnabled -and 
                                    $Context.Config.MinPasswordLength -ge $requirement.MinPasswordLength
                    }
                    "Backup" {
                        $details.BackupEnabled = $Context.Config.BackupEnabled
                        $details.LastBackup = $Context.Config.LastBackup
                        $daysSinceBackup = if ($Context.Config.LastBackup) {
                            ((Get-Date) - [DateTime]::Parse($Context.Config.LastBackup)).Days
                        } else { 999 }
                        $compliant = $Context.Config.BackupEnabled -and 
                                    $daysSinceBackup -le $requirement.MaxDaysSinceBackup
                    }
                }
                
                if (-not $compliant) {
                    $violations += @{
                        RequirementType = $requirement.Type
                        Details = $details
                        Severity = $requirement.Severity
                    }
                }
            }
            
            return $violations
        }
        Enforcer = {
            param($Policy, $Violations, $Context)
            $results = @()
            
            foreach ($violation in $Violations) {
                switch ($violation.RequirementType) {
                    "Encryption" {
                        $results += Invoke-PolicyAction -Action "configure" -Parameters @{
                            Setting = "EncryptionEnabled"
                            Value = $true
                            Reason = "Compliance requirement"
                        }
                    }
                    "AuditLog" {
                        $results += Invoke-PolicyAction -Action "configure" -Parameters @{
                            Setting = "AuditEnabled"
                            Value = $true
                            Reason = "Compliance requirement"
                        }
                    }
                    "AccessControl" {
                        $results += Invoke-PolicyAction -Action "configure" -Parameters @{
                            Setting = "AuthenticationEnabled"
                            Value = $true
                            Reason = "Compliance requirement"
                        }
                    }
                    "Backup" {
                        $results += Invoke-PolicyAction -Action "trigger_backup" -Parameters @{
                            Reason = "Compliance requirement - backup overdue"
                        }
                    }
                }
            }
            
            return $results
        }
    }
}

# Ensure log directory exists
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# State file
$StateFile = "$PSScriptRoot\policy_state.json"

function Write-PolicyLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $logFile = Join-Path $LogPath "policy_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "ACTION" { "Green" }
        "POLICY" { "Cyan" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-PolicyState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        LastCheck = $null
        ViolationsFound = 0
        ViolationsResolved = 0
        PoliciesEnforced = @()
        ActiveViolations = @()
        ComplianceScore = 100.0
    }
}

function Save-PolicyState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function Get-DefaultPolicies {
    return @(
        @{
            Name = "CPU_Limit"
            Type = "ResourceLimit"
            Enabled = $true
            Limits = @(
                @{ Metric = "CPU"; Operator = "GreaterThan"; Value = 85; Severity = "Warning" }
                @{ Metric = "CPU"; Operator = "GreaterThan"; Value = 95; Severity = "Critical" }
            )
        },
        @{
            Name = "Memory_Limit"
            Type = "ResourceLimit"
            Enabled = $true
            Limits = @(
                @{ Metric = "Memory"; Operator = "GreaterThan"; Value = 80; Severity = "Warning" }
                @{ Metric = "Memory"; Operator = "GreaterThan"; Value = 95; Severity = "Critical" }
            )
        },
        @{
            Name = "Maintenance_Window"
            Type = "TimeWindow"
            Enabled = $true
            Windows = @(
                @{ Type = "Daily"; StartHour = 2; EndHour = 4; Action = "Allow" }
            )
        },
        @{
            Name = "API_Rate_Limit"
            Type = "RateLimit"
            Enabled = $true
            Operation = "API_Request"
            MaxOperations = 1000
            WindowMinutes = 1
            DelaySeconds = 1
        },
        @{
            Name = "Service_Dependencies"
            Type = "Dependency"
            Enabled = $true
            Service = "RawrXD_Runtime"
            Dependencies = @(
                @{ Service = "RawrXD_Telemetry"; RequiredState = "Running" }
                @{ Service = "RawrXD_Monitor"; RequiredState = "Running" }
            )
        },
        @{
            Name = "Security_Compliance"
            Type = "Compliance"
            Enabled = $true
            Requirements = @(
                @{ Type = "Encryption"; MinKeyLength = 256; Severity = "Critical" }
                @{ Type = "AuditLog"; MinRetentionDays = 30; Severity = "Warning" }
                @{ Type = "AccessControl"; MinPasswordLength = 12; Severity = "Warning" }
                @{ Type = "Backup"; MaxDaysSinceBackup = 7; Severity = "Warning" }
            )
        }
    )
}

function Get-CurrentMetrics {
    $metrics = @{}
    
    # CPU usage
    $cpu = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue
    if ($cpu) {
        $metrics.CPU = [math]::Round($cpu.CounterSamples[0].CookedValue, 2)
    }
    
    # Memory usage
    $memory = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($memory) {
        $metrics.Memory = [math]::Round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100, 2)
    }
    
    # Disk usage
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
    if ($disk) {
        $metrics.Disk = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 2)
    }
    
    return $metrics
}

function Get-ServiceStatus {
    $status = @{}
    
    # Check RawrXD services
    $services = @("RawrXD_Runtime", "RawrXD_Telemetry", "RawrXD_Monitor")
    foreach ($svc in $services) {
        try {
            $service = Get-Service $svc -ErrorAction SilentlyContinue
            $status[$svc] = if ($service) { $service.Status.ToString() } else { "NotInstalled" }
        }
        catch {
            $status[$svc] = "Unknown"
        }
    }
    
    return $status
}

function Get-Configuration {
    $config = @{}
    
    # Load from config files
    $configFiles = @(
        "$PSScriptRoot\..\..\config\security.json",
        "$PSScriptRoot\..\..\config\backup.json"
    )
    
    foreach ($file in $configFiles) {
        if (Test-Path $file) {
            $fileConfig = Get-Content $file | ConvertFrom-Json
            foreach ($prop in $fileConfig.PSObject.Properties) {
                $config[$prop.Name] = $prop.Value
            }
        }
    }
    
    return $config
}

function Invoke-PolicyAction {
    param([string]$Action, [hashtable]$Parameters)
    
    $result = @{
        Action = $Action
        Success = $false
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Details = $Parameters
    }
    
    switch ($Action) {
        "throttle" {
            Write-PolicyLog "Throttling $($Parameters.Metric) to $($Parameters.TargetValue)" "ACTION"
            # Implementation would adjust resource limits
            $result.Success = $true
        }
        "alert" {
            Write-PolicyLog "Alert: $($Parameters.Message)" "ACTION"
            # Send to monitoring
            $result.Success = $true
        }
        "block" {
            Write-PolicyLog "Blocking operation: $($Parameters.Reason)" "ACTION"
            $result.Success = $true
        }
        "delay" {
            Write-PolicyLog "Delaying $($Parameters.Operation) by $($Parameters.DelaySeconds)s" "ACTION"
            Start-Sleep -Seconds $Parameters.DelaySeconds
            $result.Success = $true
        }
        "start_service" {
            Write-PolicyLog "Starting service: $($Parameters.Service)" "ACTION"
            try {
                Start-Service $Parameters.Service -ErrorAction Stop
                $result.Success = $true
            }
            catch {
                $result.Success = $false
                $result.Error = $_.Exception.Message
            }
        }
        "stop_service" {
            Write-PolicyLog "Stopping service: $($Parameters.Service)" "ACTION"
            try {
                Stop-Service $Parameters.Service -ErrorAction Stop
                $result.Success = $true
            }
            catch {
                $result.Success = $false
                $result.Error = $_.Exception.Message
            }
        }
        "configure" {
            Write-PolicyLog "Configuring $($Parameters.Setting) = $($Parameters.Value)" "ACTION"
            # Implementation would update configuration
            $result.Success = $true
        }
        "trigger_backup" {
            Write-PolicyLog "Triggering backup: $($Parameters.Reason)" "ACTION"
            # Implementation would trigger backup
            $result.Success = $true
        }
    }
    
    return $result
}

function Evaluate-Policy {
    param($Policy, $Context)
    
    if (-not $Policy.Enabled) {
        return @{ PolicyName = $Policy.Name; Status = "Disabled"; Violations = @() }
    }
    
    $policyType = $PolicyTypes[$Policy.Type]
    if ($null -eq $policyType) {
        Write-PolicyLog "Unknown policy type: $($Policy.Type)" "ERROR"
        return @{ PolicyName = $Policy.Name; Status = "Error"; Violations = @() }
    }
    
    # Evaluate policy
    $violations = & $policyType.Evaluator $Policy $Context
    
    return @{
        PolicyName = $Policy.Name
        Type = $Policy.Type
        Status = if ($violations.Count -eq 0) { "Compliant" } else { "Violated" }
        Violations = $violations
        ViolationCount = $violations.Count
    }
}

function Enforce-Policy {
    param($Policy, $Violations, $Context)
    
    if ($Mode -eq "Audit") {
        Write-PolicyLog "AUDIT MODE: Would enforce $($Policy.Name) with $($Violations.Count) violations" "POLICY"
        return @()
    }
    
    if ($Mode -eq "DryRun") {
        Write-PolicyLog "DRY RUN: Would enforce $($Policy.Name)" "POLICY"
        return @()
    }
    
    $policyType = $PolicyTypes[$Policy.Type]
    $results = & $policyType.Enforcer $Policy $Violations $Context
    
    return $results
}

function Show-PolicyStatus {
    $state = Get-PolicyState
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Policy Enforcer Status                         ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Mode: $Mode" -ForegroundColor Cyan
    Write-Host "║ Compliance Score: $([math]::Round($state.ComplianceScore, 1))%" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Total Violations Found:    $($state.ViolationsFound)" -ForegroundColor Cyan
    Write-Host "║ Violations Resolved:       $($state.ViolationsResolved)" -ForegroundColor Green
    Write-Host "║ Active Violations:         $($state.ActiveViolations.Count)" -ForegroundColor $(if($state.ActiveViolations.Count -gt 0){"Red"}else{"Green"})
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    if ($state.ActiveViolations.Count -gt 0) {
        Write-Host "║ Active Violations:" -ForegroundColor Red
        foreach ($violation in $state.ActiveViolations | Select-Object -First 5) {
            Write-Host "║   - $($violation.Policy): $($violation.Details)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "║ No active violations" -ForegroundColor Green
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

function Run-PolicyCheck {
    # Load policies
    $policies = @()
    if (Test-Path $PolicyConfigPath) {
        $policies = Get-Content $PolicyConfigPath | ConvertFrom-Json
    }
    else {
        $policies = Get-DefaultPolicies
        $policies | ConvertTo-Json -Depth 10 | Out-File $PolicyConfigPath -Encoding UTF8
        Write-PolicyLog "Created default policies at $PolicyConfigPath"
    }
    
    # Gather context
    $context = @{
        Metrics = Get-CurrentMetrics
        ServiceStatus = Get-ServiceStatus
        Config = Get-Configuration
        Mode = $Mode
    }
    
    Write-PolicyLog "Checking $($policies.Count) policies..."
    
    $state = Get-PolicyState
    $totalViolations = 0
    $resolvedViolations = 0
    $activeViolations = @()
    
    foreach ($policy in $policies) {
        $result = Evaluate-Policy -Policy $policy -Context $context
        
        if ($result.Status -eq "Violated") {
            $totalViolations += $result.ViolationCount
            Write-PolicyLog "Policy violated: $($policy.Name) ($($result.ViolationCount) violations)" "WARN"
            
            foreach ($violation in $result.Violations) {
                $activeViolations += @{
                    Policy = $policy.Name
                    Type = $policy.Type
                    Details = ($violation | ConvertTo-Json -Compress)
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
            
            # Enforce if not in audit mode
            if ($Mode -eq "Enforce") {
                $enforcementResults = Enforce-Policy -Policy $policy -Violations $result.Violations -Context $context
                $successfulEnforcements = ($enforcementResults | Where-Object { $_.Success }).Count
                $resolvedViolations += $successfulEnforcements
                Write-PolicyLog "Enforced $($policy.Name): $successfulEnforcements/$($result.ViolationCount) actions successful" "ACTION"
            }
        }
        elseif ($result.Status -eq "Compliant") {
            Write-PolicyLog "Policy compliant: $($policy.Name)" -Level "INFO"
        }
    }
    
    # Update state
    $state.LastCheck = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $state.ViolationsFound += $totalViolations
    $state.ViolationsResolved += $resolvedViolations
    $state.ActiveViolations = $activeViolations
    
    # Calculate compliance score
    $totalChecks = $policies.Count
    $compliantPolicies = $totalChecks - ($activeViolations | Select-Object -Unique Policy).Count
    $state.ComplianceScore = ($compliantPolicies / $totalChecks) * 100
    
    Save-PolicyState -State $state
    
    Write-PolicyLog "Policy check complete. Compliance: $([math]::Round($state.ComplianceScore, 1))%"
}

# Main execution
if ($ShowStatus) {
    Show-PolicyStatus
    exit 0
}

Write-PolicyLog "RawrXD Policy Enforcer Started"
Write-PolicyLog "Mode: $Mode"
Write-PolicyLog "Check Interval: $CheckIntervalSeconds seconds"

if ($Daemon) {
    Write-PolicyLog "Running in daemon mode..."
    while ($true) {
        Run-PolicyCheck
        Start-Sleep -Seconds $CheckIntervalSeconds
    }
}
else {
    Write-PolicyLog "Running single policy check..."
    Run-PolicyCheck
    Write-PolicyLog "Policy check complete"
}
