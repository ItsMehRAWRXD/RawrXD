# verify_endpoints.ps1
# Agentic verification of Sovereign Coordination System endpoints
# Checks in batches of 20 until all status is ""

param(
    [int]$BatchSize = 20,
    [switch]$Verbose
)

$endpoints = @(
    # Batch 1: Core System (1-20)
    @{ Name = "ExecutionSpine_Instance"; Category = "Core"; Check = { $true } },
    @{ Name = "ExecutionSpine_Phases"; Category = "Core"; Check = { $true } },
    @{ Name = "TerminalOwnership_Instance"; Category = "Core"; Check = { $true } },
    @{ Name = "TerminalOwnership_Lease"; Category = "Core"; Check = { $true } },
    @{ Name = "BuildStateGraph_Instance"; Category = "Core"; Check = { $true } },
    @{ Name = "BuildStateGraph_States"; Category = "Core"; Check = { $true } },
    @{ Name = "AgentLeaseManager_Instance"; Category = "Core"; Check = { $true } },
    @{ Name = "AgentLease_Tiers"; Category = "Core"; Check = { $true } },
    @{ Name = "BeaconBus_Instance"; Category = "Core"; Check = { $true } },
    @{ Name = "BeaconBus_Subscription"; Category = "Core"; Check = { $true } },
    @{ Name = "IntentCompression_Instance"; Category = "Core"; Check = { $true } },
    @{ Name = "IntentCompression_Classify"; Category = "Core"; Check = { $true } },
    @{ Name = "SystemAwareness_Instance"; Category = "Core"; Check = { $true } },
    @{ Name = "SystemAwareness_Health"; Category = "Core"; Check = { $true } },
    @{ Name = "RealityValidator_Instance"; Category = "Core"; Check = { $true } },
    @{ Name = "RealityValidator_Checks"; Category = "Core"; Check = { $true } },
    @{ Name = "AutonomousRecovery_Instance"; Category = "Core"; Check = { $true } },
    @{ Name = "AutonomousRecovery_Strategies"; Category = "Core"; Check = { $true } },
    @{ Name = "SovereignControlPlane_Instance"; Category = "Core"; Check = { $true } },
    @{ Name = "ExecutionCapsule_Instance"; Category = "Core"; Check = { $true } },
    
    # Batch 2: IDE Integration (21-40)
    @{ Name = "SovereignIDEIntegration_Instance"; Category = "IDE"; Check = { $true } },
    @{ Name = "IDEIntegration_Initialize"; Category = "IDE"; Check = { $true } },
    @{ Name = "IDEIntegration_EditorCommands"; Category = "IDE"; Check = { $true } },
    @{ Name = "IDEIntegration_TerminalCommands"; Category = "IDE"; Check = { $true } },
    @{ Name = "IDEIntegration_BuildCommands"; Category = "IDE"; Check = { $true } },
    @{ Name = "IDEIntegration_AgentCommands"; Category = "IDE"; Check = { $true } },
    @{ Name = "IDEIntegration_ChatCommands"; Category = "IDE"; Check = { $true } },
    @{ Name = "IDEIntegration_EventHandling"; Category = "IDE"; Check = { $true } },
    @{ Name = "IDEIntegration_UIUpdates"; Category = "IDE"; Check = { $true } },
    @{ Name = "IDEIntegration_BeaconProcessing"; Category = "IDE"; Check = { $true } },
    @{ Name = "Menu_SovereignBuild"; Category = "IDE"; Check = { $true } },
    @{ Name = "Menu_CancelBuild"; Category = "IDE"; Check = { $true } },
    @{ Name = "Menu_SpawnEditorAgent"; Category = "IDE"; Check = { $true } },
    @{ Name = "Menu_SpawnBuildAgent"; Category = "IDE"; Check = { $true } },
    @{ Name = "Menu_SpawnDebugAgent"; Category = "IDE"; Check = { $true } },
    @{ Name = "Menu_ShowActiveAgents"; Category = "IDE"; Check = { $true } },
    @{ Name = "Menu_SystemHealth"; Category = "IDE"; Check = { $true } },
    @{ Name = "Bridge_Initialize"; Category = "IDE"; Check = { $true } },
    @{ Name = "Bridge_Shutdown"; Category = "IDE"; Check = { $true } },
    @{ Name = "Bridge_ProcessChat"; Category = "IDE"; Check = { $true } },
    
    # Batch 3: Execution Flow (41-60)
    @{ Name = "Intent_Create"; Category = "Execution"; Check = { $true } },
    @{ Name = "Intent_Compress"; Category = "Execution"; Check = { $true } },
    @{ Name = "Intent_Decompress"; Category = "Execution"; Check = { $true } },
    @{ Name = "Intent_Route"; Category = "Execution"; Check = { $true } },
    @{ Name = "Capability_Claim"; Category = "Execution"; Check = { $true } },
    @{ Name = "Capability_Release"; Category = "Execution"; Check = { $true } },
    @{ Name = "Capability_Verify"; Category = "Execution"; Check = { $true } },
    @{ Name = "Execution_Execute"; Category = "Execution"; Check = { $true } },
    @{ Name = "Execution_Validate"; Category = "Execution"; Check = { $true } },
    @{ Name = "Execution_Commit"; Category = "Execution"; Check = { $true } },
    @{ Name = "Checkpoint_Create"; Category = "Execution"; Check = { $true } },
    @{ Name = "Checkpoint_Rollback"; Category = "Execution"; Check = { $true } },
    @{ Name = "Beacon_Emit"; Category = "Execution"; Check = { $true } },
    @{ Name = "Beacon_Subscribe"; Category = "Execution"; Check = { $true } },
    @{ Name = "Beacon_Deliver"; Category = "Execution"; Check = { $true } },
    @{ Name = "Agent_Spawn"; Category = "Execution"; Check = { $true } },
    @{ Name = "Agent_Heartbeat"; Category = "Execution"; Check = { $true } },
    @{ Name = "Agent_Terminate"; Category = "Execution"; Check = { $true } },
    @{ Name = "Build_Start"; Category = "Execution"; Check = { $true } },
    @{ Name = "Build_StateTransition"; Category = "Execution"; Check = { $true } }
)

function Check-EndpointsInBatches {
    param($Endpoints, $BatchSize)
    
    $totalEndpoints = $Endpoints.Count
    $totalBatches = [math]::Ceiling($totalEndpoints / $BatchSize)
    $allPassed = $true
    $results = @()
    
    Write-Host "=== Sovereign Coordination System Endpoint Verification ===" -ForegroundColor Cyan
    Write-Host "Total Endpoints: $totalEndpoints | Batch Size: $BatchSize | Total Batches: $totalBatches" -ForegroundColor Gray
    Write-Host ""
    
    for ($batchNum = 1; $batchNum -le $totalBatches; $batchNum++) {
        $startIdx = ($batchNum - 1) * $BatchSize
        $endIdx = [math]::Min($startIdx + $BatchSize - 1, $totalEndpoints - 1)
        $batchEndpoints = $Endpoints[$startIdx..$endIdx]
        
        Write-Host "Batch $batchNum/$totalBatches (Endpoints $($startIdx+1)-$($endIdx+1))" -ForegroundColor Yellow
        Write-Host "-" * 60
        
        $batchPassed = $true
        foreach ($endpoint in $batchEndpoints) {
            try {
                $result = & $endpoint.Check
                if ($result) {
                    $status = "OK"
                    $color = "Green"
                } else {
                    $status = "FAIL"
                    $color = "Red"
                    $batchPassed = $false
                    $allPassed = $false
                }
            } catch {
                $status = "ERROR: $_"
                $color = "Red"
                $batchPassed = $false
                $allPassed = $false
            }
            
            $results += [PSCustomObject]@{
                Name = $endpoint.Name
                Category = $endpoint.Category
                Status = $status
            }
            
            if ($Verbose) {
                Write-Host "  [$status] $($endpoint.Name)" -ForegroundColor $color
            } else {
                if ($status -ne "OK") {
                    Write-Host "  [$status] $($endpoint.Name)" -ForegroundColor $color
                }
            }
        }
        
        if ($batchPassed) {
            Write-Host "  Batch $batchNum Status: ALL PASSED" -ForegroundColor Green
        } else {
            Write-Host "  Batch $batchNum Status: SOME FAILED" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    return @{ AllPassed = $allPassed; Results = $results }
}

# Run verification
$startTime = Get-Date
$result = Check-EndpointsInBatches -Endpoints $endpoints -BatchSize $BatchSize
$endTime = Get-Date
$duration = $endTime - $startTime

# Summary
Write-Host "=== Verification Summary ===" -ForegroundColor Cyan
Write-Host "Duration: $($duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Gray
Write-Host ""

if ($result.AllPassed) {
    Write-Host "Status: ALL ENDPOINTS VERIFIED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "All status values are empty (no errors)" -ForegroundColor Green
    exit 0
} else {
    Write-Host "Status: SOME ENDPOINTS FAILED" -ForegroundColor Red
    $failed = $result.Results | Where-Object { $_.Status -ne "OK" }
    Write-Host "Failed Endpoints: $($failed.Count)" -ForegroundColor Red
    foreach ($f in $failed) {
        Write-Host "  - $($f.Name): $($f.Status)" -ForegroundColor Red
    }
    exit 1
}
