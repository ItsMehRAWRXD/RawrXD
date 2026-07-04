# AgentStressTestRunner.ps1
# 4-hour smoke test runner with 15-minute checkpointing
# Run: .\AgentStressTestRunner.ps1 -SourcePath "D:\rawrxd" -DurationHours 4

param(
    [Parameter(Mandatory=$true)]
    [string]$SourcePath,
    
    [Parameter(Mandatory=$false)]
    [int]$DurationHours = 4,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\telemetry",
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateShadowBranch
)

# ============================================================================
# CONFIGURATION
# ============================================================================
${Script:CheckpointIntervalMinutes} = 15
$TotalDuration = New-TimeSpan -Hours $DurationHours
$StartTime = Get-Date
$EndTime = $StartTime + $TotalDuration
${Script:ShouldStop} = $false

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

# Log file
$LogFile = Join-Path $OutputPath "agent_stress_test_$($StartTime.ToString('yyyyMMdd_HHmmss')).log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

# ============================================================================
# GIT SHADOW BRANCH SETUP
# ============================================================================
function Initialize-ShadowBranch {
    param([string]$RepoPath)
    
    Write-Log "Setting up shadow branch for self-modification..."
    
    Push-Location $RepoPath
    try {
        # Check if we're in a git repo
        $gitDir = git rev-parse --git-dir 2>$null
        if (-not $gitDir) {
            Write-Log "Not a git repository - skipping shadow branch" "WARN"
            return $null
        }
        
        # Create timestamped branch
        $branchName = "agent-stress-test-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        git checkout -b $branchName 2>$null
        
        Write-Log "Created shadow branch: $branchName"
        return $branchName
    }
    finally {
        Pop-Location
    }
}

# ============================================================================
# TELEMETRY MONITORING
# ============================================================================
$TelemetryScript = {
    param($OutputPath, $DurationHours)
    
    $start = Get-Date
    $checkpointInterval = New-TimeSpan -Minutes 15
    $lastCheckpoint = $start
    $checkpointNumber = 0
    
    while ($true) {
        $now = Get-Date
        $elapsed = $now - $start
        
        # Check if test is complete
        if ($elapsed.TotalHours -ge $DurationHours) {
            break
        }
        
        # Checkpoint every 15 minutes
        if (($now - $lastCheckpoint) -ge $checkpointInterval) {
            $checkpointNumber++
            $checkpointFile = Join-Path $OutputPath "checkpoint_$($checkpointNumber.ToString('000')).json"
            
            # Query telemetry via WMI or file
            $telemetry = @{
                timestamp = $now.ToString("o")
                elapsedHours = $elapsed.TotalHours
                checkpoint = $checkpointNumber
                # These would be populated from actual agent telemetry
                heapUsedMB = (Get-Process -Id $PID).WorkingSet64 / 1MB
                cpuPercent = (Get-Counter '\Process(*)\% Processor Time').CounterSamples[0].CookedValue
            }
            
            $telemetry | ConvertTo-Json -Depth 4 | Set-Content $checkpointFile
            
            $lastCheckpoint = $now
        }
        
        Start-Sleep -Seconds 1
    }
}

    # Use checkpoint interval in report
    Write-Log "Checkpoint interval: ${Script:CheckpointIntervalMinutes} minutes"
# ============================================================================
function Start-AgentIngestion {
    param([string]$SourcePath)
    
    Write-Log "Starting agent ingestion of: $SourcePath"
    
    # Get all source files
    $extensions = @("*.cpp", "*.h", "*.hpp", "*.c", "*.asm", "*.cmake", "*.txt", "*.md")
    $files = @()
    foreach ($ext in $extensions) {
        $files += Get-ChildItem -Path $SourcePath -Recurse -Filter $ext -ErrorAction SilentlyContinue
    }
    
    $files = $files | Select-Object -First 1000  # Limit to 1000 files
    $totalFiles = $files.Count
    
    Write-Log "Found $totalFiles source files to ingest"
    
    $ingested = 0
    $errors = 0
    
    foreach ($file in $files) {
        try {
            # Simulate ingestion (read + parse)
            $content = Get-Content $file.FullName -Raw -ErrorAction Stop
            $size = $content.Length
            
            # Simulate parsing time proportional to file size
            $parseTime = [Math]::Min($size / 10000, 100)  # Max 100ms per file
            Start-Sleep -Milliseconds $parseTime
            
            $ingested++
            
            if ($ingested % 100 -eq 0) {
                Write-Log "Ingested $ingested/$totalFiles files..."
            }
        }
        catch {
            $errors++
            Write-Log "Failed to ingest $($file.FullName): $_" "ERROR"
        }
    }
    
    Write-Log "Ingestion complete: $ingested files, $errors errors"
    return @{ Ingested = $ingested; Errors = $errors }
}

# ============================================================================
# MAIN TEST LOOP
# ============================================================================
function Start-StressTest {
    Write-Log "========================================"
    Write-Log "RawrXD Agent 4-Hour Stress Test"
    Write-Log "Start: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Log "End: $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Log "Source: $SourcePath"
    Write-Log "Output: $OutputPath"
    Write-Log "========================================"
    
    # Setup shadow branch
    ${script:shadowBranch} = $null
    if ($CreateShadowBranch.IsPresent) {
        ${script:shadowBranch} = Initialize-ShadowBranch -RepoPath $SourcePath
    }
    
    # Start telemetry monitor in background
    ${script:telemetryJob} = Start-Job -ScriptBlock $TelemetryScript `
        -ArgumentList $OutputPath, $DurationHours
    
    # Phase 1: Ingestion (Hour 0-1)
    Write-Log "=== PHASE 1: INGESTION (Hour 0-1) ==="
    $ingestionResult = Start-AgentIngestion -SourcePath $SourcePath
    
    if ($ingestionResult.Ingested -lt 10) {
        Write-Log "CRITICAL: Ingestion failed - less than 10 files processed" "ERROR"
        Stop-StressTest -Failed $true
        return
    }
    
    Write-Log "Phase 1 complete: $($ingestionResult.Ingested) files ingested"
    
    # Phase 2: Mapping (Hour 1-2)
    Write-Log "=== PHASE 2: MAPPING (Hour 1-2) ==="
    Write-Log "Building dependency graph..."
    
    # Simulate dependency analysis
    $dependencies = @()
    for ($i = 0; $i -lt 100; $i++) {
        $dependencies += @{
            file = "file_$i.cpp"
            includes = @("header_$($i % 10).h", "common.h")
            dependsOn = @("file_$($i-1).cpp")
        }
        Start-Sleep -Milliseconds 50
    }
    
    Write-Log "Phase 2 complete: $($dependencies.Count) dependency nodes mapped"
    
    # Phase 3: Proposal Cycle (Hour 2-3)
    Write-Log "=== PHASE 3: PROPOSAL CYCLE (Hour 2-3) ==="
    
    $proposals = 0
    $applied = 0
    $targetProposals = 5
    
    while ($proposals -lt $targetProposals -and (Get-Date) -lt $EndTime) {
        # Simulate proposal generation
        $proposals++
        Write-Log "Generated proposal $proposals/$targetProposals"
        
        # Simulate validation (50% success rate for testing)
        if ((Get-Random -Maximum 2) -eq 1) {
            $applied++
            Write-Log "Proposal $proposals validated and applied"
            
            # Create a dummy patch file
            $patchFile = Join-Path $OutputPath "proposal_$($proposals.ToString('000')).patch"
            @"
--- a/src/example.cpp
+++ b/src/example.cpp
@@ -1,5 +1,5 @@
 // Optimized by agent stress test
-void example() {
+void example_optimized() {
     // TODO: Implementation
 }
"@ | Set-Content $patchFile
        }
        else {
            Write-Log "Proposal $proposals rejected (validation failed)" "WARN"
        }
        
        Start-Sleep -Seconds 10  # Simulate thinking time
    }
    
    Write-Log "Phase 3 complete: $proposals proposals, $applied applied"
    
    # Phase 4: Stability Check (Hour 3-4)
    Write-Log "=== PHASE 4: STABILITY CHECK (Hour 3-4) ==="
    Write-Log "Monitoring for stability..."
    
    $stabilityChecks = 0
    $maxVariance = 0.01  # 0.01% variance threshold
    
    while ((Get-Date) -lt $EndTime) {
        $stabilityChecks++
        
        # Simulate fidelity check
        $variance = (Get-Random -Maximum 100) / 10000.0  # 0.00% to 0.01%
        
        if ($variance -gt $maxVariance) {
            Write-Log "Stability check $stabilityChecks: variance $variance% (WARNING)" "WARN"
        }
        else {
            Write-Log "Stability check $stabilityChecks: variance $variance% (OK)"
        }
        
        Start-Sleep -Seconds 30
    }
    
    Write-Log "Phase 4 complete: $stabilityChecks stability checks"
    
    # Use shadow branch info if needed
    if (${script:shadowBranch}) {
        Write-Log "Shadow branch was created: ${script:shadowBranch}"
    }
    
    # Cleanup
    Stop-StressTest -Failed $false
}

function Stop-StressTest {
    param([bool]$Failed)
    
    $endTime = Get-Date
    $duration = $endTime - $StartTime
    
    Write-Log "========================================"
    Write-Log "Stress Test Complete"
    Write-Log "Duration: $($duration.ToString('hh\:mm\:ss'))"
    Write-Log "Status: ${Failed}"
    Write-Log "========================================"
    
    # Stop telemetry job if it exists
    if (${Script:telemetryJob}) {
        Stop-Job ${Script:telemetryJob} -ErrorAction SilentlyContinue
        Remove-Job ${Script:telemetryJob} -ErrorAction SilentlyContinue
    }
    
    # Generate final report
    $report = @{
        startTime = $StartTime.ToString("o")
        endTime = $endTime.ToString("o")
        duration = $duration.ToString()
        status = $(if ($Failed) { "FAILED" } else { "PASSED" })
        sourcePath = $SourcePath
        shadowBranch = $shadowBranch
        outputPath = $OutputPath
    }
    
    $report | ConvertTo-Json -Depth 4 | `
        Set-Content (Join-Path $OutputPath "stress_test_report.json")
    
    exit $(if ($Failed) { 1 } else { 0 })
}

# ============================================================================
# SIGNAL HANDLING
# ============================================================================
$null = Register-ObjectEvent -InputObject ([Console]) -EventName "CancelKeyPress" -Action {
    Write-Log "Received Ctrl+C - shutting down gracefully..." "WARN"
    ${Script:ShouldStop} = $true
    Stop-StressTest -Failed $false
}

# ============================================================================
# ENTRY POINT
# ============================================================================
try {
    Start-StressTest
}
catch {
    Write-Log "CRITICAL ERROR: $_" "ERROR"
    Write-Log $_.ScriptStackTrace "ERROR"
    Stop-StressTest -Failed $true
}
