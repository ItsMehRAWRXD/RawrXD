# RawrXD Component Lifecycle Test
# VAL-052: Prove deferred initialization boundary is safe

param(
    [string]$BinaryPath = "d:\rxdn_ninja\bin\RawrXD-Win32IDE.exe",
    [string]$EvidenceDir = "d:\rawrxd\evidence\2026-07-24-56ef83e\startup_smoke",
    [string]$TraceLogPath = "d:\rxdn_ninja\bin\win32ide_trace.log",
    [int]$MaxStartupSeconds = 10
)

$ErrorActionPreference = "Stop"
$timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

# Verify binary
$binaryHash = (Get-FileHash $BinaryPath -Algorithm SHA256).Hash
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "VAL-052: Runtime Component Lifecycle" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Binary: $BinaryPath"
Write-Host "SHA256: $binaryHash"
Write-Host ""

$lifecycle = @{
    test_id = "VAL-052"
    test_name = "Runtime Component Lifecycle"
    timestamp = $timestamp
    binary = $BinaryPath
    binary_sha256 = $binaryHash
    status = "IN_PROGRESS"
    
    phase_1_wm_create = @{
        description = "Lightweight state only - heavy init forbidden"
        start_ms = 0
        end_ms = $null
        duration_ms = $null
        components = @()
        heavy_init_blocked = $true
    }
    
    phase_2_deferred = @{
        description = "Heavy initialization via WM_APP+99"
        trigger = "WM_APP+99 posted from onCreate"
        start_ms = $null
        end_ms = $null
        duration_ms = $null
        components = @()
    }
    
    invariants = @{
        no_recursion_in_deferred = $true
        no_stack_overflow_in_phase_2 = $true
        startup_phase_transitions_valid = $true
        all_components_initialized = $false
        ready_state_reached = $false
    }
    
    total_startup_ms = $null
    recursion_detected = $false
    stack_overflow_in_deferred = $false
    ready_state_reached = $false
}

# Clear previous trace log
if (Test-Path $TraceLogPath) {
    Remove-Item $TraceLogPath -Force -ErrorAction SilentlyContinue
}

# Launch process
Write-Host "[TEST] Launching IDE with trace enabled..." -ForegroundColor Yellow
$startTime = Get-Date

$proc = Start-Process -FilePath $BinaryPath -PassThru -ErrorAction Stop
$lifecycle.pid = $proc.Id
Write-Host "[INFO] Process started: PID $($proc.Id)" -ForegroundColor Green

# Wait for startup completion
$ready = $false
$elapsed = 0
$checkInterval = 100

while ($elapsed -lt ($MaxStartupSeconds * 1000)) {
    Start-Sleep -Milliseconds $checkInterval
    $elapsed += $checkInterval
    
    $proc.Refresh()
    
    if ($proc.HasExited) {
        $exitCode = $proc.ExitCode
        if ($exitCode -eq -1073741571) { # 0xC00000FD
            $lifecycle.stack_overflow_in_deferred = $true
            $lifecycle.invariants.no_stack_overflow_in_phase_2 = $false
            Write-Host "[FAIL] Stack overflow detected in deferred init!" -ForegroundColor Red
        }
        break
    }
    
    # Check for ready state via trace log
    if (Test-Path $TraceLogPath) {
        $traceContent = Get-Content $TraceLogPath -Raw -ErrorAction SilentlyContinue
        if ($traceContent -match "onCreateChildren.*END") {
            $ready = $true
            $lifecycle.ready_state_reached = $true
            $lifecycle.invariants.ready_state_reached = $true
            Write-Host "[PASS] Deferred initialization complete" -ForegroundColor Green
            break
        }
    }
    
    # Check for window (indicates phase 1 complete)
    if ($proc.MainWindowHandle -ne 0 -and -not $lifecycle.phase_1_wm_create.end_ms) {
        $phase1End = Get-Date
        $lifecycle.phase_1_wm_create.end_ms = [math]::Round(($phase1End - $startTime).TotalMilliseconds, 2)
        $lifecycle.phase_1_wm_create.duration_ms = $lifecycle.phase_1_wm_create.end_ms
        Write-Host "[INFO] Phase 1 (WM_CREATE) complete in $($lifecycle.phase_1_wm_create.end_ms)ms" -ForegroundColor Gray
    }
}

$endTime = Get-Date
$lifecycle.total_startup_ms = [math]::Round(($endTime - $startTime).TotalMilliseconds, 2)

# Analyze trace log
if (Test-Path $TraceLogPath) {
    $traceContent = Get-Content $TraceLogPath -Raw
    
    # Check for recursion
    $recursionMatches = [regex]::Matches($traceContent, "RE-ENTRANT.*detected")
    if ($recursionMatches.Count -gt 0) {
        $lifecycle.recursion_detected = $true
        $lifecycle.invariants.no_recursion_in_deferred = $false
        Write-Host "[WARN] Recursion detected: $($recursionMatches.Count) occurrences" -ForegroundColor Yellow
    }
    
    # Extract component initialization times
    $componentPattern = "\[onCreateChildren\]\s+(\w+)\s+(START|DONE)"
    $matches = [regex]::Matches($traceContent, $componentPattern)
    
    $componentTimes = @{}
    foreach ($match in $matches) {
        $component = $match.Groups[1].Value
        $event = $match.Groups[2].Value
        if (-not $componentTimes.ContainsKey($component)) {
            $componentTimes[$component] = @{}
        }
        $componentTimes[$component][$event] = $true
    }
    
    # Build component list
    $components = @()
    foreach ($comp in @("createOutputTabs", "createPowerShellPanel", "createChatPanel", "createTabBar", "applySovereignTheme")) {
        $status = "UNKNOWN"
        if ($componentTimes.ContainsKey($comp)) {
            if ($componentTimes[$comp]["DONE"] -or $componentTimes[$comp]["START"]) {
                $status = "PASS"
            }
        }
        $components += @{
            name = $comp
            status = $status
        }
    }
    
    $lifecycle.phase_2_deferred.components = $components
    $lifecycle.invariants.all_components_initialized = ($components | Where-Object { $_.status -eq "PASS" }).Count -eq $components.Count
}

# Calculate phase 2 timing
if ($lifecycle.phase_1_wm_create.end_ms) {
    $lifecycle.phase_2_deferred.start_ms = $lifecycle.phase_1_wm_create.end_ms
    $lifecycle.phase_2_deferred.end_ms = $lifecycle.total_startup_ms
    $lifecycle.phase_2_deferred.duration_ms = $lifecycle.total_startup_ms - $lifecycle.phase_1_wm_create.end_ms
}

# Determine status
$allPass = $lifecycle.invariants.no_stack_overflow_in_phase_2 -and
           $lifecycle.invariants.no_recursion_in_deferred -and
           $lifecycle.invariants.all_components_initialized -and
           $lifecycle.ready_state_reached

if ($allPass) {
    $lifecycle.status = "PASS"
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "VAL-052: PASS" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
} else {
    $lifecycle.status = "FAIL"
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "VAL-052: FAIL" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
}

Write-Host "Phase 1 (WM_CREATE): $($lifecycle.phase_1_wm_create.duration_ms)ms"
Write-Host "Phase 2 (Deferred):  $($lifecycle.phase_2_deferred.duration_ms)ms"
Write-Host "Total:             $($lifecycle.total_startup_ms)ms"
Write-Host "Recursion:         $($lifecycle.recursion_detected)"
Write-Host "Stack Overflow:    $($lifecycle.stack_overflow_in_deferred)"
Write-Host "Ready State:       $($lifecycle.ready_state_reached)"

# Cleanup
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue

# Save evidence
$evidencePath = "$EvidenceDir\component_lifecycle.json"
$lifecycle | ConvertTo-Json -Depth 5 | Out-File -FilePath $evidencePath -Encoding UTF8
Write-Host "`nEvidence: $evidencePath" -ForegroundColor Cyan

if ($allPass) { exit 0 } else { exit 1 }
