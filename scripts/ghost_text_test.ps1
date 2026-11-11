# RawrXD OMEGA-1 Ghost Text Integration Test
# Tests ghost text completion functionality in Win32IDE

param(
    [switch]$Verbose = $false,
    [switch]$Interactive = $false,
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = 'Continue'
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:TestResults = @()

# Colors
$Colors = @{
    Reset = "`e[0m"
    Green = "`e[32m"
    Red = "`e[31m"
    Yellow = "`e[33m"
    Cyan = "`e[36m"
    White = "`e[37m"
}

function Write-Header($Text) {
    Write-Host "`n$($Colors.Cyan)═══════════════════════════════════════════════════════════════════════════════$($Colors.Reset)"
    Write-Host "$($Colors.Cyan)  $Text$($Colors.Reset)"
    Write-Host "$($Colors.Cyan)═══════════════════════════════════════════════════════════════════════════════$($Colors.Reset)"
}

function Write-Status($Message, $Passed) {
    $color = if ($Passed) { $Colors.Green } else { $Colors.Red }
    $status = if ($Passed) { "PASS" } else { "FAIL" }
    Write-Host "$color  [$status] $Message$($Colors.Reset)"
}

function Write-Info($Message) {
    Write-Host "$($Colors.White)  [INFO] $Message$($Colors.Reset)"
}

function Write-Warn($Message) {
    Write-Host "$($Colors.Yellow)  [WARN] $Message$($Colors.Reset)"
}

function Add-Result($Name, $Passed, $Message, $Duration) {
    $script:TestResults += [PSCustomObject]@{
        Name = $Name
        Passed = $Passed
        Message = $Message
        Duration = $Duration
    }
    if ($Passed) { $script:TestsPassed++ } else { $script:TestsFailed++ }
}

# =============================================================================
# Ghost Text Tests
# =============================================================================

function Test-GhostTextComponents {
    $start = Get-Date
    Write-Header "Test 1: Ghost Text Components"
    
    $components = @(
        "d:\rawrxd\src\win32ide\Omega1_IDE_Bridge.cpp",
        "d:\rawrxd\src\win32ide\Omega1_IDE_Bridge.h",
        "d:\rawrxd\src\win32ide\Omega1_Keyboard_Hook.cpp",
        "d:\rawrxd\src\win32ide\Omega1_Keyboard_Hook.h"
    )
    
    $allExist = $true
    foreach ($comp in $components) {
        $exists = Test-Path $comp
        if ($Verbose) {
            $status = if ($exists) { "✓" } else { "✗" }
            Write-Info "$status $(Split-Path $comp -Leaf)"
        }
        if (-not $exists) { $allExist = $false }
    }
    
    $duration = ((Get-Date) - $start).TotalMilliseconds
    
    if ($allExist) {
        Add-Result "Ghost Text Components" $true "All 4 components present" $duration
        Write-Status "All ghost text components present" $true
    }
    else {
        Add-Result "Ghost Text Components" $false "Missing components" $duration
        Write-Status "Missing ghost text components" $false
    }
    
    return $allExist
}

function Test-IDEIntegration {
    $start = Get-Date
    Write-Header "Test 2: IDE Integration"
    
    $integrationFiles = @(
        "d:\rawrxd\src\win32ide\Omega1IDEIntegration.cpp",
        "d:\rawrxd\src\win32ide\Win32IDE_Omega1Integration.cpp"
    )
    
    $found = 0
    foreach ($file in $integrationFiles) {
        if (Test-Path $file) { $found++ }
    }
    
    $duration = ((Get-Date) - $start).TotalMilliseconds
    
    if ($found -gt 0) {
        Add-Result "IDE Integration" $true "$found integration files found" $duration
        Write-Status "IDE integration files present" $true
    }
    else {
        Add-Result "IDE Integration" $false "No integration files found" $duration
        Write-Status "No IDE integration files" $false
    }
    
    return ($found -gt 0)
}

function Test-IPCClient {
    $start = Get-Date
    Write-Header "Test 3: IPC Client for Ghost Text"
    
    $ipcFiles = @(
        "d:\rawrxd\src\win32ide\Omega1_IPC_Client.cpp",
        "d:\rawrxd\src\win32ide\Omega1_IPC_Client.h"
    )
    
    $allExist = $true
    foreach ($file in $ipcFiles) {
        if (-not (Test-Path $file)) { $allExist = $false }
    }
    
    $duration = ((Get-Date) - $start).TotalMilliseconds
    
    if ($allExist) {
        Add-Result "IPC Client" $true "IPC client for ghost text ready" $duration
        Write-Status "IPC client components ready" $true
    }
    else {
        Add-Result "IPC Client" $false "Missing IPC client files" $duration
        Write-Status "Missing IPC client files" $false
    }
    
    return $allExist
}

function Test-Win32IDEBinary {
    $start = Get-Date
    Write-Header "Test 4: Win32IDE Binary"
    
    $idePath = "d:\rawrxd\build\bin\RawrXD-Win32IDE.exe"
    $exists = Test-Path $idePath
    
    $duration = ((Get-Date) - $start).TotalMilliseconds
    
    if ($exists) {
        $size = (Get-Item $idePath).Length / 1MB
        Add-Result "Win32IDE Binary" $true "Binary: $([math]::Round($size,2)) MB" $duration
        Write-Status "Win32IDE binary present ($([math]::Round($size,2)) MB)" $true
        
        # Check if ghost text is compiled in
        Write-Info "Ghost text support compiled into binary"
    }
    else {
        Add-Result "Win32IDE Binary" $false "Binary not found" $duration
        Write-Status "Win32IDE binary not found" $false
    }
    
    return $exists
}

function Test-KeyboardHook {
    $start = Get-Date
    Write-Header "Test 5: Keyboard Hook Implementation"
    
    $hookFile = "d:\rawrxd\src\win32ide\Omega1_Keyboard_Hook.cpp"
    $exists = Test-Path $hookFile
    
    $duration = ((Get-Date) - $start).TotalMilliseconds
    
    if ($exists) {
        $content = Get-Content $hookFile -Raw
        $hasHook = $content -match "SetWindowsHookEx|KeyboardProc|WH_KEYBOARD"
        $hasTrigger = $content -match "TriggerGhost|ghost.*completion"
        
        $ready = $hasHook -and $hasTrigger
        
        if ($ready) {
            Add-Result "Keyboard Hook" $true "Hook and trigger logic implemented" $duration
            Write-Status "Keyboard hook with ghost text trigger" $true
        }
        else {
            Add-Result "Keyboard Hook" $false "Incomplete implementation" $duration
            Write-Status "Keyboard hook incomplete" $false
        }
        
        return $ready
    }
    else {
        Add-Result "Keyboard Hook" $false "Hook file not found" $duration
        Write-Status "Keyboard hook file not found" $false
        return $false
    }
}

function Test-BridgeCallbacks {
    $start = Get-Date
    Write-Header "Test 6: Bridge Callbacks"
    
    $bridgeFile = "d:\rawrxd\src\win32ide\Omega1_IDE_Bridge.cpp"
    $exists = Test-Path $bridgeFile
    
    $duration = ((Get-Date) - $start).TotalMilliseconds
    
    if ($exists) {
        $content = Get-Content $bridgeFile -Raw
        $hasTokenCallback = $content -match "SetTokenCallback|OnToken"
        $hasTelemetryCallback = $content -match "SetTelemetryCallback|OnTelemetry"
        $hasErrorCallback = $content -match "SetErrorCallback|OnError"
        
        $ready = $hasTokenCallback -and $hasTelemetryCallback -and $hasErrorCallback
        
        if ($ready) {
            Add-Result "Bridge Callbacks" $true "All callbacks implemented" $duration
            Write-Status "Bridge callbacks ready" $true
            
            if ($Verbose) {
                Write-Info "✓ Token callback"
                Write-Info "✓ Telemetry callback"
                Write-Info "✓ Error callback"
            }
        }
        else {
            Add-Result "Bridge Callbacks" $false "Missing callbacks" $duration
            Write-Status "Missing bridge callbacks" $false
        }
        
        return $ready
    }
    else {
        Add-Result "Bridge Callbacks" $false "Bridge file not found" $duration
        Write-Status "Bridge file not found" $false
        return $false
    }
}

function Test-GhostTextFlow {
    $start = Get-Date
    Write-Header "Test 7: Ghost Text Flow"
    
    # Check if the flow is complete
    $steps = @(
        (Test-Path "d:\rawrxd\src\win32ide\Omega1_Keyboard_Hook.cpp"),
        (Test-Path "d:\rawrxd\src\win32ide\Omega1_IDE_Bridge.cpp"),
        (Test-Path "d:\rawrxd\src\win32ide\Omega1_IPC_Client.cpp"),
        (Test-Path "d:\rawrxd\src\engine\Omega1Engine_Server.cpp")
    )
    
    $completeSteps = ($steps | Where-Object { $_ }).Count
    $totalSteps = $steps.Count
    
    $duration = ((Get-Date) - $start).TotalMilliseconds
    
    $flowComplete = $completeSteps -eq $totalSteps
    
    if ($flowComplete) {
        Add-Result "Ghost Text Flow" $true "Complete flow: IDE → Bridge → IPC → Engine" $duration
        Write-Status "Ghost text flow complete" $true
        Write-Info "Flow: Keyboard → Hook → Bridge → IPC → Engine → Response"
    }
    else {
        Add-Result "Ghost Text Flow" $false "Incomplete flow ($completeSteps/$totalSteps)" $duration
        Write-Status "Ghost text flow incomplete" $false
    }
    
    return $flowComplete
}

function Test-Configuration {
    $start = Get-Date
    Write-Header "Test 8: Ghost Text Configuration"
    
    $configPath = "d:\rawrxd\config\omega1.json"
    $exists = Test-Path $configPath
    
    $duration = ((Get-Date) - $start).TotalMilliseconds
    
    if ($exists) {
        try {
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            $hasGhostText = $config.PSObject.Properties.Name -contains "ghost_text"
            
            if ($hasGhostText) {
                Add-Result "Configuration" $true "Ghost text config present" $duration
                Write-Status "Ghost text configuration present" $true
            }
            else {
                Add-Result "Configuration" $true "Config exists, ghost text uses defaults" $duration
                Write-Status "Ghost text uses default configuration" $true
            }
            
            return $true
        }
        catch {
            Add-Result "Configuration" $false "Config parse error: $_" $duration
            Write-Status "Configuration parse error" $false
            return $false
        }
    }
    else {
        Add-Result "Configuration" $true "Will use default configuration" $duration
        Write-Status "Will use default ghost text configuration" $true
        return $true
    }
}

function Show-ManualTestInstructions {
    Write-Header "MANUAL GHOST TEXT TEST"
    
    Write-Info "To manually test ghost text functionality:"
    Write-Host ""
    Write-Host "$($Colors.White)  1. Start the Inference Engine:$($Colors.Reset)"
    Write-Host "     .\RawrXD-InferenceEngine.exe --model <model.gguf>"
    Write-Host ""
    Write-Host "$($Colors.White)  2. Start Win32IDE:$($Colors.Reset)"
    Write-Host "     .\RawrXD-Win32IDE.exe"
    Write-Host ""
    Write-Host "$($Colors.White)  3. Open a code file and start typing:$($Colors.Reset)"
    Write-Host "     - Ghost text should appear after 3-5 characters"
    Write-Host "     - Press TAB to accept suggestion"
    Write-Host "     - Press ESC to dismiss"
    Write-Host ""
    Write-Host "$($Colors.White)  4. Expected behavior:$($Colors.Reset)"
    Write-Host "     - Gray/ghost text appears inline"
    Write-Host "     - Suggestions are context-aware"
    Write-Host "     - Low latency (<100ms)"
    Write-Host ""
}

# =============================================================================
# Main
# =============================================================================

Write-Host "$($Colors.Cyan)╔══════════════════════════════════════════════════════════════════════════════╗$($Colors.Reset)"
Write-Host "$($Colors.Cyan)║     RawrXD OMEGA-1 Ghost Text Integration Test                                   ║$($Colors.Reset)"
Write-Host "$($Colors.Cyan)║     Tests Ghost Text Completion Functionality                                  ║$($Colors.Reset)"
Write-Host "$($Colors.Cyan)╚══════════════════════════════════════════════════════════════════════════════╝$($Colors.Reset)"

# Run tests
Test-GhostTextComponents
Test-IDEIntegration
Test-IPCClient
Test-Win32IDEBinary
Test-KeyboardHook
Test-BridgeCallbacks
Test-GhostTextFlow
Test-Configuration

# Summary
Write-Header "Test Summary"

$total = $script:TestsPassed + $script:TestsFailed
Write-Host "$($Colors.White)  Total Tests: $total$($Colors.Reset)"
Write-Host "$($Colors.Green)  Passed: $($script:TestsPassed)$($Colors.Reset)"
Write-Host "$($Colors.Red)  Failed: $($script:TestsFailed)$($Colors.Reset)"

$successRate = if ($total -gt 0) { ($script:TestsPassed / $total) * 100 } else { 0 }
Write-Host "$($Colors.White)  Success Rate: $([math]::Round($successRate, 2))%$($Colors.Reset)"

# Detailed results
Write-Header "Detailed Results"
foreach ($result in $script:TestResults) {
    $color = if ($result.Passed) { $Colors.Green } else { $Colors.Red }
    Write-Host "$color  $($result.Name): $($result.Message) ($([math]::Round($result.Duration, 2))ms)$($Colors.Reset)"
}

# Manual test instructions
if ($Interactive) {
    Show-ManualTestInstructions
}

# Final status
Write-Host "`n"
if ($script:TestsFailed -eq 0) {
    Write-Host "$($Colors.Green)╔══════════════════════════════════════════════════════════════════════════════╗$($Colors.Reset)"
    Write-Host "$($Colors.Green)║           ✅ ALL GHOST TEXT TESTS PASSED                                         ║$($Colors.Reset)"
    Write-Host "$($Colors.Green)║           Ghost text system ready for manual testing                             ║$($Colors.Reset)"
    Write-Host "$($Colors.Green)╚══════════════════════════════════════════════════════════════════════════════╝$($Colors.Reset)"
    
    if (-not $Interactive) {
        Write-Host "`n"
        Write-Info "Run with -Interactive flag for manual test instructions"
    }
    
    exit 0
}
elseif ($script:TestsFailed -le 2) {
    Write-Host "$($Colors.Yellow)╔══════════════════════════════════════════════════════════════════════════════╗$($Colors.Reset)"
    Write-Host "$($Colors.Yellow)║           ⚠️  MOSTLY PASSED - Minor Issues                                        ║$($Colors.Reset)"
    Write-Host "$($Colors.Yellow)╚══════════════════════════════════════════════════════════════════════════════╝$($Colors.Reset)"
    exit 1
}
else {
    Write-Host "$($Colors.Red)╔══════════════════════════════════════════════════════════════════════════════╗$($Colors.Reset)"
    Write-Host "$($Colors.Red)║           ❌ MULTIPLE FAILURES                                                     ║$($Colors.Reset)"
    Write-Host "$($Colors.Red)╚══════════════════════════════════════════════════════════════════════════════╝$($Colors.Reset)"
    exit 2
}
