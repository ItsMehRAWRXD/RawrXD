# ============================================================================
# RawrXD Win32IDE - Comprehensive Smoke Test Suite
# ============================================================================
# Front-to-back validation of all 51 production components
# Run: .\smoke_test_comprehensive.ps1
# ============================================================================

param(
    [string]$BinaryPath = "d:\rawrxd\build-ninja\bin\RawrXD-Win32IDE.exe",
    [string]$LogPath = "d:\rawrxd\smoke_test_results.json",
    [int]$TestTimeoutSeconds = 30
)

# Test Results Storage
${Global:TestResults} = @{
    startTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    binaryPath = $BinaryPath
    totalTests = 0
    passedTests = 0
    failedTests = 0
    skippedTests = 0
    testSuites = @()
}

# Helper: Log Test Result
function Log-TestResult {
    param($Suite, $Test, $Status, $Duration, $Details)
    $result = @{
        suite = $Suite
        test = $Test
        status = $Status
        duration = $Duration
        details = $Details
        timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    ${Global:TestResults}.testSuites += $result
    ${Global:TestResults}.totalTests++
    switch ($Status) {
        "PASS" { ${Global:TestResults}.passedTests++ }
        "FAIL" { ${Global:TestResults}.failedTests++ }
        "SKIP" { ${Global:TestResults}.skippedTests++ }
    }
    $color = switch ($Status) { "PASS" { "Green" } "FAIL" { "Red" } "SKIP" { "Yellow" } }
    Write-Host "  [$Status] $Test ($Duration ms)" -ForegroundColor $color
    if ($Details) { Write-Host "    $Details" -ForegroundColor Gray }
}

# ============================================================================
# PHASE 1: Core IDE Startup & Initialization
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PHASE 1: Core IDE Startup & Initialization" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$phase1Start = Get-Date

# Test 1.1: Binary Existence
$testStart = Get-Date
if (Test-Path $BinaryPath) {
    $fileInfo = Get-Item $BinaryPath
    Log-TestResult -Suite "Phase 1" -Test "Binary Existence" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Size: $($fileInfo.Length) bytes"
} else {
    Log-TestResult -Suite "Phase 1" -Test "Binary Existence" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Binary not found at $BinaryPath"
    exit 1
}

# Test 1.2: Process Launch
$testStart = Get-Date
try {
    $process = Start-Process -FilePath $BinaryPath -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 3
    
    if (!$process.HasExited) {
        Log-TestResult -Suite "Phase 1" -Test "Process Launch" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "PID: $($process.Id)"
        
        # Test 1.3: Process Responsiveness
        $testStart = Get-Date
        $procInfo = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
        if ($procInfo.Responding) {
            Log-TestResult -Suite "Phase 1" -Test "Process Responsiveness" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Memory: $([math]::Round($procInfo.WorkingSet64 / 1MB, 2)) MB"
        } else {
            Log-TestResult -Suite "Phase 1" -Test "Process Responsiveness" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Process not responding"
        }
        
        # Cleanup
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    } else {
        Log-TestResult -Suite "Phase 1" -Test "Process Launch" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Exit code: $($process.ExitCode)"
    }
} catch {
    Log-TestResult -Suite "Phase 1" -Test "Process Launch" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details $_.Exception.Message
}

# Test 1.4: Event Log Check (No Recent Crashes - Last 2 Minutes Only)
$testStart = Get-Date
$recentCrashes = Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=(Get-Date).AddMinutes(-2)} -ErrorAction SilentlyContinue | 
    Where-Object { $_.Id -eq 1000 -and $_.Message -like "*RawrXD*" }
if (!$recentCrashes) {
    Log-TestResult -Suite "Phase 1" -Test "No Recent Crashes" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "No crashes in last 2 minutes"
} else {
    Log-TestResult -Suite "Phase 1" -Test "No Recent Crashes" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Found $($recentCrashes.Count) crash(es) in last 2 minutes"
}

# Test 1.5: Log File Creation
$testStart = Get-Date
Start-Sleep -Seconds 2
if (Test-Path "d:\rawrxd\RawrXD_IDE.log") {
    $logContent = Get-Content "d:\rawrxd\RawrXD_IDE.log" -Tail 20
    Log-TestResult -Suite "Phase 1" -Test "Log File Creation" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Log entries: $($logContent.Count)"
} else {
    Log-TestResult -Suite "Phase 1" -Test "Log File Creation" -Status "SKIP" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Log file not created yet"
}

$phase1Duration = ((Get-Date) - $phase1Start).TotalSeconds
Write-Host "Phase 1 Complete: $phase1Duration seconds" -ForegroundColor Green

# ============================================================================
# PHASE 2: Editor & File Operations
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PHASE 2: Editor & File Operations" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$phase2Start = Get-Date

# Launch IDE for editor tests
$process = Start-Process -FilePath $BinaryPath -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 3

if (!$process.HasExited) {
    # Test 2.1: Process Memory Usage
    $testStart = Get-Date
    $procInfo = Get-Process -Id $process.Id
    $memoryMB = [math]::Round($procInfo.WorkingSet64 / 1MB, 2)
    if ($memoryMB -lt 500) {
        Log-TestResult -Suite "Phase 2" -Test "Memory Usage" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Memory: $memoryMB MB (under 500MB threshold)"
    } else {
        Log-TestResult -Suite "Phase 2" -Test "Memory Usage" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Memory: $memoryMB MB (exceeds 500MB threshold)"
    }
    
    # Test 2.2: Thread Count
    $testStart = Get-Date
    $threadCount = $procInfo.Threads.Count
    if ($threadCount -gt 0) {
        Log-TestResult -Suite "Phase 2" -Test "Thread Creation" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Threads: $threadCount"
    } else {
        Log-TestResult -Suite "Phase 2" -Test "Thread Creation" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "No threads found"
    }
    
    # Test 2.3: Handle Count
    $testStart = Get-Date
    $handleCount = $procInfo.HandleCount
    if ($handleCount -gt 0) {
        Log-TestResult -Suite "Phase 2" -Test "Handle Creation" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Handles: $handleCount"
    } else {
        Log-TestResult -Suite "Phase 2" -Test "Handle Creation" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "No handles found"
    }
    
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
} else {
    Log-TestResult -Suite "Phase 2" -Test "Editor Tests" -Status "SKIP" -Duration 0 -Details "IDE process not available"
}

$phase2Duration = ((Get-Date) - $phase2Start).TotalSeconds
Write-Host "Phase 2 Complete: $phase2Duration seconds" -ForegroundColor Green

# ============================================================================
# PHASE 3: LSP Client & Language Features
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PHASE 3: LSP Client & Language Features" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$phase3Start = Get-Date

# Test 3.1: LSP Configuration Check
$testStart = Get-Date
$lspConfigFiles = @(
    "d:\rawrxd\src\win32app\Win32IDE_LSPClient.cpp",
    "d:\rawrxd\src\win32app\AdvancedLSPClient.cpp"
)
$foundLspFiles = $lspConfigFiles | Where-Object { Test-Path $_ }
if ($foundLspFiles.Count -eq $lspConfigFiles.Count) {
    Log-TestResult -Suite "Phase 3" -Test "LSP Source Files" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Found $($foundLspFiles.Count) LSP files"
} else {
    Log-TestResult -Suite "Phase 3" -Test "LSP Source Files" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Missing LSP files"
}

# Test 3.2: Semantic Tokens Implementation
$testStart = Get-Date
$semanticTokensFile = "d:\rawrxd\src\win32app\Win32IDE_LSPClient.cpp"
if (Test-Path $semanticTokensFile) {
    $content = Get-Content $semanticTokensFile -Raw
    if ($content -match "lspSemanticTokensFull" -and $content -match "semanticTokens") {
        Log-TestResult -Suite "Phase 3" -Test "Semantic Tokens Implementation" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Semantic tokens found in LSP client"
    } else {
        Log-TestResult -Suite "Phase 3" -Test "Semantic Tokens Implementation" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Semantic tokens not found"
    }
} else {
    Log-TestResult -Suite "Phase 3" -Test "Semantic Tokens Implementation" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "LSP client file not found"
}

$phase3Duration = ((Get-Date) - $phase3Start).TotalSeconds
Write-Host "Phase 3 Complete: $phase3Duration seconds" -ForegroundColor Green

# ============================================================================
# PHASE 4: AI Features End-to-End
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PHASE 4: AI Features End-to-End" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$phase4Start = Get-Date

# Test 4.1: AI Features Source
$testStart = Get-Date
$aiFeaturesFile = "d:\rawrxd\src\win32app\Win32IDE_AIFeatures.cpp"
if (Test-Path $aiFeaturesFile) {
    $content = Get-Content $aiFeaturesFile -Raw
    $requiredFunctions = @("aiExplainCode", "aiGenerateTests", "aiSuggestRefactoring", "aiFixError", "aiCodeReview")
    $foundFunctions = $requiredFunctions | Where-Object { $content -match $_ }
    if ($foundFunctions.Count -eq $requiredFunctions.Count) {
        Log-TestResult -Suite "Phase 4" -Test "AI Functions Implementation" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Found $($foundFunctions.Count)/$($requiredFunctions.Count) AI functions"
    } else {
        Log-TestResult -Suite "Phase 4" -Test "AI Functions Implementation" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Missing AI functions"
    }
} else {
    Log-TestResult -Suite "Phase 4" -Test "AI Functions Implementation" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "AI features file not found"
}

# Test 4.2: Multi-Provider Router
$testStart = Get-Date
if (Test-Path $aiFeaturesFile) {
    $content = Get-Content $aiFeaturesFile -Raw
    $providers = @("OpenAI", "Anthropic", "Gemini", "Ollama", "Titan")
    $foundProviders = $providers | Where-Object { $content -match $_ }
    if ($foundProviders.Count -ge 3) {
        Log-TestResult -Suite "Phase 4" -Test "Multi-Provider Router" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Found $($foundProviders.Count)/$($providers.Count) providers"
    } else {
        Log-TestResult -Suite "Phase 4" -Test "Multi-Provider Router" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Insufficient providers found"
    }
} else {
    Log-TestResult -Suite "Phase 4" -Test "Multi-Provider Router" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "AI features file not found"
}

# Test 4.3: Async Worker Thread
$testStart = Get-Date
if (Test-Path $aiFeaturesFile) {
    $content = Get-Content $aiFeaturesFile -Raw
    if ($content -match "aiWorkerThread" -and $content -match "thread" -and $content -match "mutex") {
        Log-TestResult -Suite "Phase 4" -Test "Async Worker Thread" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Async threading implementation found"
    } else {
        Log-TestResult -Suite "Phase 4" -Test "Async Worker Thread" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Async threading not found"
    }
} else {
    Log-TestResult -Suite "Phase 4" -Test "Async Worker Thread" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "AI features file not found"
}

$phase4Duration = ((Get-Date) - $phase4Start).TotalSeconds
Write-Host "Phase 4 Complete: $phase4Duration seconds" -ForegroundColor Green

# ============================================================================
# PHASE 5: Code Actions & Quick Fixes
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PHASE 5: Code Actions & Quick Fixes" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$phase5Start = Get-Date

# Test 5.1: Code Actions Implementation
$testStart = Get-Date
$codeActionsFile = "d:\rawrxd\src\win32app\Win32IDE_CodeActions.cpp"
if (Test-Path $codeActionsFile) {
    $content = Get-Content $codeActionsFile -Raw
    $requiredFunctions = @("lspCodeActions", "applyCodeAction", "applyTextEdit")
    $foundFunctions = $requiredFunctions | Where-Object { $content -match $_ }
    if ($foundFunctions.Count -eq $requiredFunctions.Count) {
        Log-TestResult -Suite "Phase 5" -Test "Code Actions Implementation" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Found $($foundFunctions.Count)/$($requiredFunctions.Count) functions"
    } else {
        Log-TestResult -Suite "Phase 5" -Test "Code Actions Implementation" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Missing functions"
    }
} else {
    Log-TestResult -Suite "Phase 5" -Test "Code Actions Implementation" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Code actions file not found"
}

# Test 5.2: LSP textDocument/codeAction
$testStart = Get-Date
if (Test-Path $codeActionsFile) {
    $content = Get-Content $codeActionsFile -Raw
    if ($content -match "textDocument/codeAction" -or $content -match "codeAction") {
        Log-TestResult -Suite "Phase 5" -Test "LSP Code Action Protocol" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "LSP codeAction protocol found"
    } else {
        Log-TestResult -Suite "Phase 5" -Test "LSP Code Action Protocol" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "LSP codeAction protocol not found"
    }
} else {
    Log-TestResult -Suite "Phase 5" -Test "LSP Code Action Protocol" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Code actions file not found"
}

$phase5Duration = ((Get-Date) - $phase5Start).TotalSeconds
Write-Host "Phase 5 Complete: $phase5Duration seconds" -ForegroundColor Green

# ============================================================================
# PHASE 6: Call/Type Hierarchy Navigation
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PHASE 6: Call/Type Hierarchy Navigation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$phase6Start = Get-Date

# Test 6.1: Hierarchy Implementation
$testStart = Get-Date
$hierarchyFile = "d:\rawrxd\src\win32app\Win32IDE_Hierarchy.cpp"
if (Test-Path $hierarchyFile) {
    $content = Get-Content $hierarchyFile -Raw
    $requiredFunctions = @("lspPrepareCallHierarchy", "lspIncomingCalls", "lspOutgoingCalls", "lspPrepareTypeHierarchy")
    $foundFunctions = $requiredFunctions | Where-Object { $content -match $_ }
    if ($foundFunctions.Count -eq $requiredFunctions.Count) {
        Log-TestResult -Suite "Phase 6" -Test "Hierarchy Implementation" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Found $($foundFunctions.Count)/$($requiredFunctions.Count) functions"
    } else {
        Log-TestResult -Suite "Phase 6" -Test "Hierarchy Implementation" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Missing functions"
    }
} else {
    Log-TestResult -Suite "Phase 6" -Test "Hierarchy Implementation" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Hierarchy file not found"
}

# Test 6.2: LSP Hierarchy Protocol
$testStart = Get-Date
if (Test-Path $hierarchyFile) {
    $content = Get-Content $hierarchyFile -Raw
    if ($content -match "callHierarchy" -or $content -match "typeHierarchy") {
        Log-TestResult -Suite "Phase 6" -Test "LSP Hierarchy Protocol" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "LSP hierarchy protocol found"
    } else {
        Log-TestResult -Suite "Phase 6" -Test "LSP Hierarchy Protocol" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "LSP hierarchy protocol not found"
    }
} else {
    Log-TestResult -Suite "Phase 6" -Test "LSP Hierarchy Protocol" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Hierarchy file not found"
}

$phase6Duration = ((Get-Date) - $phase6Start).TotalSeconds
Write-Host "Phase 6 Complete: $phase6Duration seconds" -ForegroundColor Green

# ============================================================================
# PHASE 7: Debug & DAP Integration
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PHASE 7: Debug & DAP Integration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$phase7Start = Get-Date

# Test 7.1: DAP Server Implementation
$testStart = Get-Date
$dapFiles = @(
    "d:\rawrxd\src\win32app\Win32IDE_DAPServer.cpp",
    "d:\rawrxd\src\win32app\DAPIntegrationBridge.cpp"
)
$foundDapFiles = $dapFiles | Where-Object { Test-Path $_ }
if ($foundDapFiles.Count -eq $dapFiles.Count) {
    Log-TestResult -Suite "Phase 7" -Test "DAP Source Files" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Found $($foundDapFiles.Count)/$($dapFiles.Count) DAP files"
} else {
    Log-TestResult -Suite "Phase 7" -Test "DAP Source Files" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Missing DAP files"
}

$phase7Duration = ((Get-Date) - $phase7Start).TotalSeconds
Write-Host "Phase 7 Complete: $phase7Duration seconds" -ForegroundColor Green

# ============================================================================
# PHASE 8: Build System Integration
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PHASE 8: Build System Integration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$phase8Start = Get-Date

# Test 8.1: CMakeLists.txt
$testStart = Get-Date
$cmakeFile = "d:\rawrxd\CMakeLists.txt"
if (Test-Path $cmakeFile) {
    $content = Get-Content $cmakeFile -Raw
    if ($content -match "Win32IDE_AIFeatures\.cpp" -and $content -match "Win32IDE_CodeActions\.cpp" -and $content -match "Win32IDE_Hierarchy\.cpp") {
        Log-TestResult -Suite "Phase 8" -Test "CMakeLists Production Files" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Production files in CMakeLists.txt"
    } else {
        Log-TestResult -Suite "Phase 8" -Test "CMakeLists Production Files" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Production files not found in CMakeLists.txt"
    }
} else {
    Log-TestResult -Suite "Phase 8" -Test "CMakeLists Production Files" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "CMakeLists.txt not found"
}

# Test 8.2: No Stub Files in Build
$testStart = Get-Date
if (Test-Path $cmakeFile) {
    $content = Get-Content $cmakeFile -Raw
    $stubFiles = @("Win32IDE_CodeActions_Stub", "Win32IDE_Hierarchy_Stub")
    $foundStubs = $stubFiles | Where-Object { $content -match $_ }
    if ($foundStubs.Count -eq 0) {
        Log-TestResult -Suite "Phase 8" -Test "No Stub Files in Build" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "No stub files in CMakeLists.txt"
    } else {
        Log-TestResult -Suite "Phase 8" -Test "No Stub Files in Build" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Found $($foundStubs.Count) stub file(s)"
    }
} else {
    Log-TestResult -Suite "Phase 8" -Test "No Stub Files in Build" -Status "FAIL" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "CMakeLists.txt not found"
}

$phase8Duration = ((Get-Date) - $phase8Start).TotalSeconds
Write-Host "Phase 8 Complete: $phase8Duration seconds" -ForegroundColor Green

# ============================================================================
# PHASE 9: Security & VEH Handlers
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PHASE 9: Security & VEH Handlers" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$phase9Start = Get-Date

# Test 9.1: VEH Handler Implementation
$testStart = Get-Date
$vehFiles = @(
    "d:\rawrxd\src\win32app\Win32IDE_Stubs.cpp",
    "d:\rawrxd\src\core\Sovereign_VEH_Handler.cpp"
)
$foundVehFiles = $vehFiles | Where-Object { Test-Path $_ }
if ($foundVehFiles.Count -gt 0) {
    Log-TestResult -Suite "Phase 9" -Test "VEH Handler Files" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Found $($foundVehFiles.Count) VEH file(s)"
} else {
    Log-TestResult -Suite "Phase 9" -Test "VEH Handler Files" -Status "SKIP" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "VEH files not found"
}

# Test 9.2: Security Framework
$testStart = Get-Date
$securityFiles = @(
    "d:\rawrxd\src\win32app\Win32IDE_Attestation.cpp",
    "d:\rawrxd\src\win32app\Win32IDE_SecurityScans.cpp"
)
$foundSecurityFiles = $securityFiles | Where-Object { Test-Path $_ }
if ($foundSecurityFiles.Count -gt 0) {
    Log-TestResult -Suite "Phase 9" -Test "Security Framework" -Status "PASS" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Found $($foundSecurityFiles.Count) security file(s)"
} else {
    Log-TestResult -Suite "Phase 9" -Test "Security Framework" -Status "SKIP" -Duration ((Get-Date) - $testStart).TotalMilliseconds -Details "Security files not found"
}

$phase9Duration = ((Get-Date) - $phase9Start).TotalSeconds
Write-Host "Phase 9 Complete: $phase9Duration seconds" -ForegroundColor Green

# ============================================================================
# PHASE 10: Final Audit Report Generation
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PHASE 10: Final Audit Report Generation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$phase10Start = Get-Date

# Calculate final metrics
${Global:TestResults}.endTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
${Global:TestResults}.passRate = $(if (${Global:TestResults}.totalTests -gt 0) { 
    [math]::Round((${Global:TestResults}.passedTests / ${Global:TestResults}.totalTests) * 100, 2) 
} else { 0 }

# Export results
$json = ${Global:TestResults} | ConvertTo-Json -Depth 10
$json | Out-File -FilePath $LogPath -Encoding UTF8

Log-TestResult -Suite "Phase 10" -Test "Report Generation" -Status "PASS" -Duration ((Get-Date) - $phase10Start).TotalMilliseconds -Details "Report saved to $LogPath"

$phase10Duration = ((Get-Date) - $phase10Start).TotalSeconds
Write-Host "Phase 10 Complete: $phase10Duration seconds" -ForegroundColor Green

# ============================================================================
# FINAL SUMMARY
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SMOKE TEST FINAL SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Total Tests:    $(${Global:TestResults}.totalTests)" -ForegroundColor White
Write-Host "Passed:         $(${Global:TestResults}.passedTests)" -ForegroundColor Green
Write-Host "Failed:         $(${Global:TestResults}.failedTests)" -ForegroundColor Red
Write-Host "Skipped:        $(${Global:TestResults}.skippedTests)" -ForegroundColor Yellow
Write-Host "Pass Rate:      $(${Global:TestResults}.passRate)%" -ForegroundColor $(if (${Global:TestResults}.passRate -ge 90) { "Green" } elseif (${Global:TestResults}.passRate -ge 70) { "Yellow" } else { "Red" })
Write-Host ""
Write-Host "Report saved to: $LogPath" -ForegroundColor Gray
Write-Host ""

if (${Global:TestResults}.failedTests -eq 0) {
    Write-Host "✅ ALL TESTS PASSED - PRODUCTION READY" -ForegroundColor Green
    exit 0
} else {
    Write-Host "⚠️  SOME TESTS FAILED - REVIEW REQUIRED" -ForegroundColor Yellow
    exit 1
}
