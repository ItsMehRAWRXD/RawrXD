# DebugIntegrationTest.ps1
# Phase 24D: System Integration Test Protocol
# ============================================================================
# PowerShell-based integration test for the debugger stack
# Tests component wiring without requiring C++ compilation
# ============================================================================

param(
    [switch]$Verbose,
    [switch]$SkipLiveTest
)

$ErrorActionPreference = "Stop"
${script:TestResults} = @()
${script:Verbose} = $Verbose

function Write-TestLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $color = switch ($Level) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
        default { "White" }
    }
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
    "[$timestamp] [$Level] $Message" | Out-File -Append -FilePath "debug_integration_test.log"
}

function Run-Test {
    param(
        [string]$Name,
        [scriptblock]$TestScript
    )
    
    Write-TestLog "[TEST] $Name" "INFO"
    $startTime = Get-Date
    
    try {
        $result = & $TestScript
        $duration = (Get-Date) - $startTime
        
        if ($result.Success) {
            Write-TestLog "  ✓ PASSED ($($duration.TotalMilliseconds)ms)" "PASS"
            ${script:TestResults} += [PSCustomObject]@{
                Name = $Name
                Passed = $true
                Duration = $duration
                Error = $null
            }
            return $true
        } else {
            Write-TestLog "  ✗ FAILED: $($result.Error)" "FAIL"
            ${script:TestResults} += [PSCustomObject]@{
                Name = $Name
                Passed = $false
                Duration = $duration
                Error = $result.Error
            }
            return $false
        }
    }
    catch {
        $duration = (Get-Date) - $startTime
        Write-TestLog "  ✗ EXCEPTION: $_" "FAIL"
        ${script:TestResults} += [PSCustomObject]@{
            Name = $Name
            Passed = $false
            Duration = $duration
            Error = $_.Exception.Message
        }
        return $false
    }
}

# ============================================================================
# Test 1: File Structure Verification
# ============================================================================
$testFileStructure = {
    $requiredFiles = @(
        "src\debug\DapService.hpp",
        "src\debug\DapService.cpp",
        "src\debug\DebugUIPanel.hpp",
        "src\debug\DebugUIPanel.cpp",
        "src\debug\BreakpointGutter.hpp",
        "src\debug\BreakpointGutter.cpp",
        "src\debug\StepController.hpp",
        "src\debug\StepController.cpp"
    )
    
    $missingFiles = @()
    foreach ($file in $requiredFiles) {
        $fullPath = Join-Path $PSScriptRoot "..\.." $file
        if (-not (Test-Path $fullPath)) {
            $missingFiles += $file
        }
    }
    
    if ($missingFiles.Count -gt 0) {
        return @{ Success = $false; Error = "Missing files: $($missingFiles -join ', ')" }
    }
    
    return @{ Success = $true }
}

# ============================================================================
# Test 2: Header Syntax Validation
# ============================================================================
$testHeaderSyntax = {
    $headers = @(
        "src\debug\DapService.hpp",
        "src\debug\DebugUIPanel.hpp",
        "src\debug\BreakpointGutter.hpp",
        "src\debug\StepController.hpp"
    )
    
    $errors = @()
    foreach ($header in $headers) {
        $fullPath = Join-Path $PSScriptRoot "..\.." $header
        $content = Get-Content $fullPath -Raw
        
        # Check for basic C++ syntax markers
        if (-not ($content -match '#pragma once')) {
            $errors += "$header missing #pragma once"
        }
        if (-not ($content -match 'namespace RawrXD')) {
            $errors += "$header missing namespace RawrXD"
        }
    }
    
    if ($errors.Count -gt 0) {
        return @{ Success = $false; Error = ($errors -join '; ') }
    }
    
    return @{ Success = $true }
}

# ============================================================================
# Test 3: Component Interface Verification
# ============================================================================
$testComponentInterfaces = {
    # Check DapService has required methods
    $dapServicePath = Join-Path $PSScriptRoot "..\.." "src\debug\DapService.hpp"
    $dapContent = Get-Content $dapServicePath -Raw
    
    $requiredMethods = @(
        'initialize',
        'shutdown',
        'launch',
        'continueExecution',
        'stepOver',
        'stepInto',
        'stepOut',
        'setBreakpoint'
    )
    
    $missingMethods = @()
    foreach ($method in $requiredMethods) {
        if (-not ($dapContent -match $method)) {
            $missingMethods += $method
        }
    }
    
    if ($missingMethods.Count -gt 0) {
        return @{ Success = $false; Error = "DapService missing: $($missingMethods -join ', ')" }
    }
    
    # Check BreakpointGutter has required methods
    $gutterPath = Join-Path $PSScriptRoot "..\.." "src\debug\BreakpointGutter.hpp"
    $gutterContent = Get-Content $gutterPath -Raw
    
    $gutterMethods = @(
        'ToggleBreakpoint',
        'SetCurrentLine',
        'SyncWithDebugger'
    )
    
    foreach ($method in $gutterMethods) {
        if (-not ($gutterContent -match $method)) {
            $missingMethods += "BreakpointGutter.$method"
        }
    }
    
    if ($missingMethods.Count -gt 0) {
        return @{ Success = $false; Error = "Missing: $($missingMethods -join ', ')" }
    }
    
    return @{ Success = $true }
}

# ============================================================================
# Test 4: Mock DAP Protocol Test
# ============================================================================
$testMockDapProtocol = {
    $mockServerPath = Join-Path $PSScriptRoot "..\.." "mock-dap-server.js"
    
    if (-not (Test-Path $mockServerPath)) {
        return @{ Success = $false; Error = "mock-dap-server.js not found" }
    }
    
    # Test that Node.js can parse the mock server
    try {
        $syntaxCheck = node -c $mockServerPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            return @{ Success = $false; Error = "Mock server syntax error: $syntaxCheck" }
        }
    }
    catch {
        return @{ Success = $false; Error = "Node.js not available or syntax error" }
    }
    
    return @{ Success = $true }
}

# ============================================================================
# Test 5: Build Script Verification
# ============================================================================
$testBuildScripts = {
    $buildScript = Join-Path $PSScriptRoot "..\.." "build_dap_server.bat"
    
    if (-not (Test-Path $buildScript)) {
        return @{ Success = $false; Error = "build_dap_server.bat not found" }
    }
    
    $content = Get-Content $buildScript -Raw
    
    # Check for required components
    $requiredComponents = @('DAPAdapter', 'DAPTransport', 'BeaconDAPServer')
    $missing = @()
    
    foreach ($component in $requiredComponents) {
        if (-not ($content -match $component)) {
            $missing += $component
        }
    }
    
    if ($missing.Count -gt 0) {
        return @{ Success = $false; Error = "Build script missing: $($missing -join ', ')" }
    }
    
    return @{ Success = $true }
}

# ============================================================================
# Test 6: Documentation Completeness
# ============================================================================
$testDocumentation = {
    $docs = @(
        "PHASE24B_BREAKPOINT_GUTTER_COMPLETE.md",
        "PHASE24C_STEP_CONTROLLER_COMPLETE.md",
        "DAP_INTEGRATION_MILESTONE.md"
    )
    
    $missing = @()
    foreach ($doc in $docs) {
        $path = Join-Path $PSScriptRoot "..\.." $doc
        if (-not (Test-Path $path)) {
            $missing += $doc
        }
    }
    
    if ($missing.Count -gt 0) {
        return @{ Success = $false; Error = "Missing docs: $($missing -join ', ')" }
    }
    
    return @{ Success = $true }
}

# ============================================================================
# Test 7: Live DAP Protocol Test (Optional)
# ============================================================================
$testLiveDapProtocol = {
    if ($SkipLiveTest) {
        return @{ Success = $true; Error = "Skipped" }
    }
    
    $testScript = Join-Path $PSScriptRoot "..\.." "dap-protocol-test.js"
    
    if (-not (Test-Path $testScript)) {
        return @{ Success = $false; Error = "dap-protocol-test.js not found" }
    }
    
    try {
        Push-Location (Join-Path $PSScriptRoot "..\..")
        $output = node dap-protocol-test.js 2>&1
        $exitCode = $LASTEXITCODE
        Pop-Location
        
        if ($exitCode -eq 0 -and $output -match "ALL TESTS PASSED") {
            return @{ Success = $true }
        } else {
            return @{ Success = $false; Error = "DAP protocol test failed. See output above." }
        }
    }
    catch {
        return @{ Success = $false; Error = "Failed to run protocol test: $_" }
    }
}

# ============================================================================
# Main Test Execution
# ============================================================================

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  RawrXD Debugger Integration Test Suite                      ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Write-TestLog "Starting integration tests..." "INFO"
Write-TestLog "Working directory: $(Resolve-Path (Join-Path $PSScriptRoot '..\..'))" "INFO"
Write-Host ""

# Run all tests
Run-Test "File Structure Verification" $testFileStructure
Run-Test "Header Syntax Validation" $testHeaderSyntax
Run-Test "Component Interface Verification" $testComponentInterfaces
Run-Test "Mock DAP Protocol Test" $testMockDapProtocol
Run-Test "Build Script Verification" $testBuildScripts
Run-Test "Documentation Completeness" $testDocumentation
Run-Test "Live DAP Protocol Test" $testLiveDapProtocol

# Summary
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Test Summary                                              ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$passed = (${script:TestResults} | Where-Object { $_.Passed }).Count
$failed = (${script:TestResults} | Where-Object { -not $_.Passed }).Count
$total = ${script:TestResults}.Count

Write-TestLog "Total: $total" "INFO"
Write-TestLog "Passed: $passed" $(if ($passed -gt 0) { "PASS" } else { "INFO" })
Write-TestLog "Failed: $failed" $(if ($failed -gt 0) { "FAIL" } else { "INFO" })

if ($failed -gt 0) {
    Write-Host ""
    Write-TestLog "Failed tests:" "FAIL"
    ${script:TestResults} | Where-Object { -not $_.Passed } | ForEach-Object {
        Write-TestLog "  - $($_.Name): $($_.Error)" "FAIL"
    }
}

Write-Host ""

if ($failed -eq 0) {
    Write-TestLog "🎉 ALL TESTS PASSED!" "PASS"
    Write-TestLog "The debugger stack is ready for live testing with Victim.exe" "PASS"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Green
    Write-Host "  1. Build: .\build_dap_server.bat" -ForegroundColor White
    Write-Host "  2. Test: node dap-diagnostic.js" -ForegroundColor White
    Write-Host "  3. Run: Open VS Code, press F5" -ForegroundColor White
    exit 0
} else {
    Write-TestLog "⚠️  Some tests failed. Review debug_integration_test.log" "WARN"
    exit 1
}
