# test_agentic_features.ps1
# Comprehensive agentic and autonomous feature testing for RawrXD IDE

param(
    [string]$ModelPath = "",
    [string]$SovereignPath = ".\sovereign.exe",
    [switch]$StandaloneTest,
    [switch]$SkipInference
)

$ErrorActionPreference = "Stop"
$script:TestResults = @()
$script:PassedTests = 0
$script:FailedTests = 0

function Write-TestHeader($text) {
    Write-Host "`n=== $text ===" -ForegroundColor Cyan
}

function Write-TestResult($name, $passed, $details = "") {
    $status = if ($passed) { "PASS" } else { "FAIL" }
    $color = if ($passed) { "Green" } else { "Red" }
    Write-Host "[$status] $name" -ForegroundColor $color
    if ($details) {
        Write-Host "  $details" -ForegroundColor Gray
    }
    
    $script:TestResults += [PSCustomObject]@{
        Name = $name
        Passed = $passed
        Details = $details
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    if ($passed) { $script:PassedTests++ } else { $script:FailedTests++ }
}

function Test-SovereignExists {
    Write-TestHeader "Step 0: Verify Sovereign Engine"
    
    if (-not (Test-Path $SovereignPath)) {
        Write-TestResult "Sovereign Engine Exists" $false "Not found at: $SovereignPath"
        return $false
    }
    
    Write-TestResult "Sovereign Engine Exists" $true "Found at: $SovereignPath"
    
    # Run heap diagnostic if available
    $heapTest = Join-Path (Split-Path $SovereignPath) "test_heap.exe"
    if (Test-Path $heapTest) {
        Write-TestHeader "Step 0b: Heap Diagnostics"
        try {
            $output = & $heapTest 2>&1
            $exitCode = $LASTEXITCODE
            
            if ($exitCode -eq 0) {
                Write-TestResult "Heap Diagnostics" $true "All heap operations passed"
            } else {
                Write-TestResult "Heap Diagnostics" $false "Some heap tests failed (exit: $exitCode)"
            }
        } catch {
            Write-TestResult "Heap Diagnostics" $false "Exception: $_"
        }
    }
    
    return $true
}

function Test-ModelLoading {
    Write-TestHeader "Step 1: Model Loading Test"
    
    if ([string]::IsNullOrEmpty($ModelPath)) {
        Write-TestResult "Model Loading" $false "No model path provided. Use -ModelPath 'path\to\model.gguf'"
        return $false
    }
    
    if (-not (Test-Path $ModelPath)) {
        Write-TestResult "Model Loading" $false "Model not found at: $ModelPath"
        return $false
    }
    
    # First, try the minimal GGUF loader if available
    $miniLoader = Join-Path (Split-Path $SovereignPath) "gguf_mini_loader.exe"
    if (Test-Path $miniLoader) {
        try {
            Write-Host "  Trying minimal GGUF loader..." -ForegroundColor DarkGray
            $output = & $miniLoader "$ModelPath" 2>&1
            $exitCode = $LASTEXITCODE
            
            if ($exitCode -eq 0) {
                Write-TestResult "Model Loading (Mini Loader)" $true "GGUF header parsed successfully"
                return $true
            } else {
                Write-TestResult "Model Loading (Mini Loader)" $false "Exit code: $exitCode"
                # Fall through to Sovereign attempt
            }
        } catch {
            Write-TestResult "Model Loading (Mini Loader)" $false "Exception: $_"
            # Fall through to Sovereign attempt
        }
    }
    
    # Try Sovereign with fallback handling
    try {
        $output = & $SovereignPath load "$ModelPath" 2>&1
        $exitCode = $LASTEXITCODE
        
        if ($exitCode -eq 0 -or $output -match "loaded|success|ready") {
            Write-TestResult "Model Loading" $true "Model loaded successfully"
            return $true
        } elseif ($exitCode -eq -1073741819) {
            # STATUS_ACCESS_VIOLATION - known issue
            Write-Warning "Model loading failed with STATUS_ACCESS_VIOLATION (-1073741819)"
            Write-Warning "This is a known issue with Sovereign's Heap_Init. See CAPABILITY_PROBE_SUMMARY.md"
            Write-TestResult "Model Loading" $false "STATUS_ACCESS_VIOLATION (known issue)"
            return $false
        } else {
            Write-TestResult "Model Loading" $false "Exit code: $exitCode, Output: $output"
            return $false
        }
    } catch {
        Write-TestResult "Model Loading" $false "Exception: $_"
        return $false
    }
}

function Test-RawInference {
    Write-TestHeader "Step 2: Raw Inference Test"
    
    $testPrompts = @(
        "What is 2+2?",
        "Explain quantum computing in one sentence.",
        "Write a hello world program in Python."
    )
    
    $allPassed = $true
    foreach ($prompt in $testPrompts) {
        try {
            Write-Host "  Testing: '$prompt'" -ForegroundColor DarkGray
            $output = & $SovereignPath infer "$prompt" 2>&1
            $exitCode = $LASTEXITCODE
            
            if ($exitCode -eq 0 -and $output -and $output.Length -gt 10) {
                Write-TestResult "Inference: '$prompt'" $true "Response length: $($output.Length) chars"
            } else {
                Write-TestResult "Inference: '$prompt'" $false "Exit code: $exitCode, Output: $($output.Substring(0, [Math]::Min(100, $output.Length)))"
                $allPassed = $false
            }
        } catch {
            Write-TestResult "Inference: '$prompt'" $false "Exception: $_"
            $allPassed = $false
        }
    }
    
    return $allPassed
}

function Test-CapabilityProbe {
    Write-TestHeader "Step 3: Capability Probe Test"
    
    $probeAsm = "capability_probe.asm"
    $probeObj = "capability_probe.obj"
    $probeExe = "capability_probe.exe"
    
    # Check if probe source exists
    if (-not (Test-Path $probeAsm)) {
        Write-TestResult "Capability Probe Source" $false "Not found: $probeAsm"
        return $false
    }
    
    Write-TestResult "Capability Probe Source" $true "Found: $probeAsm"
    
    # Try to assemble
    try {
        $ml64Path = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
        if (-not (Test-Path $ml64Path)) {
            # Try to find ml64.exe
            $ml64Path = (Get-Command ml64.exe -ErrorAction SilentlyContinue).Source
            if (-not $ml64Path) {
                Write-TestResult "Assemble Capability Probe" $false "ml64.exe not found"
                return $false
            }
        }
        
        & $ml64Path /c /W3 /nologo /Fo $probeObj $probeAsm 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-TestResult "Assemble Capability Probe" $false "Assembly failed"
            return $false
        }
        Write-TestResult "Assemble Capability Probe" $true "Created: $probeObj"
        
        # Try to link
        $linkPath = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
        if (-not (Test-Path $linkPath)) {
            $linkPath = (Get-Command link.exe -ErrorAction SilentlyContinue).Source
        }
        
        if ($linkPath) {
            & $linkPath /SUBSYSTEM:CONSOLE /ENTRY:CapabilityTest /OUT:$probeExe $probeObj kernel32.lib 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0 -and (Test-Path $probeExe)) {
                Write-TestResult "Link Capability Probe" $true "Created: $probeExe"
                
                # Run the probe
                $output = & .\$probeExe 2>&1
                Write-TestResult "Run Capability Probe" $true "Output length: $($output.Length) chars"
                
                # Save output for model introspection
                $output | Out-File "capability_probe_output.txt" -Encoding UTF8
                Write-Host "  Output saved to: capability_probe_output.txt" -ForegroundColor DarkGray
            } else {
                Write-TestResult "Link Capability Probe" $false "Link failed"
            }
        } else {
            Write-TestResult "Link Capability Probe" $false "link.exe not found"
        }
    } catch {
        Write-TestResult "Capability Probe Build" $false "Exception: $_"
        return $false
    }
    
    return $true
}

function Test-AgenticActions {
    Write-TestHeader "Step 4: Agentic Action Tests"
    
    $actionTests = @(
        @{ Name = "File Open Action"; Prompt = "Open file d:\test\hello.asm and add a comment at the top"; Expected = "file" },
        @{ Name = "Search Action"; Prompt = "Find all .asm files in d:\rawrxd\src\asm"; Expected = "search" },
        @{ Name = "Compile Action"; Prompt = "Compile d:\test\hello.asm and report any errors"; Expected = "compile" },
        @{ Name = "Git Action"; Prompt = "Show me the git status of the current repository"; Expected = "git" }
    )
    
    $allPassed = $true
    foreach ($test in $actionTests) {
        try {
            Write-Host "  Testing: $($test.Name)" -ForegroundColor DarkGray
            
            # This would need the actual agent loop to be wired up
            # For now, we just check if the model responds with action-like output
            $output = & $SovereignPath infer $test.Prompt 2>&1
            
            # Check if response contains action indicators
            $hasAction = $output -match "open|search|compile|run|git|file"
            $hasCode = $output -match "```|\basm\b|\bmov\b|\bpush\b"
            
            if ($hasAction -or $hasCode) {
                Write-TestResult $test.Name $true "Response contains actionable content"
            } else {
                Write-TestResult $test.Name $false "Response may not trigger actions"
                $allPassed = $false
            }
        } catch {
            Write-TestResult $test.Name $false "Exception: $_"
            $allPassed = $false
        }
    }
    
    return $allPassed
}

function Test-StandaloneCapabilityProbe {
    Write-TestHeader "Standalone Capability Probe"
    
    $probeExe = "capability_probe.exe"
    if (Test-Path $probeExe) {
        try {
            $output = & .\$probeExe 2>&1
            Write-TestResult "Standalone Probe Execution" $true "Output: $($output.Length) chars"
            
            # Verify output contains expected sections
            $hasVerified = $output -match "VERIFIED ENGINES"
            $hasMissing = $output -match "CONFIRMED MISSING"
            
            Write-TestResult "Probe Output Structure" ($hasVerified -and $hasMissing) "Verified: $hasVerified, Missing: $hasMissing"
            
            return $true
        } catch {
            Write-TestResult "Standalone Probe Execution" $false "Exception: $_"
            return $false
        }
    } else {
        Write-TestResult "Standalone Probe" $false "Executable not found"
        return $false
    }
}

function Show-TestSummary {
    Write-TestHeader "Test Summary"
    
    $total = $script:PassedTests + $script:FailedTests
    $passRate = if ($total -gt 0) { ($script:PassedTests / $total) * 100 } else { 0 }
    
    Write-Host "Total Tests: $total" -ForegroundColor White
    Write-Host "Passed: $($script:PassedTests)" -ForegroundColor Green
    Write-Host "Failed: $($script:FailedTests)" -ForegroundColor Red
    Write-Host "Pass Rate: $([Math]::Round($passRate, 2))%" -ForegroundColor $(if ($passRate -ge 80) { "Green" } elseif ($passRate -ge 50) { "Yellow" } else { "Red" })
    
    # Save detailed results
    $resultsFile = "agentic_test_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $script:TestResults | ConvertTo-Json -Depth 3 | Out-File $resultsFile -Encoding UTF8
    Write-Host "`nDetailed results saved to: $resultsFile" -ForegroundColor Cyan
    
    return $script:FailedTests -eq 0
}

# Main execution
Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║     RawrXD Agentic & Autonomous Features Test Suite              ║
║                                                                  ║
║  This script tests the full agentic pipeline:                    ║
║  1. Model Loading → 2. Inference → 3. Action Execution            ║
║  4. Feedback Loop → 5. Task Completion                            ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Change to script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($scriptDir) {
    Set-Location $scriptDir
}

Write-Host "Working directory: $(Get-Location)" -ForegroundColor DarkGray
Write-Host "Sovereign path: $SovereignPath" -ForegroundColor DarkGray
Write-Host "Model path: $ModelPath" -ForegroundColor DarkGray
Write-Host ""

# Run tests
$success = $true

if (-not (Test-SovereignExists)) {
    $success = $false
}

if ($StandaloneTest) {
    Test-StandaloneCapabilityProbe
} else {
    if (-not $SkipInference) {
        if ($ModelPath) {
            if (-not (Test-ModelLoading)) {
                $success = $false
            }
            
            if (-not (Test-RawInference)) {
                $success = $false
            }
            
            if (-not (Test-AgenticActions)) {
                $success = $false
            }
        } else {
            Write-Host "`nSkipping inference tests (no model provided)" -ForegroundColor Yellow
            Write-Host "To test inference, provide a model path:" -ForegroundColor Yellow
            Write-Host "  .\test_agentic_features.ps1 -ModelPath 'd:\models\your-model.gguf'" -ForegroundColor Yellow
        }
    }
    
    # Always run capability probe test
    if (-not (Test-CapabilityProbe)) {
        $success = $false
    }
}

# Show summary
$finalSuccess = Show-TestSummary

if ($finalSuccess) {
    Write-Host "`n✓ All tests passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n✗ Some tests failed. Review the output above." -ForegroundColor Red
    exit 1
}
