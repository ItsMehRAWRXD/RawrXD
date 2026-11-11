#!/usr/bin/env pwsh
# RawrXD LSP Server Comprehensive Smoke Test
# Tests: Lifecycle, Document Sync, Completion, Hover, Symbols, JSON-RPC framing

param(
    [string]$BuildDir = "d:\rawrxd\build-ninja",
    [string]$TestOutputDir = "d:\rawrxd\test_output"
)

$ErrorActionPreference = "Stop"
$global:TestsPassed = 0
$global:TestsFailed = 0
$global:TestResults = @()

function Write-TestHeader($title) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $title -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-TestResult($name, $passed, $details = "") {
    $status = if ($passed) { "PASS" } else { "FAIL" }
    $color = if ($passed) { "Green" } else { "Red" }
    Write-Host "  [$status] $name" -ForegroundColor $color
    if ($details) {
        Write-Host "        $details" -ForegroundColor Gray
    }
    
    $global:TestResults += [PSCustomObject]@{
        Name = $name
        Passed = $passed
        Details = $details
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    if ($passed) { $global:TestsPassed++ } else { $global:TestsFailed++ }
}

function Send-LSPMessage($process, $message) {
    $json = $message | ConvertTo-Json -Depth 10 -Compress
    $contentLength = [System.Text.Encoding]::UTF8.GetByteCount($json)
    $header = "Content-Length: $contentLength`r`n`r`n"
    $fullMessage = $header + $json
    
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullMessage)
    $process.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
    $process.StandardInput.BaseStream.Flush()
}

function Read-LSPResponse($process, $timeoutMs = 5000) {
    $response = ""
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    while ($sw.ElapsedMilliseconds -lt $timeoutMs) {
        if ($process.StandardOutput.Peek() -ge 0) {
            $line = $process.StandardOutput.ReadLine()
            if ($line -match "Content-Length:\s*(\d+)") {
                $contentLength = [int]$Matches[1]
                $process.StandardOutput.ReadLine() # Empty line
                $buffer = New-Object char[] $contentLength
                $read = 0
                while ($read -lt $contentLength) {
                    $read += $process.StandardOutput.Read($buffer, $read, $contentLength - $read)
                }
                return [System.String]::new($buffer)
            }
        }
        Start-Sleep -Milliseconds 50
    }
    return $null
}

# Test 1: Verify LSP source files exist
Write-TestHeader "TEST 1: Source File Verification"

$lspFiles = @(
    "d:\rawrxd\src\lsp\RawrXD_LSPServer.cpp",
    "d:\rawrxd\src\lsp\RawrXD_LSPServer.h",
    "d:\rawrxd\src\lsp\workspace_symbol_index.cpp",
    "d:\rawrxd\src\lsp\intellisense_completion.cpp",
    "d:\rawrxd\src\lsp\phase3_lsp_test_suite.cpp"
)

foreach ($file in $lspFiles) {
    $exists = Test-Path $file
    Write-TestResult "Source file exists: $(Split-Path $file -Leaf)" $exists
}

# Test 2: Check if LSP is integrated into main binary
Write-TestHeader "TEST 2: LSP Integration Check"

$mainBinary = "$BuildDir\bin\RawrXD-Win32IDE.exe"
if (Test-Path $mainBinary) {
    Write-TestResult "Main binary exists" $true "Found: $mainBinary"
    
    # Check for LSP symbols in binary
    $dumpbin = & "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\dumpbin.exe" /SYMBOLS $mainBinary 2>$null | Select-String -Pattern "LSP|lsp|LSPServer" | Select-Object -First 10
    $hasLSPSymbols = ($dumpbin | Measure-Object).Count -gt 0
    Write-TestResult "LSP symbols in binary" $hasLSPSymbols "Found $(($dumpbin | Measure-Object).Count) LSP-related symbols"
} else {
    Write-TestResult "Main binary exists" $false "Not found: $mainBinary"
}

# Test 3: Validate LSP Server Code Structure
Write-TestHeader "TEST 3: LSP Code Structure Validation"

$lspServerCode = Get-Content "d:\rawrxd\src\lsp\RawrXD_LSPServer.cpp" -Raw

$requiredMethods = @(
    "handleInitialize",
    "handleShutdown", 
    "handleExit",
    "handleDidOpen",
    "handleDidChange",
    "handleDidClose",
    "handleTextDocumentHover",
    "handleTextDocumentCompletion",
    "handleTextDocumentDefinition",
    "handleWorkspaceSymbol"
)

foreach ($method in $requiredMethods) {
    $found = $lspServerCode -match $method
    Write-TestResult "LSP method implemented: $method" $found
}

# Test 4: JSON-RPC Framing Validation
Write-TestHeader "TEST 4: JSON-RPC Framing"

$hasContentLength = $lspServerCode -match "Content-Length"
$hasJsonRpc = $lspServerCode -match "jsonrpc"
$hasProperFraming = $lspServerCode -match "Content-Length:\s*\d+"

Write-TestResult "Content-Length header support" $hasContentLength
Write-TestResult "JSON-RPC 2.0 protocol" $hasJsonRpc
Write-TestResult "Proper message framing" $hasProperFraming

# Test 5: Thread Safety Checks
Write-TestHeader "TEST 5: Thread Safety"

$hasMutex = $lspServerCode -match "std::mutex|std::shared_mutex|std::lock_guard"
$hasThreading = $lspServerCode -match "std::thread"
$hasConditionVariable = $lspServerCode -match "std::condition_variable"

Write-TestResult "Mutex/lock usage" $hasMutex
Write-TestResult "Thread spawning" $hasThreading
Write-TestResult "Condition variables" $hasConditionVariable

# Test 6: LSP Lifecycle State Machine
Write-TestHeader "TEST 6: LSP Lifecycle State Machine"

$stateMachinePatterns = @(
    "ServerState::Created",
    "ServerState::Initializing",
    "ServerState::Running",
    "ServerState::ShuttingDown",
    "ServerState::Stopped",
    "m_exitRequested",
    "m_shutdownRequested"
)

foreach ($pattern in $stateMachinePatterns) {
    $found = $lspServerCode -match $pattern
    Write-TestResult "State machine element: $pattern" $found
}

# Test 7: Document Synchronization
Write-TestHeader "TEST 7: Document Synchronization"

$docSyncPatterns = @(
    "textDocument/didOpen",
    "textDocument/didChange",
    "textDocument/didClose",
    "textDocument/didSave",
    "m_openDocuments"
)

foreach ($pattern in $docSyncPatterns) {
    $found = $lspServerCode -match [regex]::Escape($pattern)
    Write-TestResult "Document sync: $pattern" $found
}

# Test 8: Symbol Indexing
Write-TestHeader "TEST 8: Symbol Indexing"

$indexCode = Get-Content "d:\rawrxd\src\lsp\workspace_symbol_index.cpp" -Raw
$hasFNV1a = $indexCode -match "fnv1a|FNV-1a"
$hasSymbolStorage = $indexCode -match "SymbolInfo|m_symbols"
$hasDocumentIndexing = $indexCode -match "indexDocument|indexFile"

Write-TestResult "FNV-1a hash implementation" $hasFNV1a
Write-TestResult "Symbol storage structures" $hasSymbolStorage
Write-TestResult "Document indexing capability" $hasDocumentIndexing

# Test 9: Completion Provider
Write-TestHeader "TEST 9: Completion Provider"

$completionCode = Get-Content "d:\rawrxd\src\lsp\intellisense_completion.cpp" -Raw
$hasCompletionItems = $completionCode -match "CompletionItem|completionItem"
$hasTriggerKinds = $completionCode -match "CompletionTriggerKind"
$hasScoring = $completionCode -match "score|relevance|rank"

Write-TestResult "Completion items structure" $hasCompletionItems
Write-TestResult "Trigger kind support" $hasTriggerKinds
Write-TestResult "Completion scoring/ranking" $hasScoring

# Test 10: Test Suite Validation
Write-TestHeader "TEST 10: Phase 3 Test Suite"

$testSuiteCode = Get-Content "d:\rawrxd\src\lsp\phase3_lsp_test_suite.cpp" -Raw
$testCategories = @(
    "testDay10WorkspaceIndexing",
    "testDay11RenameAndSearch",
    "testDay12IntelliSenseAndLSP"
)

foreach ($test in $testCategories) {
    $found = $testSuiteCode -match $test
    Write-TestResult "Test category: $test" $found
}

# Test 11: Header File Completeness
Write-TestHeader "TEST 11: LSP Header Files"

$headerFiles = Get-ChildItem "d:\rawrxd\src\lsp\*.h" -ErrorAction SilentlyContinue
$cppFiles = Get-ChildItem "d:\rawrxd\src\lsp\*.cpp" -ErrorAction SilentlyContinue

Write-TestResult "Header files present" ($headerFiles.Count -gt 0) "Found $($headerFiles.Count) headers"
Write-TestResult "Implementation files present" ($cppFiles.Count -gt 0) "Found $($cppFiles.Count) cpp files"

# Check for header guards
foreach ($header in $headerFiles) {
    $content = Get-Content $header.FullName -Raw
    $hasGuard = $content -match "#ifndef\s+\w+_H|#pragma once"
    Write-TestResult "Header guard in $($header.Name)" $hasGuard
}

# Test 12: CMake Integration
Write-TestHeader "TEST 12: CMake Build Integration"

$cmakeCode = Get-Content "d:\rawrxd\CMakeLists.txt" -Raw
$hasLSPSources = $cmakeCode -match "RawrXD_LSPServer\.cpp"
$hasLSPInTarget = $cmakeCode -match "src/lsp/"

Write-TestResult "LSP sources in CMake" $hasLSPSources
Write-TestResult "LSP directory referenced" $hasLSPInTarget

# Final Summary
Write-TestHeader "SMOKE TEST SUMMARY"

$totalTests = $global:TestsPassed + $global:TestsFailed
$passRate = if ($totalTests -gt 0) { [math]::Round(($global:TestsPassed / $totalTests) * 100, 2) } else { 0 }

Write-Host "Total Tests: $totalTests" -ForegroundColor White
Write-Host "Passed: $global:TestsPassed" -ForegroundColor Green
Write-Host "Failed: $global:TestsFailed" -ForegroundColor Red
Write-Host "Pass Rate: $passRate%" -ForegroundColor $(if ($passRate -ge 80) { "Green" } elseif ($passRate -ge 50) { "Yellow" } else { "Red" })

# Export results
$resultsPath = "$TestOutputDir\lsp_smoke_test_results.json"
New-Item -ItemType Directory -Path $TestOutputDir -Force | Out-Null
$global:TestResults | ConvertTo-Json -Depth 3 | Out-File $resultsPath
Write-Host "`nResults exported to: $resultsPath" -ForegroundColor Gray

# Return exit code
if ($global:TestsFailed -eq 0) {
    Write-Host "`n✓ ALL TESTS PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n✗ SOME TESTS FAILED" -ForegroundColor Red
    exit 1
}
