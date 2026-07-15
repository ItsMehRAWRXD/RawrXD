# RawrXD LSP Smoke Test
# Tests basic LSP functionality for RawrXD-Script

param(
    [string]$ExtensionPath = "$env:USERPROFILE\.vscode\extensions\rawrxd.rawrxd-lsp-client-0.1.0",
    [string]$TestFile = "d:\test.rxs",
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"
$Success = $true

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RawrXD LSP Smoke Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Verify extension structure
Write-Host "[TEST 1] Extension Structure..." -NoNewline
$requiredFiles = @(
    "package.json",
    "out\extension.js",
    "bin\RawrXD_LSPServer.exe"
)

$allExist = $true
foreach ($file in $requiredFiles) {
    $fullPath = Join-Path $ExtensionPath $file
    if (-not (Test-Path $fullPath)) {
        Write-Host " MISSING: $file" -ForegroundColor Red
        $allExist = $false
        $Success = $false
    }
}

if ($allExist) {
    Write-Host " PASS" -ForegroundColor Green
} else {
    Write-Host " FAIL" -ForegroundColor Red
}

# Test 2: Verify LSP binary
Write-Host "[TEST 2] LSP Binary..." -NoNewline
$lspBinary = Join-Path $ExtensionPath "bin\RawrXD_LSPServer.exe"
if (Test-Path $lspBinary) {
    $fileInfo = Get-Item $lspBinary
    Write-Host " PASS ($([math]::Round($fileInfo.Length/1KB,0)) KB)" -ForegroundColor Green
} else {
    Write-Host " FAIL (not found)" -ForegroundColor Red
    $Success = $false
}

# Test 3: Check if LSP process is running
Write-Host "[TEST 3] LSP Process..." -NoNewline
Start-Sleep -Milliseconds 500
$lspProcess = Get-Process | Where-Object { $_.ProcessName -like "*RawrXD*LSP*" -or $_.ProcessName -like "*LSPServer*" } | Select-Object -First 1
if ($lspProcess) {
    Write-Host " PASS (PID: $($lspProcess.Id))" -ForegroundColor Green
} else {
    Write-Host " NOT RUNNING (may need to open .rxs file)" -ForegroundColor Yellow
}

# Test 4: Test file exists
Write-Host "[TEST 4] Test File..." -NoNewline
if (Test-Path $TestFile) {
    Write-Host " PASS ($TestFile)" -ForegroundColor Green
} else {
    Write-Host " CREATING..." -ForegroundColor Yellow
    @"
// RawrXD-Script Smoke Test File
// This file tests LSP functionality

function test() {
    console.log("Hello RawrXD!");
    return 42;
}

// Try typing here for completions:
// 
"@ | Set-Content $TestFile
    Write-Host " CREATED" -ForegroundColor Green
}

# Test 5: VS Code logs check
Write-Host "[TEST 5] VS Code Logs..." -NoNewline
$logDir = "$env:APPDATA\Code\logs"
if (Test-Path $logDir) {
    $latestLogDir = Get-ChildItem $logDir -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latestLogDir) {
        $extLogs = Get-ChildItem $latestLogDir.FullName -Recurse -Filter "*extension*" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($extLogs) {
            Write-Host " PASS (logs available)" -ForegroundColor Green
        } else {
            Write-Host " INFO (no extension logs yet)" -ForegroundColor Yellow
        }
    } else {
        Write-Host " INFO (no logs)" -ForegroundColor Yellow
    }
} else {
    Write-Host " SKIP (log dir not found)" -ForegroundColor Gray
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
if ($Success) {
    Write-Host "  SMOKE TEST PASSED" -ForegroundColor Green
} else {
    Write-Host "  SMOKE TEST FAILED" -ForegroundColor Red
}
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Open test.rxs in VS Code" -ForegroundColor Gray
Write-Host "  2. Check Output panel -> 'RawrXD LSP'" -ForegroundColor Gray
Write-Host "  3. Try typing for completions" -ForegroundColor Gray
Write-Host ""

if ($Success) { exit 0 } else { exit 1 }
