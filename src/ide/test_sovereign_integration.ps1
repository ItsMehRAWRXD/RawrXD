# Test Sovereign IDE Integration
# ==============================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Sovereign IDE Integration Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Check source files exist
Write-Host "[TEST 1] Checking source files..." -ForegroundColor Yellow
$files = @(
    "RawrXD_IDE_Win32.h",
    "RawrXD_IDE_Win32.cpp",
    "SovereignBridge.hpp",
    "SovereignBridge.cpp",
    "SOVEREIGN_INTEGRATION.md"
)

$allExist = $true
foreach ($file in $files) {
    if (Test-Path $file) {
        Write-Host "  ✓ $file" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $file NOT FOUND" -ForegroundColor Red
        $allExist = $false
    }
}

if (-not $allExist) {
    Write-Host "`nFAILED: Missing source files" -ForegroundColor Red
    exit 1
}

# Test 2: Check menu IDs defined
Write-Host "`n[TEST 2] Checking menu ID definitions..." -ForegroundColor Yellow
$content = Get-Content "RawrXD_IDE_Win32.h" -Raw
$ids = @(
    "IDM_TOOLS_SOVEREIGN_RUN",
    "IDM_TOOLS_VIEW_EVIDENCE"
)

$allFound = $true
foreach ($id in $ids) {
    if ($content -match $id) {
        Write-Host "  ✓ $id defined" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $id NOT FOUND" -ForegroundColor Red
        $allFound = $false
    }
}

if (-not $allFound) {
    Write-Host "`nFAILED: Missing menu ID definitions" -ForegroundColor Red
    exit 1
}

# Test 3: Check function declarations
Write-Host "`n[TEST 3] Checking function declarations..." -ForegroundColor Yellow
$funcs = @(
    "RawrXD_IDE_RunSovereignValidation",
    "RawrXD_IDE_ViewEvidenceBundle"
)

$allDeclared = $true
foreach ($func in $funcs) {
    if ($content -match $func) {
        Write-Host "  ✓ $func declared" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $func NOT FOUND" -ForegroundColor Red
        $allDeclared = $false
    }
}

if (-not $allDeclared) {
    Write-Host "`nFAILED: Missing function declarations" -ForegroundColor Red
    exit 1
}

# Test 4: Check implementation
Write-Host "`n[TEST 4] Checking implementation..." -ForegroundColor Yellow
$implContent = Get-Content "RawrXD_IDE_Win32.cpp" -Raw

$implChecks = @(
    "IDM_TOOLS_SOVEREIGN_RUN",
    "IDM_TOOLS_VIEW_EVIDENCE",
    "RawrXD_IDE_RunSovereignValidation",
    "RawrXD_IDE_ViewEvidenceBundle",
    "SOVEREIGN VALIDATION",
    "rawrxd.exe",
    "--validate",
    "--autonomous"
)

$allImplFound = $true
foreach ($check in $implChecks) {
    if ($implContent -match [regex]::Escape($check)) {
        Write-Host "  ✓ '$check' found in implementation" -ForegroundColor Green
    } else {
        Write-Host "  ✗ '$check' NOT FOUND" -ForegroundColor Red
        $allImplFound = $false
    }
}

if (-not $allImplFound) {
    Write-Host "`nFAILED: Implementation incomplete" -ForegroundColor Red
    exit 1
}

# Test 5: Check menu wiring
Write-Host "`n[TEST 5] Checking menu wiring..." -ForegroundColor Yellow
if ($implContent -match "AppendMenuW.*IDM_TOOLS_SOVEREIGN_RUN") {
    Write-Host "  ✓ Sovereign Run menu item added" -ForegroundColor Green
} else {
    Write-Host "  ✗ Sovereign Run menu NOT WIRED" -ForegroundColor Red
    exit 1
}

if ($implContent -match "case IDM_TOOLS_SOVEREIGN_RUN") {
    Write-Host "  ✓ Command handler wired" -ForegroundColor Green
} else {
    Write-Host "  ✗ Command handler NOT WIRED" -ForegroundColor Red
    exit 1
}

# Test 6: Check accelerator
Write-Host "`n[TEST 6] Checking keyboard shortcut..." -ForegroundColor Yellow
if ($implContent -match "FCONTROL.*FSHIFT.*FVIRTKEY.*'V'.*IDM_TOOLS_SOVEREIGN_RUN") {
    Write-Host "  ✓ Ctrl+Shift+V accelerator defined" -ForegroundColor Green
} else {
    Write-Host "  ✗ Accelerator NOT DEFINED" -ForegroundColor Red
    exit 1
}

# Summary
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "ALL TESTS PASSED" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Integration Status:" -ForegroundColor Cyan
Write-Host "  • Menu items: ADDED" -ForegroundColor White
Write-Host "  • Accelerators: CONFIGURED" -ForegroundColor White
Write-Host "  • Command handlers: WIRED" -ForegroundColor White
Write-Host "  • Implementation: COMPLETE" -ForegroundColor White
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Build IDE: .\build_ide_with_sovereign.bat" -ForegroundColor White
Write-Host "  2. Ensure rawrxd.exe is available" -ForegroundColor White
Write-Host "  3. Run IDE and press Ctrl+Shift+V" -ForegroundColor White
Write-Host ""
