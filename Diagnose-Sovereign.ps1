# Sovereign Engine Diagnostic Script
# Verifies setup and identifies blockers

param(
    [string]$ModelPath = "$PSScriptRoot\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
)

$ErrorActionPreference = "Continue"
$issues = @()
$warnings = @()

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Sovereign Engine Diagnostic" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check for model file
Write-Host "[1/6] Checking model file..." -ForegroundColor Gray
if (Test-Path $ModelPath) {
    $size = (Get-Item $ModelPath).Length / 1MB
    Write-Host "  ✓ Model found: $([math]::Round($size,2)) MB" -ForegroundColor Green
    
    # Verify GGUF magic
    $bytes = Get-Content $ModelPath -Encoding Byte -TotalCount 4
    $magic = [BitConverter]::ToUInt32($bytes, 0)
    if ($magic -eq 0x46554747 -or $magic -eq 0x47475546) {
        Write-Host "  ✓ Valid GGUF format" -ForegroundColor Green
    } else {
        $issues += "Model file has invalid GGUF magic bytes"
        Write-Host "  ✗ Invalid GGUF format" -ForegroundColor Red
    }
} else {
    $issues += "Model file not found: $ModelPath"
    Write-Host "  ✗ Model not found" -ForegroundColor Red
    Write-Host "  Run: .\Download-Model.ps1" -ForegroundColor Yellow
}

# 2. Check for Sovereign executable
Write-Host ""
Write-Host "[2/6] Checking Sovereign executable..." -ForegroundColor Gray
$exePaths = @(
    "$PSScriptRoot\SovereignOrchestrator.exe",
    "$PSScriptRoot\build\SovereignOrchestrator.exe",
    "$PSScriptRoot\bin\SovereignOrchestrator.exe"
)
$exeFound = $false
foreach ($exe in $exePaths) {
    if (Test-Path $exe) {
        Write-Host "  ✓ Found: $exe" -ForegroundColor Green
        $exeFound = $true
        break
    }
}
if (!$exeFound) {
    $warnings += "SovereignOrchestrator.exe not found - needs build"
    Write-Host "  ⚠ Executable not found" -ForegroundColor Yellow
}

# 3. Check for required DLLs
Write-Host ""
Write-Host "[3/6] Checking dependencies..." -ForegroundColor Gray
$requiredDlls = @(
    "Sovereign_SDK.dll",
    "kernel32.dll",
    "user32.dll"
)
foreach ($dll in $requiredDlls) {
    $dllPath = "$PSScriptRoot\$dll"
    if (Test-Path $dllPath) {
        Write-Host "  ✓ $dll" -ForegroundColor Green
    } else {
        if ($dll -eq "Sovereign_SDK.dll") {
            $warnings += "Sovereign_SDK.dll not found - some features unavailable"
        }
        Write-Host "  ⚠ $dll not found" -ForegroundColor Yellow
    }
}

# 4. Check VS Code extension
Write-Host ""
Write-Host "[4/6] Checking VS Code extension..." -ForegroundColor Gray
$vsixFiles = Get-ChildItem "$PSScriptRoot\*.vsix" -ErrorAction SilentlyContinue
if ($vsixFiles) {
    Write-Host "  ✓ Extension package found: $($vsixFiles[0].Name)" -ForegroundColor Green
} else {
    $warnings += "VS Code extension .vsix not found"
    Write-Host "  ⚠ Extension package not found" -ForegroundColor Yellow
}

# 5. Check source files
Write-Host ""
Write-Host "[5/6] Checking source files..." -ForegroundColor Gray
$sourceFiles = @(
    "src\core\sovereign_super_node.cpp",
    "src\engine\sovereign_engines.cpp"
)
$srcFound = 0
foreach ($src in $sourceFiles) {
    $srcPath = "$PSScriptRoot\$src"
    if (Test-Path $srcPath) {
        $srcFound++
    }
}
if ($srcFound -eq $sourceFiles.Count) {
    Write-Host "  ✓ All source files present" -ForegroundColor Green
} else {
    $warnings += "Some source files missing ($srcFound/$($sourceFiles.Count))"
    Write-Host "  ⚠ Some source files missing" -ForegroundColor Yellow
}

# 6. Check build system
Write-Host ""
Write-Host "[6/6] Checking build system..." -ForegroundColor Gray
if (Test-Path "$PSScriptRoot\CMakeLists.txt") {
    Write-Host "  ✓ CMake configuration found" -ForegroundColor Green
} else {
    $warnings += "CMakeLists.txt not found"
    Write-Host "  ⚠ CMake not configured" -ForegroundColor Yellow
}

# Summary
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Diagnostic Summary" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

if ($issues.Count -eq 0 -and $warnings.Count -eq 0) {
    Write-Host "✓ All checks passed! Ready to run." -ForegroundColor Green
    Write-Host ""
    Write-Host "To start inference:" -ForegroundColor Yellow
    Write-Host "  .\SovereignOrchestrator.exe `"$ModelPath`"" -ForegroundColor White
} else {
    if ($issues.Count -gt 0) {
        Write-Host "ERRORS (Must fix):" -ForegroundColor Red
        foreach ($issue in $issues) {
            Write-Host "  ✗ $issue" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    if ($warnings.Count -gt 0) {
        Write-Host "WARNINGS (Recommended):" -ForegroundColor Yellow
        foreach ($warning in $warnings) {
            Write-Host "  ⚠ $warning" -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
    Write-Host "Quick fixes:" -ForegroundColor Cyan
    if ($issues -contains "Model file not found: $ModelPath") {
        Write-Host "  1. Run: .\Download-Model.ps1" -ForegroundColor White
    }
    if ($warnings -contains "SovereignOrchestrator.exe not found - needs build") {
        Write-Host "  2. Build: cmake --build build --config Release" -ForegroundColor White
    }
}

Write-Host ""
