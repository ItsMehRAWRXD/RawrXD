# BenignPacker Windows Build Script (PowerShell)
# Advanced PE Packer with Encryption Features

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   BenignPacker Windows Build Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Visual Studio is available
try {
    $clPath = Get-Command cl -ErrorAction Stop
    Write-Host "✓ Visual Studio compiler found: $($clPath.Source)" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Visual Studio compiler (cl.exe) not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install Visual Studio 2019/2022 with C++ development tools." -ForegroundColor Yellow
    Write-Host "Download from: https://visualstudio.microsoft.com/downloads/" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Make sure to include:" -ForegroundColor Yellow
    Write-Host "- C++ development tools" -ForegroundColor Yellow
    Write-Host "- Windows 10/11 SDK" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""

# Check if required files exist
$requiredFiles = @(
    "VS2022_GUI_Benign_Packer.cpp",
    "ultimate_encryption_integration.h",
    "enhanced_encryption_system.h",
    "cross_platform_encryption.h",
    "tiny_loader.h",
    "enhanced_loader_utils.h",
    "enhanced_tiny_loader.h"
)

foreach ($file in $requiredFiles) {
    if (Test-Path $file) {
        Write-Host "✓ $file found" -ForegroundColor Green
    } else {
        Write-Host "ERROR: $file not found!" -ForegroundColor Red
        Write-Host "Please make sure all source files are present." -ForegroundColor Yellow
        Read-Host "Press Enter to exit"
        exit 1
    }
}

Write-Host ""
Write-Host "✓ All required source files found" -ForegroundColor Green
Write-Host ""

# Set compiler flags
$cxxFlags = "/std:c++17 /O2 /EHsc /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x0601"
$libs = "ole32.lib crypt32.lib wininet.lib wintrust.lib imagehlp.lib comctl32.lib shell32.lib advapi32.lib gdi32.lib user32.lib kernel32.lib"

Write-Host "Building BenignPacker with advanced encryption features..." -ForegroundColor Yellow
Write-Host ""

# Compile the main application
$compileCommand = "cl $cxxFlags /Fe:BenignPacker.exe VS2022_GUI_Benign_Packer.cpp $libs"
Write-Host "Running: $compileCommand" -ForegroundColor Gray

try {
    Invoke-Expression $compileCommand
    if ($LASTEXITCODE -ne 0) {
        throw "Compilation failed with exit code $LASTEXITCODE"
    }
} catch {
    Write-Host ""
    Write-Host "ERROR: Compilation failed!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Common solutions:" -ForegroundColor Yellow
    Write-Host "1. Make sure Visual Studio is properly installed" -ForegroundColor Yellow
    Write-Host "2. Run this script from Visual Studio Developer PowerShell" -ForegroundColor Yellow
    Write-Host "3. Check that all header files are present" -ForegroundColor Yellow
    Write-Host "4. Ensure Windows SDK is installed" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "✓ Compilation successful!" -ForegroundColor Green
Write-Host "✓ Binary created: BenignPacker.exe" -ForegroundColor Green
Write-Host ""

# Check if the executable was created
if (Test-Path "BenignPacker.exe") {
    $fileInfo = Get-Item "BenignPacker.exe"
    Write-Host "File size: $($fileInfo.Length) bytes" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "🎉 BenignPacker is ready to use!" -ForegroundColor Green
    Write-Host ""
    Write-Host "To run the application:" -ForegroundColor Yellow
    Write-Host "  .\BenignPacker.exe" -ForegroundColor White
    Write-Host ""
    Write-Host "Features available:" -ForegroundColor Yellow
    Write-Host "- 7 Advanced encryption methods" -ForegroundColor White
    Write-Host "- FUD (Fully Undetectable) features" -ForegroundColor White
    Write-Host "- Company profile masquerading" -ForegroundColor White
    Write-Host "- Certificate chain integration" -ForegroundColor White
    Write-Host "- Multi-architecture support" -ForegroundColor White
    Write-Host "- Exploit integration" -ForegroundColor White
    Write-Host "- Mass generation capabilities" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "ERROR: Executable was not created!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Press Enter to exit..."
Read-Host