# RawrXD Distribution Package Creator
# Creates a complete distribution package with all components

param(
    [string]$Version = "14.7.3",
    [string]$OutputDir = ".\dist",
    [switch]$IncludeSource = $false
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD Distribution Package Creator" -ForegroundColor Cyan
Write-Host "Version: $Version" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Create output directory
$DistDir = "$OutputDir\RawrXD-$Version"
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
New-Item -ItemType Directory -Force -Path "$DistDir\bin" | Out-Null
New-Item -ItemType Directory -Force -Path "$DistDir\docs" | Out-Null
New-Item -ItemType Directory -Force -Path "$DistDir\samples" | Out-Null
New-Item -ItemType Directory -Force -Path "$DistDir\redist" | Out-Null

Write-Host "Copying files..." -ForegroundColor Yellow

# Copy executables
$Binaries = @(
    "..\bin\RawrXD_GUI_Minimal.exe",
    "..\build\bin\RawrXD-InferenceRoutingTest.exe"
)

foreach ($binary in $Binaries) {
    if (Test-Path $binary) {
        Copy-Item $binary "$DistDir\bin\" -Force
        Write-Host "  [OK] $(Split-Path $binary -Leaf)" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $(Split-Path $binary -Leaf)" -ForegroundColor Red
    }
}

# Rename main executable
if (Test-Path "$DistDir\bin\RawrXD_GUI_Minimal.exe") {
    Rename-Item "$DistDir\bin\RawrXD_GUI_Minimal.exe" "RawrXD.exe" -Force
}

# Copy documentation
$Docs = @(
    "..\README_GUI.md",
    "..\FINAL_STATUS.md",
    "..\GUI_COMPLETE_SESSION_SUMMARY.md",
    "..\AUDIT_COMPLETE.md"
)

foreach ($doc in $Docs) {
    if (Test-Path $doc) {
        $dest = "$DistDir\docs\$(Split-Path $doc -Leaf)"
        Copy-Item $doc $dest -Force
        # Convert to .txt for easy viewing
        $content = Get-Content $dest -Raw
        $content | Set-Content "$DistDir\docs\$( [System.IO.Path]::GetFileNameWithoutExtension($doc) ).txt"
        Remove-Item $dest
        Write-Host "  [OK] $(Split-Path $doc -Leaf)" -ForegroundColor Green
    }
}

# Create sample files
Write-Host "`nCreating sample files..." -ForegroundColor Yellow

@"
# Welcome to RawrXD

RawrXD is a fully local AI IDE with GGUF model support.

## Quick Start

1. Launch RawrXD.exe
2. Load a GGUF model via Model → Load Model
3. Start chatting in the Chat Panel
4. Edit files in the Editor Panel

## Features

- 100% local inference (no cloud required)
- GGUF model support
- Syntax highlighting
- File explorer
- Dark theme

## Support

See the docs folder for complete documentation.
"@ | Set-Content "$DistDir\README.txt"

@"
{
  "version": "$Version",
  "theme": "dark",
  "font_size": 14,
  "auto_save": true,
  "streaming": true,
  "max_tokens": 2048,
  "model_path": "",
  "recent_files": [],
  "window_state": {
    "width": 1400,
    "height": 900,
    "maximized": false
  }
}
"@ | Set-Content "$DistDir\config.json"

# Create sample C++ file
@"
// Sample C++ file for testing
#include <iostream>
#include <string>

class HelloWorld {
public:
    void greet(const std::string& name) {
        std::cout << "Hello, " << name << "!" << std::endl;
    }
};

int main() {
    HelloWorld hw;
    hw.greet("RawrXD");
    return 0;
}
"@ | Set-Content "$DistDir\samples\hello.cpp"

# Create install script
@"
@echo off
echo ============================================
echo RawrXD v$Version Installer
echo ============================================
echo.

set "INSTALL_DIR=%LOCALAPPDATA%\RawrXD"
set "START_MENU=%APPDATA%\Microsoft\Windows\Start Menu\Programs\RawrXD"

echo Installing to: %INSTALL_DIR%
echo.

if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%START_MENU%" mkdir "%START_MENU%"

xcopy /E /I /Y "%~dp0bin" "%INSTALL_DIR%\bin"
xcopy /E /I /Y "%~dp0docs" "%INSTALL_DIR%\docs"
xcopy /E /I /Y "%~dp0samples" "%INSTALL_DIR%\samples"
copy /Y "%~dp0config.json" "%INSTALL_DIR%\config.json"
copy /Y "%~dp0README.txt" "%INSTALL_DIR%\README.txt"

echo Creating shortcuts...
powershell -Command "`$WshShell = New-Object -comObject WScript.Shell; `$Shortcut = `$WshShell.CreateShortcut('%START_MENU%\RawrXD.lnk'); `$Shortcut.TargetPath = '%INSTALL_DIR%\bin\RawrXD.exe'; `$Shortcut.WorkingDirectory = '%INSTALL_DIR%\bin'; `$Shortcut.IconLocation = '%INSTALL_DIR%\bin\RawrXD.exe,0'; `$Shortcut.Save()"
powershell -Command "`$WshShell = New-Object -comObject WScript.Shell; `$Shortcut = `$WshShell.CreateShortcut('%USERPROFILE%\Desktop\RawrXD.lnk'); `$Shortcut.TargetPath = '%INSTALL_DIR%\bin\RawrXD.exe'; `$Shortcut.WorkingDirectory = '%INSTALL_DIR%\bin'; `$Shortcut.IconLocation = '%INSTALL_DIR%\bin\RawrXD.exe,0'; `$Shortcut.Save()"

echo.
echo Installation complete!
echo RawrXD v$Version has been installed to: %INSTALL_DIR%
echo.
pause
"@ | Set-Content "$DistDir\INSTALL.bat"

# Create uninstall script
@"
@echo off
echo ============================================
echo RawrXD v$Version Uninstaller
echo ============================================
echo.

set "INSTALL_DIR=%LOCALAPPDATA%\RawrXD"
set "START_MENU=%APPDATA%\Microsoft\Windows\Start Menu\Programs\RawrXD"

echo Removing RawrXD...

if exist "%INSTALL_DIR%" rmdir /S /Q "%INSTALL_DIR%"
if exist "%START_MENU%" rmdir /S /Q "%START_MENU%"
if exist "%USERPROFILE%\Desktop\RawrXD.lnk" del /Q "%USERPROFILE%\Desktop\RawrXD.lnk"

echo.
echo Uninstallation complete!
echo.
pause
"@ | Set-Content "$DistDir\UNINSTALL.bat"

# Create launcher script
@"
@echo off
set "RAWRXD_HOME=%~dp0"
set "PATH=%RAWRXD_HOME%bin;%PATH%"
cd /d "%RAWRXD_HOME%bin"
start RawrXD.exe
"@ | Set-Content "$DistDir\Launch.bat"

# Include source if requested
if ($IncludeSource) {
    Write-Host "`nIncluding source code..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path "$DistDir\source" | Out-Null
    
    $SourceFiles = @(
        "..\src\win32app\RawrXD_GUI_Minimal.cpp",
        "..\src\win32app\RawrXD_GUI_Integrated.cpp",
        "..\src\win32app\RawrXD_GUI_Enhanced.cpp",
        "..\src\tests\inference_routing_test.cpp",
        "..\tests\test_gui_components.cpp",
        "..\src\debugger\RawrXD_Debugger.cpp",
        "..\src\lsp\RawrXD_LSP_Client.cpp"
    )
    
    foreach ($file in $SourceFiles) {
        if (Test-Path $file) {
            Copy-Item $file "$DistDir\source\" -Force
            Write-Host "  [OK] $(Split-Path $file -Leaf)" -ForegroundColor Green
        }
    }
    
    # Copy build scripts
    Copy-Item "..\build_minimal_gui.bat" "$DistDir\source\" -Force
}

# Create ZIP archive
Write-Host "`nCreating distribution archive..." -ForegroundColor Yellow
$ZipFile = "$OutputDir\RawrXD-$Version-Windows-x64.zip"

if (Test-Path $ZipFile) {
    Remove-Item $ZipFile -Force
}

Compress-Archive -Path $DistDir -DestinationPath $ZipFile -Force

# Calculate checksums
Write-Host "`nCalculating checksums..." -ForegroundColor Yellow
$Hash = Get-FileHash $ZipFile -Algorithm SHA256
$Hash.Hash | Set-Content "$OutputDir\RawrXD-$Version-Windows-x64.sha256"

# Create release notes
@"
# RawrXD v$Version Release Notes

## What's New

- Complete GUI implementation with local GGUF inference
- Chat panel with streaming responses
- File editor with syntax highlighting
- Model management panel
- File tree explorer
- Settings persistence
- Debugger integration
- LSP (Language Server Protocol) support
- CI/CD pipeline

## Installation

1. Extract RawrXD-$Version-Windows-x64.zip
2. Run INSTALL.bat as Administrator
3. Launch RawrXD from Start Menu or Desktop

## System Requirements

- Windows 10/11 (64-bit)
- Visual C++ Redistributable 2022
- Windows SDK 10.0.22621.0 (for building from source)

## Files Included

- RawrXD.exe - Main GUI application
- RawrXD-InferenceRoutingTest.exe - Test suite
- Documentation (README, STATUS, AUDIT)
- Sample files
- Install/Uninstall scripts

## Known Issues

None reported.

## Support

See docs folder for complete documentation.
"@ | Set-Content "$OutputDir\RELEASE_NOTES.md"

# Summary
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Distribution Package Created!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Location: $ZipFile" -ForegroundColor Cyan
Write-Host "Size: $([math]::Round((Get-Item $ZipFile).Length / 1MB, 2)) MB" -ForegroundColor Cyan
Write-Host "SHA256: $($Hash.Hash)" -ForegroundColor Cyan
Write-Host ""
Write-Host "Contents:" -ForegroundColor Yellow
Get-ChildItem $DistDir -Recurse | Where-Object { -not $_.PSIsContainer } | 
    Select-Object @{N="Name";E={$_.FullName.Replace($DistDir, "")}}, @{N="Size";E={"{0:N0} KB" -f ($_.Length / 1KB)}} |
    Format-Table -AutoSize

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. Test the distribution package" -ForegroundColor White
Write-Host "  2. Upload to GitHub releases" -ForegroundColor White
Write-Host "  3. Update website with download link" -ForegroundColor White
