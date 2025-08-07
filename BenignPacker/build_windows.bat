@echo off
echo ========================================
echo    BenignPacker Windows Build Script
echo ========================================
echo.

REM Check if Visual Studio is available
where cl >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Visual Studio compiler (cl.exe) not found!
    echo.
    echo Please install Visual Studio 2019/2022 with C++ development tools.
    echo Download from: https://visualstudio.microsoft.com/downloads/
    echo.
    echo Make sure to include:
    echo - C++ development tools
    echo - Windows 10/11 SDK
    echo.
    pause
    exit /b 1
)

echo ✓ Visual Studio compiler found
echo.

REM Check if required files exist
if not exist "VS2022_GUI_Benign_Packer.cpp" (
    echo ERROR: VS2022_GUI_Benign_Packer.cpp not found!
    echo Please make sure you're in the correct directory.
    pause
    exit /b 1
)

if not exist "ultimate_encryption_integration.h" (
    echo ERROR: ultimate_encryption_integration.h not found!
    echo Please make sure all source files are present.
    pause
    exit /b 1
)

echo ✓ All required source files found
echo.

REM Set compiler flags
set CXXFLAGS=/std:c++17 /O2 /EHsc /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x0601
set LIBS=ole32.lib crypt32.lib wininet.lib wintrust.lib imagehlp.lib comctl32.lib shell32.lib advapi32.lib gdi32.lib user32.lib kernel32.lib

echo Building BenignPacker with advanced encryption features...
echo.

REM Compile the main application
cl %CXXFLAGS% /Fe:BenignPacker.exe VS2022_GUI_Benign_Packer.cpp %LIBS%

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Compilation failed!
    echo.
    echo Common solutions:
    echo 1. Make sure Visual Studio is properly installed
    echo 2. Run this script from Visual Studio Developer Command Prompt
    echo 3. Check that all header files are present
    echo 4. Ensure Windows SDK is installed
    echo.
    pause
    exit /b 1
)

echo.
echo ✓ Compilation successful!
echo ✓ Binary created: BenignPacker.exe
echo.

REM Check if the executable was created
if exist "BenignPacker.exe" (
    echo File size: 
    dir BenignPacker.exe | find "BenignPacker.exe"
    echo.
    echo 🎉 BenignPacker is ready to use!
    echo.
    echo To run the application:
    echo   BenignPacker.exe
    echo.
    echo Features available:
    echo - 7 Advanced encryption methods
    echo - FUD (Fully Undetectable) features
    echo - Company profile masquerading
    echo - Certificate chain integration
    echo - Multi-architecture support
    echo - Exploit integration
    echo - Mass generation capabilities
    echo.
) else (
    echo ERROR: Executable was not created!
    pause
    exit /b 1
)

echo Press any key to exit...
pause >nul