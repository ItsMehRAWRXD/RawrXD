@echo off
:: Build script for Sovereign CLI
:: Phase 7C.2 Complete Integration

setlocal enabledelayedexpansion

echo ============================================
echo Building Sovereign CLI
echo ============================================

:: Setup MSVC environment using vcvars64
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

if not exist "%VCVARS%" (
    echo [ERROR] vcvars64.bat not found at %VCVARS%
    exit /b 1
)

call "%VCVARS%" >nul 2>&1

:: Directories
set "SRC_DIR=%~dp0src"
set "ASM_DIR=d:\src\asm"
set "BUILD_DIR=%~dp0build"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

:: Include paths
set "INCLUDES=/I"%SRC_DIR%" /I"%SRC_DIR%\cli" /I"%ASM_DIR%""

:: Compiler flags
set "CFLAGS=/std:c++17 /O2 /EHsc /W3 /nologo /D_CRT_SECURE_NO_WARNINGS"

echo.
echo Compiling SovereignCLI.cpp...

cl.exe %CFLAGS% %INCLUDES% /c "%SRC_DIR%\cli\SovereignCLI.cpp" /Fo"%BUILD_DIR%\SovereignCLI.obj" /Fd"%BUILD_DIR%\SovereignCLI.pdb"

if errorlevel 1 (
    echo [ERROR] Compilation failed
    exit /b 1
)

echo.
echo Compiling Sovereign_KernelDispatch.cpp...

cl.exe %CFLAGS% %INCLUDES% /c "%ASM_DIR%\Sovereign_KernelDispatch.cpp" /Fo"%BUILD_DIR%\Sovereign_KernelDispatch.obj" /Fd"%BUILD_DIR%\Sovereign_KernelDispatch.pdb"

if errorlevel 1 (
    echo [ERROR] KernelDispatch compilation failed
    exit /b 1
)

echo.
echo Compiling SovereignConfig.cpp...

cl.exe %CFLAGS% %INCLUDES% /c "%SRC_DIR%\cli\SovereignConfig.cpp" /Fo"%BUILD_DIR%\SovereignConfig.obj" /Fd"%BUILD_DIR%\SovereignConfig.pdb"

if errorlevel 1 (
    echo [ERROR] Config compilation failed
    exit /b 1
)

echo.
echo Compiling SovereignIntegrationTest.cpp...

cl.exe %CFLAGS% %INCLUDES% /c "%SRC_DIR%\cli\SovereignIntegrationTest.cpp" /Fo"%BUILD_DIR%\SovereignIntegrationTest.obj" /Fd"%BUILD_DIR%\SovereignIntegrationTest.pdb"

if errorlevel 1 (
    echo [ERROR] IntegrationTest compilation failed
    exit /b 1
)

echo.
echo Linking SovereignCLI.exe...

link.exe /OUT:"%BUILD_DIR%\SovereignCLI.exe" /DEBUG /PDB:"%BUILD_DIR%\SovereignCLI.pdb" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" "%BUILD_DIR%\SovereignCLI.obj" "%BUILD_DIR%\Sovereign_KernelDispatch.obj" "%BUILD_DIR%\SovereignConfig.obj"

if errorlevel 1 (
    echo [ERROR] Linking SovereignCLI failed
    exit /b 1
)

echo.
echo Linking SovereignIntegrationTest.exe...

link.exe /OUT:"%BUILD_DIR%\SovereignIntegrationTest.exe" /DEBUG /PDB:"%BUILD_DIR%\SovereignIntegrationTest.pdb" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" "%BUILD_DIR%\SovereignIntegrationTest.obj" "%BUILD_DIR%\Sovereign_KernelDispatch.obj"

if errorlevel 1 (
    echo [ERROR] Linking SovereignIntegrationTest failed
    exit /b 1
)

echo.
echo ============================================
echo Build successful!
echo ============================================
echo.
echo Executables:
echo   %BUILD_DIR%\SovereignCLI.exe
echo   %BUILD_DIR%\SovereignIntegrationTest.exe
echo.
echo Usage:
echo   %BUILD_DIR%\SovereignCLI.exe status
echo   %BUILD_DIR%\SovereignCLI.exe test
echo   %BUILD_DIR%\SovereignCLI.exe benchmark
echo   %BUILD_DIR%\SovereignCLI.exe memory
echo   %BUILD_DIR%\SovereignCLI.exe diagnostic
echo.
echo   %BUILD_DIR%\SovereignIntegrationTest.exe
echo ============================================

endlocal
