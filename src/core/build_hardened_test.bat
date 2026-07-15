@echo off
REM Build and test hardened Tool Registry

echo Setting up Visual Studio environment...
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (
    echo Failed to set up VS environment
    exit /b 1
)

cd /d d:\rawrxd\src\core

echo.
echo ============================================
echo Building Hardened Tool Registry Tests
echo ============================================
echo.

echo Compiling...
ml64.exe /c /Zi /Fo"tool_registry_hardened.obj" tool_registry_hardened.asm
if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)
echo SUCCESS: Compiled
echo.

echo Linking...
link.exe /DEBUG /OUT:ToolRegistryTest.exe tool_registry_hardened.obj "C:\Program Files\Microsoft Visual Studio\18\Enterprise\SDK\ScopeCppSDK\vc15\SDK\lib\kernel32.lib" /SUBSYSTEM:CONSOLE /ENTRY:main
if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)
echo SUCCESS: Linked
echo.

echo ============================================
echo Running Tests
echo ============================================
echo.
ToolRegistryTest.exe

echo.
pause
