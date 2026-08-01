@echo off
setlocal

echo ========================================
echo Testing Ship Directory Compilation
echo ========================================

REM Find VS installation
set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise"
if not exist "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
)

if not exist "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat" (
    echo ERROR: Could not find Visual Studio
    exit /b 1
)

echo Found VS at: %VS_PATH%

REM Setup environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat"

if errorlevel 1 (
    echo ERROR: Failed to setup environment
    exit /b 1
)

cd /d d:\rawrxd\Ship

set "INCLUDE_FLAGS=/I. /I..\include /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared""

echo.
echo Testing AgentOrchestrator.hpp syntax...
cl /c /std:c++20 /EHsc %INCLUDE_FLAGS% /Fo:AgentOrchestrator.obj AgentOrchestrator.hpp 2>&1
if errorlevel 1 (
    echo FAILED: AgentOrchestrator.hpp
    exit /b 1
) else (
    echo OK: AgentOrchestrator.hpp
)

echo.
echo Testing LLMClient.hpp syntax...
cl /c /std:c++20 /EHsc %INCLUDE_FLAGS% /Fo:LLMClient.obj LLMClient.hpp 2>&1
if errorlevel 1 (
    echo FAILED: LLMClient.hpp
    exit /b 1
) else (
    echo OK: LLMClient.hpp
)

echo.
echo Testing ToolExecutionEngine.hpp syntax...
cl /c /std:c++20 /EHsc %INCLUDE_FLAGS% /Fo:ToolExecutionEngine.obj ToolExecutionEngine.hpp 2>&1
if errorlevel 1 (
    echo FAILED: ToolExecutionEngine.hpp
    exit /b 1
) else (
    echo OK: ToolExecutionEngine.hpp
)

echo.
echo Testing ToolImplementations.hpp syntax...
cl /c /std:c++20 /EHsc %INCLUDE_FLAGS% /Fo:ToolImplementations.obj ToolImplementations.hpp 2>&1
if errorlevel 1 (
    echo FAILED: ToolImplementations.hpp
    exit /b 1
) else (
    echo OK: ToolImplementations.hpp
)

echo.
echo ========================================
echo All syntax checks passed!
echo ========================================

endlocal
