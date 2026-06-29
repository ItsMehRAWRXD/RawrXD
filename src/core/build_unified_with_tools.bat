@echo off
REM Build script for AgenticUnified.exe with Tool Registry
REM This compiles and links the orchestrator with Tool Registry support

echo ============================================
echo Building AgenticUnified with Tool Registry
echo ============================================
echo.

set ML64="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set LINK="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

if not exist %ML64% (
    echo ERROR: ml64.exe not found at expected path
    exit /b 1
)

echo Step 1: Compiling Tool Registry...
%ML64% /c /Zi /Fo"tool_registry.obj" tool_registry.asm
if errorlevel 1 (
    echo ERROR: Tool Registry compilation failed
    exit /b 1
)
echo SUCCESS: tool_registry.obj created
echo.

echo Step 2: Compiling Orchestrator...
%ML64% /c /Zi /Fo"agentic_orchestrator.obj" agentic_orchestrator.asm
if errorlevel 1 (
    echo ERROR: Orchestrator compilation failed
    exit /b 1
)
echo SUCCESS: agentic_orchestrator.obj created
echo.

echo Step 3: Linking unified executable...
%LINK% /DEBUG /OUT:AgenticUnified.exe ^
    agentic_orchestrator.obj ^
    tool_registry.obj ^
    kernel32.lib ^
    /SUBSYSTEM:CONSOLE ^
    /ENTRY:AgenticUnifiedMain
if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)
echo SUCCESS: AgenticUnified.exe created
echo.

echo ============================================
echo Build Complete!
echo ============================================
echo.
echo Running AgenticUnified.exe...
echo.
AgenticUnified.exe

pause
