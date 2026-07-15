@echo off
REM Build script for AgenticUnified.exe with Tool Registry

echo Setting up Visual Studio environment...
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (
    echo Failed to set up VS environment
    exit /b 1
)

cd /d d:\rawrxd\src\core

echo.
echo ============================================
echo Building AgenticUnified with Tool Registry
echo ============================================
echo.

echo Step 1: Compiling KV Cache...
ml64.exe /c /Zi /Fo"kv_cache_standalone.obj" ..\kv_cache_standalone.asm
if errorlevel 1 (
    echo ERROR: KV Cache compilation failed
    exit /b 1
)
echo SUCCESS: kv_cache_standalone.obj created
echo.

echo Step 2: Compiling Aperture Kernel...
ml64.exe /c /Zi /Fo"aperture_q4_0_avx512_v2.obj" aperture_q4_0_avx512_v2.asm
if errorlevel 1 (
    echo ERROR: Aperture compilation failed
    exit /b 1
)
echo SUCCESS: aperture_q4_0_avx512_v2.obj created
echo.

echo Step 3: Compiling Agentic Memory Layer (Simple)...
ml64.exe /c /Zi /Fo"agentic_memory_simple.obj" agentic_memory_simple.asm
if errorlevel 1 (
    echo ERROR: Memory Layer compilation failed
    exit /b 1
)
echo SUCCESS: agentic_memory_simple.obj created
echo.

echo Step 4: Compiling Tool Registry...
ml64.exe /c /Zi /Fo"tool_registry.obj" tool_registry.asm
if errorlevel 1 (
    echo ERROR: Tool Registry compilation failed
    exit /b 1
)
echo SUCCESS: tool_registry.obj created
echo.

echo Step 5: Compiling Orchestrator...
ml64.exe /c /Zi /Fo"agentic_orchestrator.obj" agentic_orchestrator.asm
if errorlevel 1 (
    echo ERROR: Orchestrator compilation failed
    exit /b 1
)
echo SUCCESS: agentic_orchestrator.obj created
echo.

echo Step 6: Linking unified executable...
link.exe /DEBUG /LARGEADDRESSAWARE:NO /OUT:AgenticUnified.exe agentic_orchestrator.obj tool_registry.obj agentic_memory_simple.obj kv_cache_standalone.obj aperture_q4_0_avx512_v2.obj "C:\Program Files\Microsoft Visual Studio\18\Enterprise\SDK\ScopeCppSDK\vc15\SDK\lib\kernel32.lib" /SUBSYSTEM:CONSOLE /ENTRY:AgenticUnifiedMain
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

echo.
pause
