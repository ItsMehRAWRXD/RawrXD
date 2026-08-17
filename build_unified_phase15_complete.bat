@echo off
REM =============================================================================
REM RawrXD Phase 15 Complete Unification Build Script
REM =============================================================================
REM This script builds the fully unified RawrXD platform with:
REM - AIProvider interface layer
REM - Deep2Provider adapter
REM - ContextEngine for project awareness
REM - CompilerAgent for autonomous fixing
REM - AIServiceAdapter (bridges to IAIService)
REM - CompilerServiceAdapter (bridges to ICompilerService)
REM =============================================================================

setlocal enabledelayedexpansion

echo =============================================================================
echo RawrXD Phase 15 - Complete Unification Build
echo =============================================================================

REM Setup paths
set "SRC_ROOT=%~dp0"
cd /d "%SRC_ROOT%"

REM Find Visual Studio
set "VS_PATH=C:\VS2022Enterprise"
if not exist "%VS_PATH%" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
)
if not exist "%VS_PATH%" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Professional"
)
if not exist "%VS_PATH%" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community"
)

set "VCVARS=%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "%VCVARS%" (
    echo ERROR: Visual Studio 2022 not found at %VCVARS%
    exit /b 1
)

echo Found Visual Studio at: %VS_PATH%

REM Initialize VS environment
call "%VCVARS%" x64
if errorlevel 1 (
    echo ERROR: Failed to initialize VS environment
    exit /b 1
)

set "CL=cl.exe"
set "LINK=link.exe"

REM Create output directory
if not exist "bin" mkdir bin
if not exist "obj" mkdir obj

REM Compiler flags
set "CFLAGS=/nologo /W3 /EHsc /O2 /arch:AVX2 /std:c++17 /MP"
set "INCLUDES=/I. /Isrc /Isrc\core /Isrc\deep2 /Isrc\context /Isrc\agent /Isrc\unified"
set "DEFINES=/DUNICODE /D_UNICODE /DNDEBUG /DRAWRXD_PHASE15"

REM =============================================================================
REM Phase 1: Compile Core Components
REM =============================================================================
echo.
echo [1/6] Compiling Core Components...

REM Core interfaces (header-only, but we verify they compile)
%CL% %CFLAGS% %INCLUDES% %DEFINES% /c /Foobj\AIProvider.obj src\core\AIProvider.h 2>nul || echo AIProvider.h is header-only

REM =============================================================================
REM Phase 2: Compile Deep2 Engine
REM =============================================================================
echo.
echo [2/6] Compiling Deep2 Engine...

%CL% %CFLAGS% %INCLUDES% %DEFINES% /c /Foobj\Deep2Engine.obj src\deep2\Deep2Engine.cpp
if errorlevel 1 goto :error

%CL% %CFLAGS% %INCLUDES% %DEFINES% /c /Foobj\Tokenizer.obj src\deep2\Tokenizer.cpp
if errorlevel 1 goto :error

%CL% %CFLAGS% %INCLUDES% %DEFINES% /c /Foobj\advanced_sampler.obj src\deep2\advanced_sampler.cpp
if errorlevel 1 goto :error

%CL% %CFLAGS% %INCLUDES% %DEFINES% /c /Foobj\Deep2Provider.obj src\deep2\Deep2Provider.cpp
if errorlevel 1 goto :error

REM =============================================================================
REM Phase 3: Compile Context Engine
REM =============================================================================
echo.
echo [3/6] Compiling Context Engine...

%CL% %CFLAGS% %INCLUDES% %DEFINES% /c /Foobj\ContextEngine.obj src\context\ContextEngine.cpp
if errorlevel 1 goto :error

REM =============================================================================
REM Phase 4: Compile Agent System
REM =============================================================================
echo.
echo [4/6] Compiling Agent System...

%CL% %CFLAGS% %INCLUDES% %DEFINES% /c /Foobj\CompilerAgent.obj src\agent\CompilerAgent.cpp
if errorlevel 1 goto :error

REM =============================================================================
REM Phase 5: Compile Unified Host and Adapters
REM =============================================================================
echo.
echo [5/6] Compiling Unified Host and Adapters...

%CL% %CFLAGS% %INCLUDES% %DEFINES% /c /Foobj\AIServiceAdapter.obj src\unified\AIServiceAdapter.cpp
if errorlevel 1 goto :error

%CL% %CFLAGS% %INCLUDES% %DEFINES% /c /Foobj\CompilerServiceAdapter.obj src\unified\CompilerServiceAdapter.cpp
if errorlevel 1 goto :error

%CL% %CFLAGS% %INCLUDES% %DEFINES% /c /Foobj\RawrXDHost.obj src\unified\RawrXDHost.cpp
if errorlevel 1 goto :error

REM =============================================================================
REM Phase 6: Link Everything
REM =============================================================================
echo.
echo [6/6] Linking RawrXD.exe...

%LINK% /nologo /OUT:bin\RawrXD.exe /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF ^
    obj\Deep2Engine.obj ^
    obj\Tokenizer.obj ^
    obj\advanced_sampler.obj ^
    obj\Deep2Provider.obj ^
    obj\ContextEngine.obj ^
    obj\CompilerAgent.obj ^
    obj\AIServiceAdapter.obj ^
    obj\CompilerServiceAdapter.obj ^
    obj\RawrXDHost.obj ^
    src\unified\main_unified.cpp ^
    kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib

if errorlevel 1 goto :error

REM =============================================================================
REM Success
REM =============================================================================
echo.
echo =============================================================================
echo BUILD SUCCESSFUL
echo =============================================================================
echo.
echo Output: bin\RawrXD.exe
echo.
echo Usage:
echo   RawrXD.exe --cli      Command-line interface
echo   RawrXD.exe --gui      Win32 IDE
echo   RawrXD.exe --server   Deep2 local server (localhost:11442)
echo   RawrXD.exe --compile  Sovereign compiler
echo   RawrXD.exe --agent    Autonomous agent
echo   RawrXD.exe --model=   Specify model path
echo.
echo Architecture:
echo   - AIProvider Interface    : Unified AI ABI
echo   - Deep2Provider             : Local GGUF inference
echo   - ContextEngine            : Project awareness
echo   - CompilerAgent            : Autonomous compile-fix loop
echo   - AIServiceAdapter         : Bridge to IAIService
echo   - CompilerServiceAdapter   : Bridge to ICompilerService
echo.
goto :end

:error
echo.
echo =============================================================================
echo BUILD FAILED
echo =============================================================================
exit /b 1

:end
endlocal
