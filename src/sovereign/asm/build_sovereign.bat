@echo off
REM ==================================================================================
REM Sovereign Engine - MASM x64 Assembly Build Script
REM Target: R9700 AI Pro (32GB Uncached Bus Mapping)
REM Toolchain: MSVC 14.50.35717 + MASM x64
REM ==================================================================================

echo ======================================================================
echo [+] SOVEREIGN ENGINE - ZERO-BRANCH ASSEMBLY BUILD
echo ======================================================================

REM Set MASM path from environment
set MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe

REM Verify MASM exists
if not exist "%MASM_PATH%" (
    echo [FAIL] MASM x64 not found at %MASM_PATH%
    echo [NOTE] Ensure Visual Studio 2022 Enterprise is installed with C++ toolchain
    exit /b 1
)

echo [+] MASM Found: %MASM_PATH%

REM Find link.exe from VS installation
for /f "delims=" %%i in ('where link.exe 2^>nul') do set LINK_PATH=%%i
if not defined LINK_PATH (
    set LINK_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
)

if not exist "%LINK_PATH%" (
    echo [FAIL] link.exe not found at %LINK_PATH%
    echo [NOTE] Ensure Visual Studio 2022 Enterprise is installed with C++ toolchain
    exit /b 1
)

echo [+] Linker Found: %LINK_PATH%

REM Step 1: Assemble raw AVX2/AVX-512 vectors into native COFF object modules
echo [+] Step 1: Assembling SovereignConduit.asm...
"%MASM_PATH%" /c /Cx /FoSovereignConduit.obj SovereignConduit.asm
if %ERRORLEVEL% neq 0 (
    echo [FAIL] Assembly compilation failed
    exit /b %ERRORLEVEL%
)
echo [+] Assembly successful: SovereignConduit.obj

REM Step 2: Link object blocks into DLL using definition switch export
echo [+] Step 2: Linking SovereignEngineCore.dll...
"%LINK_PATH%" /DLL /NOENTRY /DEF:SovereignConduit.def SovereignConduit.obj /OUT:SovereignEngineCore.dll /MACHINE:X64
if %ERRORLEVEL% neq 0 (
    echo [FAIL] Linker failed
    exit /b %ERRORLEVEL%
)
echo [+] Link successful: SovereignEngineCore.dll

echo ======================================================================
echo [+] BUILD COMPLETE: Sovereign Engine Zero-Branch Pipeline
echo [+] Exports: RouteViaLinearConduitMASM, CycleWarhammerMoERing
echo [+] Output: SovereignEngineCore.dll
echo ======================================================================
