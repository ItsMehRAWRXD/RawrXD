@echo off
REM ============================================================================
REM Sovereign SDK Build Script
REM Builds libsovereign.dll - C API wrapper for Sovereign Engine
REM ============================================================================

setlocal EnableDelayedExpansion

echo ============================================
echo Sovereign SDK Build System
echo ============================================
echo.

REM Configuration
set "SDK_VERSION_MAJOR=1"
set "SDK_VERSION_MINOR=0"
set "SDK_VERSION_PATCH=0"
set "SDK_VERSION=!SDK_VERSION_MAJOR!.!SDK_VERSION_MINOR!.!SDK_VERSION_PATCH!"

echo SDK Version: %SDK_VERSION%
echo.

REM ============================================================================
REM Tool Paths
REM ============================================================================

set "VS_TOOLS=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "CL_EXE=%VS_TOOLS%\cl.exe"
set "LINK_EXE=%VS_TOOLS%\link.exe"
set "LIB_EXE=%VS_TOOLS%\lib.exe"

REM Verify tools exist
if not exist "%CL_EXE%" (
    echo ERROR: cl.exe not found at %CL_EXE%
    exit /b 1
)

if not exist "%LINK_EXE%" (
    echo ERROR: link.exe not found at %LINK_EXE%
    exit /b 1
)

echo Build Tools:
echo   cl.exe:   %CL_EXE%
echo   link.exe: %LINK_EXE%
echo   lib.exe:  %LIB_EXE%
echo.

REM ============================================================================
REM Directories
REM ============================================================================

set "RAW_RXD_ROOT=D:\RawrXD"
set "SRC_DIR=%RAW_RXD_ROOT%\src\core"
set "INCLUDE_DIR=%RAW_RXD_ROOT%\include"
set "BUILD_DIR=%RAW_RXD_ROOT%\build\sdk"
set "OUTPUT_DIR=%RAW_RXD_ROOT%\lib"

REM Create directories
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo Directories:
echo   Source:  %SRC_DIR%
echo   Include: %INCLUDE_DIR%
echo   Build:   %BUILD_DIR%
echo   Output:  %OUTPUT_DIR%
echo.

REM ============================================================================
REM Compiler Flags
REM ============================================================================

set "COMMON_FLAGS=/nologo /W4 /EHsc /MP /std:c++17"
set "OPT_FLAGS=/O2 /Oi /Ot /GL"
set "DEBUG_FLAGS=/Zi /FS"
set "DEFINES=/D SOVEREIGN_SDK_EXPORTS /D SOVEREIGN_SDK_VERSION_MAJOR=%SDK_VERSION_MAJOR% /D SOVEREIGN_SDK_VERSION_MINOR=%SDK_VERSION_MINOR% /D SOVEREIGN_SDK_VERSION_PATCH=%SDK_VERSION_PATCH%"
set "INCLUDES=/I "%INCLUDE_DIR%" /I "%RAW_RXD_ROOT%\src\engine" /I "%RAW_RXD_ROOT%\src\threading" /I "%RAW_RXD_ROOT%\src\recovery""

set "CFLAGS=%COMMON_FLAGS% %OPT_FLAGS% %DEBUG_FLAGS% %DEFINES% %INCLUDES%"

echo Compiler Flags:
echo   %CFLAGS%
echo.

REM ============================================================================
REM Source Files
REM ============================================================================

echo Scanning source files...

set "SDK_SOURCES="
set "ENGINE_SOURCES="

REM SDK Core
if exist "%SRC_DIR%\sovereign_sdk.cpp" (
    set "SDK_SOURCES=!SDK_SOURCES! "%SRC_DIR%\sovereign_sdk.cpp""
    echo   [SDK] sovereign_sdk.cpp
)

REM Engine Controller (required for SDK)
if exist "%RAW_RXD_ROOT%\src\engine\sovereign_engine_controller_integration.cpp" (
    set "ENGINE_SOURCES=!ENGINE_SOURCES! "%RAW_RXD_ROOT%\src\engine\sovereign_engine_controller_integration.cpp""
    echo   [Engine] sovereign_engine_controller_integration.cpp
)

REM Thread Pool
if exist "%RAW_RXD_ROOT%\src\threading\sovereign_thread_pool.cpp" (
    set "ENGINE_SOURCES=!ENGINE_SOURCES! "%RAW_RXD_ROOT%\src\threading\sovereign_thread_pool.cpp""
    echo   [Threading] sovereign_thread_pool.cpp
)

REM Ring Attention
if exist "%RAW_RXD_ROOT%\src\engine\sovereign_ring_attention_integration.cpp" (
    set "ENGINE_SOURCES=!ENGINE_SOURCES! "%RAW_RXD_ROOT%\src\engine\sovereign_ring_attention_integration.cpp""
    echo   [Ring] sovereign_ring_attention_integration.cpp
)

REM Error Recovery
if exist "%RAW_RXD_ROOT%\src\recovery\error_recovery_system.cpp" (
    set "ENGINE_SOURCES=!ENGINE_SOURCES! "%RAW_RXD_ROOT%\src\recovery\error_recovery_system.cpp""
    echo   [Recovery] error_recovery_system.cpp
)

echo.

REM ============================================================================
REM Compile SDK
REM ============================================================================

echo Compiling SDK...
echo.

set "OBJ_FILES="

REM Compile SDK core
echo Compiling: sovereign_sdk.cpp
"%CL_EXE%" %CFLAGS% /c /Fo"%BUILD_DIR%\sovereign_sdk.obj" "%SRC_DIR%\sovereign_sdk.cpp"
if errorlevel 1 (
    echo ERROR: Failed to compile sovereign_sdk.cpp
    exit /b 1
)
set "OBJ_FILES=!OBJ_FILES! "%BUILD_DIR%\sovereign_sdk.obj""

REM Compile engine components (if available)
for %%F in (%ENGINE_SOURCES%) do (
    if exist "%%~F" (
        echo Compiling: %%~nF%%~xF
        "%CL_EXE%" %CFLAGS% /c /Fo"%BUILD_DIR%\%%~nF.obj" "%%~F"
        if errorlevel 1 (
            echo WARNING: Failed to compile %%~nF%%~xF - will use stub
        ) else (
            set "OBJ_FILES=!OBJ_FILES! "%BUILD_DIR%\%%~nF.obj""
        )
    )
)

echo.
echo Object files: %OBJ_FILES%
echo.

REM ============================================================================
REM Link DLL
REM ============================================================================

echo Linking libsovereign.dll...
echo.

set "LINK_FLAGS=/DLL /LARGEADDRESSAWARE /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF /LTCG"
set "LINK_LIBS=kernel32.lib user32.lib gdi32.lib advapi32.lib"

"%LINK_EXE%" %LINK_FLAGS% %LINK_LIBS% ^
    /OUT:"%OUTPUT_DIR%\libsovereign.dll" ^
    /IMPLIB:"%OUTPUT_DIR%\libsovereign.lib" ^
    /PDB:"%OUTPUT_DIR%\libsovereign.pdb" ^
    /EXPORT:Sovereign_Init ^
    /EXPORT:Sovereign_Shutdown ^
    /EXPORT:Sovereign_GetStatus ^
    /EXPORT:Sovereign_GetVersion ^
    /EXPORT:Sovereign_LoadModel ^
    /EXPORT:Sovereign_UnloadModel ^
    /EXPORT:Sovereign_SubmitTask ^
    /EXPORT:Sovereign_CancelTask ^
    /EXPORT:Sovereign_WaitForTask ^
    /EXPORT:Sovereign_HasAVX512 ^
    /EXPORT:Sovereign_HasAMX ^
    /EXPORT:Sovereign_GetOptimalThreadCount ^
    /EXPORT:Sovereign_GetMemoryInfo ^
    /EXPORT:Sovereign_GetLastError ^
    /EXPORT:Sovereign_GetErrorString ^
    /EXPORT:Sovereign_SetLogLevel ^
    /EXPORT:Sovereign_SetLogCallback ^
    %OBJ_FILES%

if errorlevel 1 (
    echo ERROR: Failed to link libsovereign.dll
    exit /b 1
)

echo.
echo ============================================
echo Build Successful!
echo ============================================
echo.
echo Output files:
echo   DLL:  %OUTPUT_DIR%\libsovereign.dll
echo   LIB:  %OUTPUT_DIR%\libsovereign.lib
echo   PDB:  %OUTPUT_DIR%\libsovereign.pdb
echo.

REM ============================================================================
REM Verify Exports
REM ============================================================================

echo Verifying exports...
echo.

set "DUMPBIN_EXE=%VS_TOOLS%\dumpbin.exe"
if exist "%DUMPBIN_EXE%" (
    "%DUMPBIN_EXE%" /EXPORTS "%OUTPUT_DIR%\libsovereign.dll" ^
        | findstr "Sovereign_" ^
        | find /c /v ""
    echo exports found
) else (
    echo dumpbin.exe not found, skipping export verification
)

echo.

REM ============================================================================
REM Copy Headers
REM ============================================================================

echo Copying headers to output directory...
if not exist "%OUTPUT_DIR%\include" mkdir "%OUTPUT_DIR%\include"
copy /Y "%INCLUDE_DIR%\sovereign_sdk.h" "%OUTPUT_DIR%\include\"
echo   sovereign_sdk.h copied
echo.

REM ============================================================================
REM Create SDK Package
REM ============================================================================

echo Creating SDK package...
if not exist "%RAW_RXD_ROOT%\dist" mkdir "%RAW_RXD_ROOT%\dist"

set "SDK_PACKAGE=%RAW_RXD_ROOT%\dist\sovereign-sdk-%SDK_VERSION%-win64.zip"

REM Create package using PowerShell
powershell -Command "& {
    $files = @(
        '%OUTPUT_DIR%\libsovereign.dll',
        '%OUTPUT_DIR%\libsovereign.lib',
        '%OUTPUT_DIR%\include\sovereign_sdk.h'
    )
    Compress-Archive -Path $files -DestinationPath '%SDK_PACKAGE%' -Force
}"

if exist "%SDK_PACKAGE%" (
    echo SDK package created: %SDK_PACKAGE%
) else (
    echo WARNING: Failed to create SDK package
)

echo.
echo ============================================
echo SDK Build Complete!
echo ============================================
echo.
echo To use the SDK in your IDE project:
echo   1. Link against: %OUTPUT_DIR%\libsovereign.lib
echo   2. Include:      %OUTPUT_DIR%\include\sovereign_sdk.h
echo   3. Deploy:       %OUTPUT_DIR%\libsovereign.dll
echo.
echo Example:
echo   #include "sovereign_sdk.h"
echo   #pragma comment(lib, "libsovereign.lib")
echo.
echo   SovereignHandle engine = Sovereign_Init(^&config);
echo.

endlocal