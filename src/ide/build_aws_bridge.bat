@echo off
REM ============================================================================
REM Build script for RawrXD IDE AWS Bedrock Native Client
REM Compiles: AwsSigV4Signer, AwsBedrockClient, SovereignAwsBridge
REM Links into: GhostTextIntegration_Wiring (part of RawrXD-Win32IDE)
REM ============================================================================

setlocal enabledelayedexpansion

set "SRC_DIR=%~dp0..\src\ide"
set "BUILD_DIR=%~dp0..\..\build-ninja"
set "OBJ_DIR=%BUILD_DIR%\obj"

echo ============================================================================
echo  Building RawrXD IDE AWS Bedrock Native Client
echo ============================================================================
echo Source: %SRC_DIR%
echo Output: %OBJ_DIR%
echo.

REM Check for Visual Studio environment
if not defined VSINSTALLDIR (
    echo ERROR: Visual Studio environment not set.
    echo Please run from a Visual Studio Developer Command Prompt.
    exit /b 1
)

REM Create output directories
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"

REM Compile AwsSigV4Signer
echo [1/3] Compiling AwsSigV4Signer.cpp...
cl.exe /nologo /W4 /EHsc /O2 /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS ^
    /c /Fo"%OBJ_DIR%\AwsSigV4Signer.obj" ^
    "%SRC_DIR%\AwsSigV4Signer.cpp" ^
    advapi32.lib

if errorlevel 1 (
    echo ERROR: AwsSigV4Signer compilation failed
    exit /b 1
)
echo   OK

REM Compile AwsBedrockClient
echo [2/3] Compiling AwsBedrockClient.cpp...
cl.exe /nologo /W4 /EHsc /O2 /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS ^
    /c /Fo"%OBJ_DIR%\AwsBedrockClient.obj" ^
    "%SRC_DIR%\AwsBedrockClient.cpp" ^
    ws2_32.lib secur32.lib advapi32.lib

if errorlevel 1 (
    echo ERROR: AwsBedrockClient compilation failed
    exit /b 1
)
echo   OK

REM Compile SovereignAwsBridge
echo [3/3] Compiling SovereignAwsBridge.cpp...
cl.exe /nologo /W4 /EHsc /O2 /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS ^
    /c /Fo"%OBJ_DIR%\SovereignAwsBridge.obj" ^
    "%SRC_DIR%\SovereignAwsBridge.cpp" ^
    ws2_32.lib secur32.lib advapi32.lib

if errorlevel 1 (
    echo ERROR: SovereignAwsBridge compilation failed
    exit /b 1
)
echo   OK

REM Create static library
echo.
echo Creating library: %BUILD_DIR%\SovereignAwsBridge.lib
lib.exe /nologo /OUT:"%BUILD_DIR%\SovereignAwsBridge.lib" ^
    "%OBJ_DIR%\AwsSigV4Signer.obj" ^
    "%OBJ_DIR%\AwsBedrockClient.obj" ^
    "%OBJ_DIR%\SovereignAwsBridge.obj"

if errorlevel 1 (
    echo ERROR: Library creation failed
    exit /b 1
)

echo.
echo ============================================================================
echo  Build complete!
echo ============================================================================
echo  Library: %BUILD_DIR%\SovereignAwsBridge.lib
echo  Objects:
echo    - %OBJ_DIR%\AwsSigV4Signer.obj
echo    - %OBJ_DIR%\AwsBedrockClient.obj
echo    - %OBJ_DIR%\SovereignAwsBridge.obj
echo.
echo  To link into RawrXD-Win32IDE, add to your link line:
echo    SovereignAwsBridge.lib ws2_32.lib secur32.lib advapi32.lib
echo ============================================================================

exit /b 0
