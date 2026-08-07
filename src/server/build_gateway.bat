@echo off
:: Build RawrXD Gateway Server
:: Native HTTP server - no Python required

echo Building RawrXD Gateway...
echo.

set SRC=RawrXDGateway.cpp
set OUT=..\..\build\RawrXDGateway.exe

:: Create build directory if needed
if not exist ..\..\build mkdir ..\..\build

:: Compile with MSVC
cl.exe /O2 /EHsc /Fe"%OUT%" %SRC% /link httpapi.lib ws2_32.lib

if %ERRORLEVEL% neq 0 (
    echo.
    echo Build failed!
    exit /b 1
)

echo.
echo Build succeeded: %OUT%
echo.
echo Usage:
echo   RawrXDGateway.exe         :: Start on port 11435
echo   RawrXDGateway.exe --port 8080  :: Start on custom port
echo.
