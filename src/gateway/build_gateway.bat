@echo off
REM Build RawrXD Gateway Server
REM ============================

echo Building RawrXD Gateway Server...
echo.

REM Initialize VS2022 environment
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

if errorlevel 1 (
    echo ERROR: Failed to initialize Visual Studio environment
    pause
    exit /b 1
)

REM Compile gateway
echo Compiling RawrXDGateway.cpp...
cl.exe /W3 /O2 /nologo /EHsc /std:c++17 /I.. /Fe:RawrXDGateway.exe RawrXDGateway.cpp ws2_32.lib

if errorlevel 1 (
    echo.
    echo ERROR: Compilation failed
    pause
    exit /b 1
)

echo.
echo ==========================================
echo Build successful: RawrXDGateway.exe
echo ==========================================
echo.
echo To start the gateway:
echo   RawrXDGateway.exe        (port 8080)
echo   RawrXDGateway.exe 11436  (custom port)
echo.
echo Test endpoints:
echo   curl http://127.0.0.1:8080/health
echo   curl http://127.0.0.1:8080/api/capabilities
echo   curl http://127.0.0.1:8080/api/models
echo   curl http://127.0.0.1:8080/api/phases
echo.
pause
