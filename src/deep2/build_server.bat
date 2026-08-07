@echo off
REM Build Deep2 Test API Server
REM ===========================

call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

echo Building Deep2 Test API Server...

cl.exe /W3 /O2 /nologo /EHsc /Fe:test_api_server.exe test_api_server.cpp ws2_32.lib

if errorlevel 1 (
    echo Build failed!
    pause
    exit /b 1
)

echo.
echo Build complete: test_api_server.exe
echo.
pause
