@echo off
REM Build Deep2 Test API Server
REM ===========================

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
echo To run:
echo   test_api_server.exe        (port 11436)
echo   test_api_server.exe 11437  (custom port)
echo.
echo Test with curl:
echo   curl http://127.0.0.1:11436/api/version
echo   curl http://127.0.0.1:11436/api/backends
echo.

pause
