@echo off
REM Build Deep2 Complete API Server
REM =================================

call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat" 2>nul

echo Building Deep2 Complete API Server...
echo.

cl.exe /W3 /O2 /nologo /EHsc /Fe:Deep2APIServer.exe Deep2APIServer_Complete.cpp ws2_32.lib

if errorlevel 1 (
    echo.
    echo Build failed!
    echo Make sure Visual Studio 2022 is installed
    pause
    exit /b 1
)

echo.
echo ==========================================
echo Build complete: Deep2APIServer.exe
echo ==========================================
echo.
echo To run:
echo   Deep2APIServer.exe        (port 11436)
echo   Deep2APIServer.exe 11437  (custom port)
echo.
echo Test endpoints:
echo   curl http://127.0.0.1:11436/health
echo   curl http://127.0.0.1:11436/api/version
echo   curl http://127.0.0.1:11436/api/phases
echo   curl http://127.0.0.1:11436/api/phases/10
echo   curl http://127.0.0.1:11436/api/backends
echo.
echo Press any key to exit...
pause >nul
