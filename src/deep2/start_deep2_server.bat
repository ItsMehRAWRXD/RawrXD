@echo off
REM Start Deep2 API Server
REM ========================

echo ==========================================
echo  Deep2 Native API Server Startup
echo ==========================================
echo.
echo This will start the Deep2 API server on port 11436
echo.
echo Required endpoints for IDE integration:
echo   - GET  /api/version
echo   - GET  /api/backends
echo   - GET  /api/health
echo   - GET  /api/tags
echo   - POST /api/generate
echo   - POST /api/chat
echo.
echo Press Ctrl+C to stop the server
echo ==========================================
echo.

REM Check if test server exists
if not exist "test_api_server.exe" (
    echo ERROR: test_api_server.exe not found!
    echo.
    echo Building now...
    call build_server.bat
    if errorlevel 1 (
        echo Build failed!
        pause
        exit /b 1
    )
)

echo Starting Deep2 API Server on port 11436...
echo.

test_api_server.exe 11436

if errorlevel 1 (
    echo.
    echo Server failed to start. Possible causes:
    echo   - Port 11436 already in use
    echo   - Windows Firewall blocking
    echo   - Missing dependencies
    echo.
    echo To check port usage: netstat -ano ^| findstr 11436
    pause
)
