@echo off
:: Minimal DAP Server Build Script
:: Uses g++ (MinGW) to build the standalone DAP server

echo Building RawrXD-Script DAP Server...
echo.

set SRC_DIR=d:\rawrxd\src\script\debug
set OUT_DIR=d:\rawrxd\bin

if not exist %OUT_DIR% mkdir %OUT_DIR%

g++ -std=c++20 ^
    %SRC_DIR%\main_dap_server.cpp ^
    %SRC_DIR%\rawrxd_script_dap_adapter.cpp ^
    -I d:\rawrxd\include ^
    -I d:\rawrxd\src ^
    -I d:\rawrxd\third_party ^
    -o %OUT_DIR%\rxd-script-dap.exe ^
    -static-libgcc ^
    -static-libstdc++ ^
    -lws2_32 ^
    -lwsock32

if %ERRORLEVEL% neq 0 (
    echo Build failed!
    exit /b 1
)

echo Build successful: %OUT_DIR%\rxd-script-dap.exe
echo.
echo To test the DAP server:
echo   1. Run: .\bin\rxd-script-dap.exe
echo   2. Send: Content-Length: 156^^^&echo.{"seq":1,"type":"request","command":"initialize","arguments":{"clientID":"vscode","adapterID":"rawrxd-script"}}
echo   3. Expect: JSON response with capabilities
