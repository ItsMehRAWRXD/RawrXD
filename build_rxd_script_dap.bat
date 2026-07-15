@echo off
REM Build script for RawrXD-Script DAP Server
REM Run this in VS Developer Command Prompt

echo ==========================================
echo RawrXD-Script DAP Server Build
echo ==========================================

set SRC_DIR=d:\rawrxd\src\script\debug
set OUT_DIR=d:\rawrxd\bin

if not exist %OUT_DIR% mkdir %OUT_DIR%

echo.
echo [1/3] Compiling rawrxd_script_dap_adapter.cpp...
cl /c /EHsc /O2 /MD /W4 /std:c++20 /I%SRC_DIR%\..\..\.. /I%SRC_DIR%\..\..\..\lsp /I%SRC_DIR%\..\..\..\3rdparty /Fo%OUT_DIR%\rxd_script_dap_adapter.obj %SRC_DIR%\rawrxd_script_dap_adapter.cpp
if errorlevel 1 goto :error

echo.
echo [2/3] Compiling main_dap_server.cpp...
cl /c /EHsc /O2 /MD /W4 /std:c++20 /I%SRC_DIR%\..\..\.. /I%SRC_DIR%\..\..\..\lsp /I%SRC_DIR%\..\..\..\3rdparty /Fo%OUT_DIR%\main_dap_server.obj %SRC_DIR%\main_dap_server.cpp
if errorlevel 1 goto :error

echo.
echo [3/3] Linking rxd-script-dap.exe...
link.exe /OUT:%OUT_DIR%\rxd-script-dap.exe ^
    %OUT_DIR%\main_dap_server.obj ^
    %OUT_DIR%\rxd_script_dap_adapter.obj ^
    kernel32.lib user32.lib ws2_32.lib ^
    /SUBSYSTEM:CONSOLE /LARGEADDRESSAWARE:NO
if errorlevel 1 goto :error

echo.
echo ==========================================
echo Build SUCCESSFUL!
echo Output: %OUT_DIR%\rxd-script-dap.exe
echo ==========================================
goto :end

:error
echo.
echo ==========================================
echo Build FAILED!
echo ==========================================
exit /b 1

:end
echo.
echo Next steps:
echo   1. Test the server: echo {"seq":1,"type":"request","command":"initialize"} ^| rxd-script-dap.exe
echo   2. Configure VS Code to use %OUT_DIR%\rxd-script-dap.exe
echo   3. Start debugging RawrXD-Script files!
