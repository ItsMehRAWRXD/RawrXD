@echo off
echo Building RawrXD OpenAI-Compatible Server...
cl /O2 /W3 /Fe:rawrxd_server.exe rawrxd_server.c /link ws2_32.lib user32.lib kernel32.lib
if %errorlevel% == 0 (
    echo.
    echo SUCCESS: rawrxd_server.exe built
    echo.
    echo Launch sequence:
    echo   1. Start SovereignOrchestrator.exe
    echo   2. Start rawrxd_server.exe
    echo   3. Connect editor to http://localhost:8080/v1
) else (
    echo BUILD FAILED
)
