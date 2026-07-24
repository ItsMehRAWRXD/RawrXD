@echo off
cd /d d:\rawrxd\build-ninja
ninja witness_system_test 2>&1
if %ERRORLEVEL% == 0 (
    echo Build successful!
    echo Running witness_system_test...
    bin\witness_system_test.exe
) else (
    echo Build failed!
)
pause
