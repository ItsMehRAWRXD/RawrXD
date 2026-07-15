@echo off
REM Quick standalone build for validation test
setlocal

echo Building QuickTest.exe...

"C:\VS2022Enterprise\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64\cl.exe" /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"d:\rawrxd\src\debug" "d:\rawrxd\src\debug\QuickTest.cpp" "d:\rawrxd\src\debug\DebugBackend.cpp" "d:\rawrxd\src\debug\DebugBridge.cpp" /Fe"d:\rawrxd\build\bin\QuickTest.exe" /link dbghelp.lib kernel32.lib user32.lib /SUBSYSTEM:CONSOLE

if %ERRORLEVEL% neq 0 (
    echo BUILD FAILED
    exit /b 1
)

echo BUILD SUCCESS
echo Running QuickTest.exe...
"d:\rawrxd\build\bin\QuickTest.exe"
echo.
echo Results written to: d:\rawrxd\build\bin\test_results.txt
type "d:\rawrxd\build\bin\test_results.txt"
