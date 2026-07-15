@echo off
echo [TEST] Direct VS2022 Linker Test
echo =================================

cd /d C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64

echo Current directory: %CD%
echo.

echo Testing linker...
link.exe /VERSION
echo Linker exit: %ERRORLEVEL%
echo.

echo Testing simple link...
link.exe /DLL /OUT:d:\rawrxd\build-master\bin\test.dll d:\rawrxd\build-master\input_handler.obj kernel32.lib
echo Link exit: %ERRORLEVEL%
echo.

if exist d:\rawrxd\build-master\bin\test.dll (
    echo SUCCESS: test.dll created
    for %%F in (d:\rawrxd\build-master\bin\test.dll) do echo Size: %%~zF bytes
) else (
    echo FAILED: test.dll not created
)
