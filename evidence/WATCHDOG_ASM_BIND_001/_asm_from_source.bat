@echo off
set ML64=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\ml64.exe
set SRC=G:\~dev\rawrxd\src\asm\RawrXD_Watchdog.asm
set OUT=G:\~dev\rawrxd\evidence\WATCHDOG_ASM_BIND_001\RawrXD_Watchdog_from_source.obj
set INC=G:\~dev\rawrxd\src\asm
"%ML64%" /c /Zi /Zd /I "%INC%" /Fo"%OUT%" "%SRC%" > "G:\~dev\rawrxd\evidence\WATCHDOG_ASM_BIND_001\ml64_from_source.out" 2>&1
echo EXIT=%ERRORLEVEL%
if exist "%OUT%" (for %%A in ("%OUT%") do echo OBJ_SIZE=%%~zA) else (echo OBJ_MISSING)
