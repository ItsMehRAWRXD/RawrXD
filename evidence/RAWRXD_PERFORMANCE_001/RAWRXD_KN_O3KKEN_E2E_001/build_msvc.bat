@echo off
setlocal
cd /d "%~dp0"

del /q KN_O3KKEN.obj KN_O3KKEN_smoke.obj KN_O3KKEN.exe 2>nul

ml64 /nologo /c /I"G:\~dev\rawrxd\src\deep2\lavapath" KN_O3KKEN.asm
if errorlevel 1 exit /b 1
ml64 /nologo /c /I"G:\~dev\rawrxd\src\deep2\lavapath" KN_O3KKEN_smoke.asm
if errorlevel 1 exit /b 1

link /nologo /subsystem:console /entry:main KN_O3KKEN.obj KN_O3KKEN_smoke.obj kernel32.lib
if errorlevel 1 exit /b 1

KN_O3KKEN.exe
set RC=%ERRORLEVEL%
echo KN_O3KKEN_E2E_EXIT=%RC%
if not "%RC%"=="42" exit /b 1
echo KN_O3KKEN_E2E=PASS
exit /b 0
