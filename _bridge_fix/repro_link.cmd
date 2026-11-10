@echo off
REM Bridge link probe harness. Links all 7 pre-built probe objects that make up
REM the real h.exe (hexmag, sub, drv, aac, conf, deleg, retry) plus any fix
REM implementation objects dropped into %~dp0impl\. Reports unresolved count.

setlocal enabledelayedexpansion
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (echo VCVARS_FAILED & exit /b 2)

cd /d "%~dp0"
set SRC=F:\rawrxd\build_lnk
set OUT=%~dp0

set OBJS=%SRC%\hexmag.obj %SRC%\sub.obj %SRC%\drv.obj %SRC%\aac.obj %SRC%\conf.obj %SRC%\deleg.obj %SRC%\retry.obj
if exist "%OUT%impl" for %%i in ("%OUT%impl\*.obj") do set OBJS=!OBJS! "%%i"

link /nologo /subsystem:console /entry:mainCRTStartup /out:"%OUT%h_repro.exe" !OBJS! > "%OUT%link_repro.txt" 2>&1
echo LINK_EXIT=!errorlevel!
findstr /R /C:"LNK2019" /C:"LNK2001" /C:"LNK1120" "%OUT%link_repro.txt" | findstr /R /C:"unresolved external" | find /C /V "" > "%OUT%count.txt"
set /p CNT=<"%OUT%count.txt"
echo UNRESOLVED_COUNT=!CNT!
findstr /R /C:"LNK1120" "%OUT%link_repro.txt"
endlocal
