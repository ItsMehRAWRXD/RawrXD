@echo off
setlocal
set CL=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe
set OUTDIR=G:\~dev\rawrxd\evidence\AGENTIC_COMPOSER_RUNTIME_001
cd /d "%OUTDIR%"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
"%CL%" /nologo /EHsc /O2 /Fe:probe_composer_modes.exe probe_composer_modes.cpp /link /nologo
if errorlevel 1 exit /b 1
probe_composer_modes.exe > probe_run.txt 2>&1
echo EXIT=%ERRORLEVEL%>> probe_run.txt
type probe_run.txt
exit /b %ERRORLEVEL%
