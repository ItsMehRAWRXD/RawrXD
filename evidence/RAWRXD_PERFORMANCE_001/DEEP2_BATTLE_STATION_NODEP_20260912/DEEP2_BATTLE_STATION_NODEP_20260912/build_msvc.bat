@echo off
setlocal
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" echo MSVC_VCVARS_NOT_FOUND& exit /b 2
call "%VCVARS%" >nul
if errorlevel 1 echo MSVC_VCVARS_INIT_FAILED& exit /b 3
where cl >nul 2>&1 || (echo MSVC_CL_NOT_FOUND_AFTER_VCVARS& exit /b 4)
cl /nologo /TC /O2 /W4 /WX /MT /D_CRT_SECURE_NO_WARNINGS /Isrc src\battle_station.c src\bs_sha256.c src\bs_logscan.c src\bs_process.c src\bs_policy.c /Fe:battle_station.exe
if errorlevel 1 exit /b %errorlevel%
cl /nologo /TC /O2 /W4 /WX /MT /Isrc tests\smoke.c src\bs_policy.c /Fe:battle_station_smoke.exe
if errorlevel 1 exit /b %errorlevel%
battle_station_smoke.exe
