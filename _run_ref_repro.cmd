@echo off
REM RAWRXD reference reproduction run (Move 04).
REM Usage: _run_ref_repro.cmd <kv_type> <outdir> <logfile>
setlocal
set VSD=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat
call "%VSD%" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91

set KV=%~1
if "%KV%"=="" set KV=f16
set OUTDIR=%~2
if "%OUTDIR%"=="" set OUTDIR=F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\ref_repro_%KV%
set LOG=%~3
if "%LOG%"=="" set LOG=%OUTDIR%_run.log

if not exist "%OUTDIR%" mkdir "%OUTDIR%"
set RAWRXD_PROBE_DIR=%OUTDIR%
set RAWRXD_REF_KV=%KV%

echo [ref-repro] kv=%KV% outdir=%OUTDIR%
F:\rawrxd\tmp_build_ref\rawrxd_kq_probe.exe F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf 19 1 185 16 13 440 40 6 76 11547 11 304 481 6 83 883 185 17 13 440 > "%LOG%" 2>&1
echo [ref-repro] exit=%errorlevel%
exit /b %errorlevel%
