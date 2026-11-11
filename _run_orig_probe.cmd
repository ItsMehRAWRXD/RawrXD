@echo off
REM Run the ORIGINAL (10:35 PM) probe with instrumented dlls.
REM Usage: _run_orig_probe.cmd <n_pos> <token0> <token1> ...
setlocal
set VSD=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat
call "%VSD%" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91

set NPOS=%~1
if "%NPOS%"=="" set NPOS=3
shift
set TOKENS=%*

set OUTDIR=F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\orig_rerun2
if not exist "%OUTDIR%" mkdir "%OUTDIR%"
set RAWRXD_PROBE_DIR=%OUTDIR%

echo [orig-probe] npos=%NPOS% tokens=%TOKENS% outdir=%OUTDIR%
F:\rawrxd\tmp_build_orig\rawrxd_kq_probe.exe F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf %NPOS% %TOKENS% > "%OUTDIR%_run.log" 2>&1
echo [orig-probe] exit=%errorlevel%
exit /b %errorlevel%
