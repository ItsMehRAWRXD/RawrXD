@echo off
setlocal
set GATE=G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_VDRIVER_DUAL_POOL_001
set VS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
mkdir "%GATE%" 2>nul
call "%VS%" >nul
cd /d G:\~dev\rawrxd\tools
cl /nologo /EHsc /std:c++17 /O2 /MD g3_vdrv_dual_pool.cpp /Fe:"%GATE%\g3_vdrv_dual_pool.exe" /link dxgi.lib d3d12.lib >"%GATE%\build.log" 2>&1
if errorlevel 1 (
  type "%GATE%\build.log"
  exit /b 1
)
"%GATE%\g3_vdrv_dual_pool.exe" >"%GATE%\PROBE_OUT.txt"
type "%GATE%\PROBE_OUT.txt"
echo PROBE_EXIT=%ERRORLEVEL%
endlocal
