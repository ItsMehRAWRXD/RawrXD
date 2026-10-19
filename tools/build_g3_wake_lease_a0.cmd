@echo off
setlocal EnableDelayedExpansion
set GATE=G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_AMDVLK_UNBLOCK_001\P2
set VK=C:\VulkanSDK\1.4.357.0
set VS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
mkdir "%GATE%" 2>nul
call "%VS%" >nul
cd /d G:\~dev\rawrxd\tools
cl /nologo /EHsc /std:c++17 /O2 /MD /I"%VK%\Include" g3_wake_lease_a0.cpp g3_wake_lease_d3d.cpp g3_wake_lease_util.cpp /Fe:"%GATE%\g3_wake_lease_a0.exe" /link d3d12.lib dxgi.lib >"%GATE%\build.log" 2>&1
if errorlevel 1 (
  type "%GATE%\build.log"
  exit /b 1
)
set PASSN=0
for /L %%i in (1,1,5) do (
  "%GATE%\g3_wake_lease_a0.exe" >"%GATE%\wake_%%i.txt" 2>&1
  set EC=!ERRORLEVEL!
  echo RUN_%%i_EXIT=!EC!
  findstr /C:"WAKE_LEASE_A0=" "%GATE%\wake_%%i.txt"
  if !EC! EQU 0 set /a PASSN+=1
)
echo WAKE_LEASE_PASS=!PASSN!_OF_5
endlocal
