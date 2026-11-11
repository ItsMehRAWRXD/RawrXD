@echo off
setlocal EnableExtensions
set BT=F:\rawrxd\build_tip_ext_host_001
set LOG=F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\harness\_rebuild_ext_loop_b01_023.log
echo BUILD_START %DATE% %TIME%> "%LOG%"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >> "%LOG%" 2>&1
if errorlevel 1 (
  echo VCVARS_FAIL>> "%LOG%"
  exit /b 90
)
echo Building Ext+loop -j2 from %BT%>> "%LOG%"
cmake --build "%BT%" --config RelWithDebInfo --target RawrXD-Win32IDE-Native-Ext --target deep2_agentic_loop -j 2 >> "%LOG%" 2>&1
set RC=%ERRORLEVEL%
echo BUILD_EXIT=%RC%>> "%LOG%"
echo BUILD_END %DATE% %TIME%>> "%LOG%"
exit /b %RC%
