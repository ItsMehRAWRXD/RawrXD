@echo off
REM Build the RAWRXD_CORE_DLL_NATIVE_E2E_001 endurance/streaming/cancellation
REM harness against the freshly built production DLL.
REM   --len N   endurance: N tokens, no collapse, clean shutdown
REM   --stream N streaming order
REM   --cancel N cancellation + post-cancel reuse
REM   --reuse N context create/destroy cycles on one model handle
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91
cd /d F:\rawrxd
cl /nologo /EHsc /O2 /std:c++20 /W1 /DNOMINMAX /DWIN32_LEAN_AND_MEAN ^
   /I src\core\dll /I include /I build_cert\src\core\dll ^
   tools\e2e_endurance.cpp ^
   build_cert\lib\Release\RawrXDCore.lib ^
   /Fe:tmp_build_e2e\e2e_endurance.exe
if errorlevel 1 (
  echo ENDURANCE_BUILD_FAILED
  exit /b 2
)
echo ENDURANCE_BUILD_OK
exit /b 0
