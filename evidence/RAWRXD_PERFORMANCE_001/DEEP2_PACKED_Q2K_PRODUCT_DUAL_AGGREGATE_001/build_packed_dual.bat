@echo off
setlocal
set VKINC=C:\VulkanSDK\1.4.357.0\Include
set ROOT=%~dp0
set M15=%ROOT%..\DEEP2_MISSING15_NODEP_SOURCE_20260912\DEEP2_MISSING15_NODEP_SOURCE_20260912\src
set LIVE=%ROOT%..\DEEP2_DUAL_AGGREGATE_SSVK_BIND_001\src
set MAT=%ROOT%..\DEEP2_MATERIAL_DUAL_OVERLAP_NODEP_20260912
set DB=%ROOT%..\DEEP2_X64_MASM_DECODE_FINISH_BALANCER_20260912
if not exist build mkdir build
if not exist "%DB%\build" mkdir "%DB%\build"
pushd "%DB%"
ml64 /nologo /c /Fo build\deep2_decode_balance.obj deep2_decode_balance.asm
if errorlevel 1 popd & exit /b %errorlevel%
copy /Y build\deep2_decode_balance.obj "%ROOT%build\deep2_decode_balance.obj" >nul
popd
cl /nologo /std:c++17 /O2 /EHsc /I src /I include /I "%VKINC%" /I "%M15%" /I "%LIVE%" /I "%MAT%\include" /I "%DB%" ^
  src\main.cpp src\d2_gguf_q2k_slice.cpp src\d2_packed_dual_run.cpp src\d2_packed_dual_exec.cpp ^
  "%LIVE%\d2_live_vk_open.cpp" "%LIVE%\d2_live_vk_lane.cpp" ^
  "%M15%\d2_packed_q2k_contract.cpp" ^
  "%MAT%\src\d2_overlap_core.cpp" "%MAT%\src\d2_material_overlap_win32.cpp" ^
  build\deep2_decode_balance.obj ^
  /Fe:build\d2_packed_q2k_dual.exe
if errorlevel 1 exit /b %errorlevel%
build\d2_packed_q2k_dual.exe "G:\~dev\rawrxd\llama3.2-3b-Q2_K.gguf" 16
exit /b %errorlevel%
