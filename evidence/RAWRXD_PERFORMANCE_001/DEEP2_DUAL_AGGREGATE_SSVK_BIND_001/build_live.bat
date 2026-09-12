@echo off
setlocal
set VKINC=C:\VulkanSDK\1.4.357.0\Include
set M15=..\DEEP2_MISSING15_NODEP_SOURCE_20260912\DEEP2_MISSING15_NODEP_SOURCE_20260912\src
if not exist build mkdir build
cl /nologo /std:c++17 /O2 /EHsc /I src /I "%VKINC%" /I "%M15%" ^
  src\live_main.cpp src\d2_live_vk_open.cpp src\d2_live_vk_lane.cpp src\d2_ssvk_live_bind.cpp ^
  "%M15%\d2_partition_planner.cpp" "%M15%\d2_range_locality.cpp" ^
  "%M15%\d2_deviceio_ssvk_bind.cpp" "%M15%\d2_fabric_submit.cpp" ^
  "%M15%\d2_overlap_authority.cpp" "%M15%\d2_compact_reduce.cpp" ^
  "%M15%\d2_authority_gate.cpp" "%M15%\d2_nvme_coldpath_guard.cpp" ^
  /Fe:build\d2_dual_ssvk_live.exe
if errorlevel 1 exit /b %errorlevel%
build\d2_dual_ssvk_live.exe
exit /b %errorlevel%
