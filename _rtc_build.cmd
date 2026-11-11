@echo off
REM Rebuild runtime_graph_executor.cpp with /RTC1 to localize the CPU heap
REM corruption, then relink deep2_runtime_dispatch.exe with that checked object.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (echo VCVARS_FAILED & exit /b 2)
cd /d F:\rawrxd

set DEFS=/DGGML_VERSION=\"0.9.4\" /DGGML_COMMIT=\"unknown\"
set INCS=/I . /I include /I src /I src\deep2 /I src\deep2\modelgenie /I tools /I generated\DeepSeek-V2-Lite-Chat /I 3rdparty\ggml\include /I 3rdparty\ggml\src /I C:\VulkanSDK\1.4.357.0\Include

cl /nologo /c /EHsc /Od /RTC1 /std:c++20 /W1 /DNOMINMAX /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS /permissive- %INCS% %DEFS% src\deep2\runtime_graph_executor.cpp /Fo:"F:\rawrxd\build_rt\runtime_graph_executor_rtc.obj"
if errorlevel 1 (echo RTC_COMPILE_FAILED & exit /b 4)
echo RTC_COMPILED

link /nologo /subsystem:console /out:"F:\rawrxd\build_rt\deep2_runtime_dispatch_rtc.exe" ^
  "F:\rawrxd\build_rt\deep2_runtime_dispatch.obj" "F:\rawrxd\build_rt\ggml_support.obj" ^
  "F:\rawrxd\build_rt\universal_gguf.obj" "F:\rawrxd\build_rt\runtime_graph_executor_rtc.obj" ^
  "F:\rawrxd\build_rt\quant_dot_dispatch.obj" "F:\rawrxd\build_rt\vulkan_compute.obj" ^
  "F:\rawrxd\build_rt\ggml-quants.obj" "F:\rawrxd\build_rt\ggml_link_stubs.obj" ^
  C:\VulkanSDK\1.4.357.0\Lib\vulkan-1.lib
if errorlevel 1 (echo RTC_LINK_FAILED & exit /b 5)
echo RTC_LINK_OK
exit /b 0
