@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91
cd /d F:\rawrxd
set OUT=F:\rawrxd\build_rt
set SRCS=_fma_test.cpp
cl /nologo /c /EHsc /O2 /std:c++20 /W1 /DNOMINMAX /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS /permissive- /I. /Iinclude /I3rdparty\ggml\include /I3rdparty\ggml\src /Isrc /Isrc\deep2 /Isrc\deep2\modelgenie /Itools /IC:\VulkanSDK\1.4.357.0\Include /DGGML_VERSION=\"0.9.4\" /DGGML_COMMIT=\"unknown\" /Fo:"%OUT%\\" %SRCS%
if errorlevel 1 (echo COMPILE_FAILED & exit /b 2)
rem reuse the already-built objects for the other translation units
link /nologo /subsystem:console /out:%OUT%\fma_kernel_check.exe "%OUT%\_fma_test.obj" "%OUT%\ggml_support.obj" "%OUT%\universal_gguf.obj" "%OUT%\runtime_graph_executor.obj" "%OUT%\quant_dot_dispatch.obj" "%OUT%\vulkan_compute.obj" "%OUT%\ggml-quants.obj" "%OUT%\ggml_link_stubs.obj" C:\VulkanSDK\1.4.357.0\Lib\vulkan-1.lib
if errorlevel 1 (echo LINK_FAILED & exit /b 3)
echo BUILD_OK
