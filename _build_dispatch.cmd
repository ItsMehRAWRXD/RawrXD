@echo off
REM Build deep2_runtime_dispatch.exe from current sources (compile then link)
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91
cd /d F:\rawrxd
set OUT=F:\rawrxd\build_rt
if not exist "%OUT%" mkdir "%OUT%"

set SRCS=tools\deep2_runtime_dispatch.cpp tools\ggml_support.cpp src\deep2\modelgenie\universal_gguf.cpp src\deep2\runtime_graph_executor.cpp src\deep2\quant_dot_dispatch.cpp src\vulkan_compute.cpp src\ggml-quants.c tools\ggml_link_stubs.cpp
set DEFS=/DGGML_VERSION=\"0.9.4\" /DGGML_COMMIT=\"unknown\"
set INCS=/I . /I include /I src /I src\deep2 /I src\deep2\modelgenie /I tools /I generated\DeepSeek-V2-Lite-Chat /I 3rdparty\ggml\include /I 3rdparty\ggml\src /I C:\VulkanSDK\1.4.357.0\Include

REM C++ sources
cl /nologo /c /EHsc /O2 /Ob2 /std:c++20 /W1 /DNOMINMAX /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS /permissive- %INCS% %DEFS% /Fo:"%OUT%\\" %SRCS%
if errorlevel 1 (
  echo CPP_COMPILE_FAILED
  exit /b 2
)

REM Link
link /nologo /subsystem:console /out:%OUT%\deep2_runtime_dispatch.exe "%OUT%\deep2_runtime_dispatch.obj" "%OUT%\ggml_support.obj" "%OUT%\universal_gguf.obj" "%OUT%\runtime_graph_executor.obj" "%OUT%\quant_dot_dispatch.obj" "%OUT%\vulkan_compute.obj" "%OUT%\ggml-quants.obj" "%OUT%\ggml_link_stubs.obj" C:\VulkanSDK\1.4.357.0\Lib\vulkan-1.lib
if errorlevel 1 (
  echo LINK_FAILED
  exit /b 3
)
echo BUILD_OK
exit /b 0
