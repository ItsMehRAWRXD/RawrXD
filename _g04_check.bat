@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if "%INCLUDE%"=="" ( echo VCVARS_FAIL & exit /b 1 )
set VK_INC=C:\VulkanSDK\1.4.357.0\Include
set GGML_SRC=F:\rawrxd\3rdparty\ggml
set SRC=F:\rawrxd\src
if not exist "F:\rawrxd\tools\obj_g04_chk" mkdir "F:\rawrxd\tools\obj_g04_chk"
cl /nologo /c /std:c++20 /EHsc /O2 /W3 /permissive- /bigobj /openmp /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS /I %VK_INC% /I %GGML_SRC%\include /I %SRC% /I %SRC%\deep2 /I %SRC%\deep2\modelgenie /I F:\rawrxd\include /I F:\rawrxd %SRC%\vulkan_compute.cpp %SRC%\deep2\quant_dot_dispatch.cpp /FoF:\rawrxd\tools\obj_g04_chk\ 2>&1
echo EXIT=%errorlevel%
