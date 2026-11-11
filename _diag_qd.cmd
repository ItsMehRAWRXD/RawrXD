@echo off
REM Diagnostic compile of quant_dot_dispatch.cpp
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul
cd /d F:\rawrxd
set DEFS=/DGGML_VERSION="0.9.4" /DGGML_COMMIT="unknown"
set INCS=/I . /I include /I src /I src\deep2 /I src\deep2\modelgenie /I tools /I generated\DeepSeek-V2-Lite-Chat /I 3rdparty\ggml\include /I 3rdparty\ggml\src /I C:\VulkanSDK\1.4.357.0\Include
cl /nologo /c /EHsc /O2 /Ob2 /std:c++20 /W1 /DNOMINMAX /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS /permissive- %INCS% %DEFS% /Fo:F:\rawrxd\qd_test.obj src\deep2\quant_dot_dispatch.cpp
exit /b %errorlevel%
