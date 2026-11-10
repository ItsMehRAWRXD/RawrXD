@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul
cd /d F:\rawrxd\_eval_harness
cl /nologo /std:c++20 /EHsc /O2 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS /I F:\rawrxd\src /I F:\rawrxd\include h3_direct.cpp F:\rawrxd\src\rawr_core.cpp /Fe:F:\rawrxd\_eval_harness\h3_direct.exe /link winhttp.lib ws2_32.lib advapi32.lib kernel32.lib user32.lib
if errorlevel 1 (echo BUILD_FAILED & exit /b 1)
F:\rawrxd\_eval_harness\h3_direct.exe
echo H3DIRECT_RC=%errorlevel%
