@echo off
REM Deterministic certification for the universal-agent host gates H3 and H5.
REM Builds and runs from tracked sources; no LLM backend required.
REM   H5 authorization: links production src/rawr_core.cpp tool registry.
REM   H3 loop breaker:   drives real answerUniversal() with a scripted stub server.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 (echo FATAL VsDevCmd missing & exit /b 91)
set "SRC=F:\rawrxd\src"
cd /d %~dp0
if not exist bin mkdir bin
cl /nologo /std:c++20 /EHsc /O2 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS /I "%SRC%" /I "F:\rawrxd\include" h5_authorization_direct.cpp "%SRC%\rawr_core.cpp" /Fe:bin\h5_authorization_direct.exe /link winhttp.lib ws2_32.lib advapi32.lib kernel32.lib user32.lib
if errorlevel 1 (echo H5_BUILD_FAIL & exit /b 1)
cl /nologo /std:c++20 /EHsc /O2 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS /I "%SRC%" /I "F:\rawrxd\include" h3_loopbreaker_direct.cpp "%SRC%\rawr_core.cpp" /Fe:bin\h3_loopbreaker_direct.exe /link winhttp.lib ws2_32.lib advapi32.lib kernel32.lib user32.lib
if errorlevel 1 (echo H3_BUILD_FAIL & exit /b 1)
echo ==================== H5 authorization ====================
bin\h5_authorization_direct.exe
set H5=%errorlevel%
echo ==================== H3 loop breaker ==================
bin\h3_loopbreaker_direct.exe
set H3=%errorlevel%
echo ========================================================
echo H5_RC=%H5%  H3_RC=%H3%
if "%H5%"=="0" if "%H3%"=="0" (echo HOST_GATES_H3_H5_CERTIFIED) else (echo HOST_GATES_FAILED)
exit /b 0
