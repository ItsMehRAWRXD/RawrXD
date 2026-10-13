@echo off
REM ============================================================================
REM  Canonical build for `rawr` - the RawrXD universal native CLI agent.
REM  Commands: rawr ask | reason | run | tools | models | backend | doctor ...
REM  Dependencies: MSVC (VS 2022) + nlohmann/json (bundled under include\) +
REM                WinHTTP. No Qt, no third-party libs, no external agent SDK.
REM  Produces:   <repo>\bin\rawr.exe
REM  Invoke from ANY directory; paths are derived from this script's location.
REM ============================================================================
setlocal
set VSDEV="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
if not exist %VSDEV% set VSDEV="C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
if not exist %VSDEV% set VSDEV="C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
call %VSDEV% -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 (echo [build_rawr] FATAL: VsDevCmd.bat not found & exit /b 91)

set "ROOT=%~dp0.."
if not exist "%ROOT%\bin" mkdir "%ROOT%\bin"
if not exist "%ROOT%\bin\obj" mkdir "%ROOT%\bin\obj"

cl /nologo /std:c++20 /EHsc /O2 /W3 /permissive- /bigobj /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS ^
   /I "%ROOT%\src" /I "%ROOT%\include" ^
   "%ROOT%\src\rawr_cli.cpp" "%ROOT%\src\rawr_core.cpp" ^
   /Fo:"%ROOT%\bin\obj\\" ^
   /Fe:"%ROOT%\bin\rawr.exe" ^
   /link winhttp.lib ws2_32.lib advapi32.lib kernel32.lib user32.lib
echo RAWREXE_RC=%errorlevel%
exit /b %errorlevel%
