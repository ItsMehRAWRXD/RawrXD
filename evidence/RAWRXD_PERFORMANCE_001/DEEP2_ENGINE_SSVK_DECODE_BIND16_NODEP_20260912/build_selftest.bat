@echo off
setlocal
cd /d "%~dp0"
call :try_vcvars
cl /nologo /EHsc /O2 /W4 /std:c++17 /I src src\selftest.cpp src\d2_engine_ssvk_bind16.cpp /Fe:selftest_bind16.exe
if errorlevel 1 exit /b %errorlevel%
selftest_bind16.exe
exit /b %errorlevel%

:try_vcvars
if defined VSCMD_ARG_TGT_ARCH goto :eof
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
  call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
  goto :eof
)
if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
  call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
  goto :eof
)
goto :eof
