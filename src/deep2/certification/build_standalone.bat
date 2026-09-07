@echo off
REM Deep2 Gateway Runtime Certification - Standalone Build (BuildTools)
setlocal
set "VCVARS="
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
  set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
  set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
)
if "%VCVARS%"=="" (
  echo ERROR: vcvars64.bat not found
  exit /b 1
)
call "%VCVARS%" >nul
cd /d "%~dp0"
cl.exe /nologo /W3 /O2 /EHsc /std:c++20 /GR- /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS ^
  /Fe:Deep2_Gateway_Runtime_Certification.exe ^
  Deep2_Cert_Main.cpp Deep2_Cert_MockGateway.cpp ^
  /link /SUBSYSTEM:CONSOLE winhttp.lib ws2_32.lib
if errorlevel 1 exit /b %ERRORLEVEL%
echo BUILD OK
dir Deep2_Gateway_Runtime_Certification.exe
echo Run: Deep2_Gateway_Runtime_Certification.exe --selftest
