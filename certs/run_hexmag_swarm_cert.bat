@echo off
REM ===========================================================================
REM RAWRXD_HEXMAG_SWARM_INTEGRATION_001 - build and run the certification.
REM Offline. Native toolchain only. Exit code 0 = PASS.
REM
REM NOTE: this script deliberately avoids parenthesised IF blocks, because the
REM MSVC path contains "(x86)" which prematurely closes the block.
REM ===========================================================================
setlocal

set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" goto novcvars

set "ROOT=%~dp0.."
if not "%~1"=="" set "ROOT=%~1"
set "REPOBUILD=%~2"
if "%REPOBUILD%"=="" set "REPOBUILD=%ROOT%\build-ninja"

echo [cert] configuring toolchain: %VCVARS%
call "%VCVARS%"
if %ERRORLEVEL% NEQ 0 goto envfail

echo [cert] building certification harness...
cl.exe /nologo /std:c++17 /EHsc /O2 /W3 /Fe:"%TEMP%\hexmag_swarm_cert.exe" "%~dp0hexmag_swarm_cert.cpp"
if %ERRORLEVEL% NEQ 0 goto buildfail

echo [cert] running swarm...
"%TEMP%\hexmag_swarm_cert.exe" "%ROOT%" "%REPOBUILD%" "%VCVARS%"
set CERT_RC=%ERRORLEVEL%

echo.
if %CERT_RC% EQU 0 echo CERTIFICATION: PASS
if %CERT_RC% NEQ 0 echo CERTIFICATION: FAIL
echo [cert] evidence: %ROOT%\HEXMAG_SWARM_CERT_EVIDENCE.json
exit /b %CERT_RC%

:buildfail
echo ERROR: failed to compile hexmag_swarm_cert.cpp
exit /b 2

:envfail
echo ERROR: vcvars64.bat failed to initialise the build environment
exit /b 3

:novcvars
echo ERROR: vcvars64.bat not found at %VCVARS%
exit /b 4
