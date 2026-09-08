@echo off
setlocal
cd /d "%~dp0"

set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if exist "%VCVARS%" call "%VCVARS%" >nul

if not exist "%ML64%" (
  where ml64.exe >nul 2>&1 || (echo ml64 not found & exit /b 2)
  set ML64=ml64.exe
)

if not exist out mkdir out

"%ML64%" /nologo /c /Foout\model_bridge_web_x64.obj model_bridge_web_x64.asm || exit /b 3
"%ML64%" /nologo /c /Foout\rawr_native_policy_x64.obj rawr_native_policy_x64.asm || exit /b 4
"%ML64%" /nologo /c /Foout\rawr_native_receipt_x64.obj rawr_native_receipt_x64.asm || exit /b 5

cl /nologo /c /O2 /EHsc /W3 /I. /DWIN32_LEAN_AND_MEAN /DNOMINMAX /Foout\rawr_native_http_adapter.obj rawr_native_http_adapter.cpp || exit /b 6

lib /nologo out\model_bridge_web_x64.obj out\rawr_native_policy_x64.obj out\rawr_native_receipt_x64.obj out\rawr_native_http_adapter.obj /OUT:out\RawrNativeWebBridge.lib || exit /b 7

echo BUILT out\RawrNativeWebBridge.lib
endlocal
