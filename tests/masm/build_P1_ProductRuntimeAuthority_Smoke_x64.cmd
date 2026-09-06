@echo off
setlocal EnableExtensions

set "HERE=%~dp0"
for %%I in ("%HERE%..\..") do set "ROOT=%%~fI"

set "ASM=%ROOT%\src\asm"
set "OUT=%ROOT%\build\p1_product_runtime_authority_x64"

if not exist "%OUT%" mkdir "%OUT%"

where ml64.exe >nul 2>nul
if errorlevel 1 (
    echo ERROR: ml64.exe not found.
    echo Run from an x64 Native Tools Command Prompt.
    exit /b 9009
)

where link.exe >nul 2>nul
if errorlevel 1 (
    echo ERROR: link.exe not found.
    exit /b 9009
)

echo [1/3] Runtime

ml64.exe /nologo /c ^
  /I"%ASM%" ^
  /Fo"%OUT%\P1_ProductRuntimeAuthority_x64.obj" ^
  "%ASM%\P1_ProductRuntimeAuthority_x64.asm"

if errorlevel 1 exit /b %ERRORLEVEL%

echo [2/3] Smoke

ml64.exe /nologo /c ^
  /I"%ASM%" ^
  /Fo"%OUT%\P1_ProductRuntimeAuthority_Smoke_x64.obj" ^
  "%HERE%P1_ProductRuntimeAuthority_Smoke_x64.asm"

if errorlevel 1 exit /b %ERRORLEVEL%

echo [3/3] Link

link.exe /nologo ^
  /machine:x64 ^
  /subsystem:console ^
  /entry:P1_SmokeEntry ^
  /nodefaultlib ^
  /incremental:no ^
  /dynamicbase ^
  /nxcompat ^
  /out:"%OUT%\P1_ProductRuntimeAuthority_Smoke_x64.exe" ^
  "%OUT%\P1_ProductRuntimeAuthority_x64.obj" ^
  "%OUT%\P1_ProductRuntimeAuthority_Smoke_x64.obj"

if errorlevel 1 exit /b %ERRORLEVEL%

"%OUT%\P1_ProductRuntimeAuthority_Smoke_x64.exe"
set "RC=%ERRORLEVEL%"

if "%RC%"=="0" (
    echo P1_PRODUCT_RUNTIME_AUTHORITY_002_SMOKE=PASS
) else (
    echo P1_PRODUCT_RUNTIME_AUTHORITY_002_SMOKE=FAIL
)

echo EXIT=%RC%
exit /b %RC%
