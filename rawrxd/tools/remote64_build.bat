@echo off
setlocal enabledelayedexpansion
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
  echo VCVARS_FAIL
  exit /b 1
)
set SRC=%~dp0..\src\remote64
set OUT=%~dp0..\build_remote64\obj
if not exist "%OUT%" mkdir "%OUT%"
set PASS=0
set FAIL=0
set FAILEDLIST=
for %%F in ("%SRC%\*.asm") do (
  echo [ASM] %%~nxF
  ml64 /nologo /c /I "%SRC%" /Fo"%OUT%\%%~nF.obj" "%%F" > "%OUT%\%%~nF.log" 2>&1
  if errorlevel 1 (
    set /a FAIL+=1
    set FAILEDLIST=!FAILEDLIST! %%~nF
  ) else (
    set /a PASS+=1
  )
)
echo.
echo ASM_PASS=!PASS!
echo ASM_FAIL=!FAIL!
echo FAILED=!FAILEDLIST!
if not "!FAIL!"=="0" exit /b 1
exit /b 0
