@echo off
REM Assemble the real HexMag repeat tuner MASM into impl\hexmag_tuner.obj.
REM NOTE: this ml64 build ignores /Fo and writes <source-basename>.obj into the
REM current directory, so we run with CWD=impl and move the produced object.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (echo VCVARS_FAILED & exit /b 2)

set ASMDIR=F:\rawrxd\RawrXD-ModelLoader\services\hexmag\_drop_HexMag_Polymorphic_Repeat_Integration
set OUT=F:\rawrxd\_bridge_fix
if not exist "%OUT%\impl" mkdir "%OUT%\impl"

cd /d "%OUT%\impl"
ml64 /nologo /c /I "%ASMDIR%" "%ASMDIR%\RawrXD_HexMag_RepeatTuner.fixed.asm" > "%OUT%\ml_tuner.txt" 2>&1
if errorlevel 1 (
  echo ASM_FAILED
  type "%OUT%\ml_tuner.txt"
  exit /b 1
)
if exist "%OUT%\impl\RawrXD_HexMag_RepeatTuner.fixed.obj" (
  move /Y "%OUT%\impl\RawrXD_HexMag_RepeatTuner.fixed.obj" "%OUT%\impl\hexmag_tuner.obj" >nul
  echo ASM_OK
) else (
  echo OBJ_NOT_PRODUCED
  type "%OUT%\ml_tuner.txt"
  exit /b 1
)
endlocal
