@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd
set OUT=evidence\K2_REAL_ATTENTION_001
set SRC_DIR=src\asm\k2_real_attention
set SRC=%SRC_DIR%\RawrXD_K2_RealAttention_x64.asm
set ML64=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\ml64.exe
if not exist "%OUT%" mkdir "%OUT%"
"%ML64%" /c /nologo /I "%SRC_DIR%" /Fo"%OUT%\RawrXD_K2_RealAttention_x64.obj" "%SRC%"
if errorlevel 1 (
  echo ASSEMBLED=FAIL
  exit /b 1
)
echo ASSEMBLED=PASS
echo OBJ=%OUT%\RawrXD_K2_RealAttention_x64.obj
dir "%OUT%\RawrXD_K2_RealAttention_x64.obj"
