@echo off
setlocal
if "%VSCMD_ARG_TGT_ARCH%"=="" (
  echo Run from x64 Native Tools Command Prompt or call vcvars64.bat first.
  exit /b 2
)
ml64 /nologo /c /Fo:deep2_lb.obj deep2_lb.asm
if errorlevel 1 exit /b %errorlevel%
echo BUILT=deep2_lb.obj
echo NOTE=object-only source drop; link into Deep2 product after gate validation.
endlocal
