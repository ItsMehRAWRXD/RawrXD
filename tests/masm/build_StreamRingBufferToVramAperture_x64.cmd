@echo off
setlocal
set "VSROOT=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
set "VCVARS=%VSROOT%\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
  set "VSROOT=C:\Program Files\Microsoft Visual Studio\2022\Community"
  set "VCVARS=%VSROOT%\VC\Auxiliary\Build\vcvars64.bat"
)
call "%VCVARS%" >nul || exit /b 1

set "ROOT=F:\~dev\rawrxd"
set "OUT=%ROOT%\build\streamer_vram_aperture"
if not exist "%OUT%" mkdir "%OUT%"

ml64 /nologo /c ^
  /Fo"%OUT%\StreamRingBufferToVramAperture_x64.obj" ^
  "%ROOT%\src\asm\StreamRingBufferToVramAperture_x64.asm"
if errorlevel 1 exit /b %errorlevel%

echo STREAMER_VRAM_APERTURE_OBJ=%OUT%\StreamRingBufferToVramAperture_x64.obj
exit /b 0
