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
set "EV=%ROOT%\evidence\STREAMER_VRAM_APERTURE_001"
if not exist "%OUT%" mkdir "%OUT%"
if not exist "%EV%" mkdir "%EV%"

call "%ROOT%\tests\masm\build_StreamRingBufferToVramAperture_x64.cmd"
if errorlevel 1 exit /b %errorlevel%

cl /nologo /O2 /EHsc /std:c++20 /W3 ^
  /Fe"%OUT%\streamer_vram_aperture_smoke.exe" ^
  /Fo"%OUT%\\" ^
  "%ROOT%\src\deep2\streamer_vram_aperture_smoke.cpp" ^
  "%OUT%\StreamRingBufferToVramAperture_x64.obj"
if errorlevel 1 exit /b %errorlevel%

"%OUT%\streamer_vram_aperture_smoke.exe" > "%EV%\RUN.log"
set RC=%ERRORLEVEL%
type "%EV%\RUN.log"
echo EXIT=%RC%>> "%EV%\RUN.log"
exit /b %RC%
