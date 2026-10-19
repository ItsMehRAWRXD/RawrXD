@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd
set OUT=evidence\RAWRXD_PERFORMANCE_001
set ASM=src\asm\xr_realmath
set ML64=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\ml64.exe
if not exist "%OUT%" mkdir "%OUT%"
"%ML64%" /c /nologo /I "%ASM%" /Fo"%OUT%\RawrXD_RealMathAttention_x64.obj" "%ASM%\RawrXD_RealMathAttention_x64.asm"
if errorlevel 1 exit /b 1
cl /nologo /EHsc /std:c++17 /O2 /I. /Isrc /Fo"%OUT%\\" /Fe"%OUT%\k2_realmath_attention_climb_001.exe" certs\k2_realmath_attention_climb_001.cpp /link "%OUT%\RawrXD_RealMathAttention_x64.obj"
if errorlevel 1 exit /b 1
"%OUT%\k2_realmath_attention_climb_001.exe"
echo RUN_EXIT=%ERRORLEVEL%
