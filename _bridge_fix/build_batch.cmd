@echo off
REM Compile one pure-native C++20 /MT fix source into impl\<name>.obj, then relink
REM the bridge probe and report the unresolved external count.
REM   usage: build_batch.cmd <src_path> <obj_name>
setlocal enabledelayedexpansion
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (echo VCVARS_FAILED & exit /b 2)

set SRC=%~1
set NAME=%~2
set OUT=F:\rawrxd\_bridge_fix
if not exist "%OUT%\impl" mkdir "%OUT%\impl"

cl /nologo /c /std:c++20 /MT /EHsc /O2 /Zc:__cplusplus /permissive- ^
   /I F:\rawrxd\src /I F:\rawrxd\include ^
   "%SRC%" /Fo:"%OUT%\impl\%NAME%.obj" > "%OUT%\cc_%NAME%.txt" 2>&1
if errorlevel 1 (
  echo COMPILE_FAILED_%NAME%
  findstr /R /C:"error" "%OUT%\cc_%NAME%.txt"
  exit /b 1
)
echo COMPILED_%NAME%
endlocal
