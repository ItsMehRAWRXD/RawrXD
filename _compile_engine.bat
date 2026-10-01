@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 ( echo VCVARS_FAILED & exit /b 1 )

REM Compile Deep2Engine.cpp with the same flags as prior session (/MT, /W3)
set SRC=F:\~dev\rawrxd\src\deep2\Deep2Engine.cpp
set OBJ=F:\~dev\rawrxd\build_ide_audit\_Deep2Engine_patched_MT.obj
set INCLUDE_DIRS=/I"F:\~dev\rawrxd\src" /I"F:\~dev\rawrxd\src\deep2" /I"F:\~dev\rawrxd\src\sampling" /I"F:\~dev\rawrxd\src\lavapath" /I"F:\~dev\rawrxd\src\engine" /I"F:\~dev\rawrxd\3rdparty\vulkan\include" /I"F:\~dev\rawrxd\3rdparty" /I"C:\VulkanSDK\1.4.357.0\Include"
set DEFS=/D"_CRT_SECURE_NO_WARNINGS" /D"NOMINMAX" /D"WIN32" /D"_WINDOWS" /D"_MBCS"
set FLAGS=/nologo /std:c++17 /EHsc /O2 /W3 /MT /GS /Gy /Gd /Zp8 /Zc:__cplusplus

cl %FLAGS% %DEFS% %INCLUDE_DIRS% /c "%SRC%" /Fo"%OBJ%" 2>&1
if errorlevel 1 (
  echo COMPILE_FAIL
  exit /b 1
)
echo COMPILE_OK
