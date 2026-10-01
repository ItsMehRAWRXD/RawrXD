@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 ( echo VCVARS_FAILED & exit /b 1 )

set TEST_SRC=F:\~dev\rawrxd\tools\deep2_generation_lifecycle_test.cpp
set TEST_OBJ=F:\~dev\rawrxd\build_ide_audit\_lifecycle_test_MT.obj
set INCLUDE_DIRS=/I"F:\~dev\rawrxd\src" /I"F:\~dev\rawrxd\src\deep2" /I"F:\~dev\rawrxd\src\sampling" /I"F:\~dev\rawrxd\src\lavapath" /I"F:\~dev\rawrxd\src\engine" /I"C:\VulkanSDK\1.4.357.0\Include" /I"F:\~dev\rawrxd\3rdparty"
set DEFS=/D"_CRT_SECURE_NO_WARNINGS" /D"NOMINMAX" /D"WIN32" /D"_WINDOWS" /D"_MBCS"
set FLAGS=/nologo /std:c++17 /EHsc /O2 /W3 /MT /GS /Gy /Gd /Zp8 /Zc:__cplusplus

echo === STEP 1: Compile lifecycle test ===
cl %FLAGS% %DEFS% %INCLUDE_DIRS% /c "%TEST_SRC%" /Fo"%TEST_OBJ%"
if errorlevel 1 ( echo LIFECYCLE_COMPILE_FAIL & exit /b 1 )
echo LIFECYCLE_COMPILE_OK

echo === STEP 2: Link with InferenceEngine_patched.lib ===
set EXE=F:\~dev\rawrxd\bin\deep2_generation_lifecycle_test.exe
set DEEP2_OBJ=F:\~dev\rawrxd\build_ide_audit\_Deep2Engine_patched_MT.obj
set LIB=F:\~dev\rawrxd\build_ide_audit\Release\InferenceEngine_patched.lib
set VULKAN=C:\VulkanSDK\1.4.357.0\Lib\vulkan-1.lib

link /nologo /OUT:"%EXE%" "%TEST_OBJ%" "%DEEP2_OBJ%" "%LIB%" "%VULKAN%"
if errorlevel 1 ( echo LINK_FAIL & exit /b 1 )
echo LINK_OK
echo === STEP 3: Verify executable ===
if exist "%EXE%" (
  echo EXE_EXISTS
  echo EXE_SIZE_BYTES=%~z2
  for %%A in ("%EXE%") do echo EXE_FULL_SIZE=%%~zA
)
echo REBUILD_DONE
