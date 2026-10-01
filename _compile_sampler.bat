@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
  echo VCVARS_FAILED
  exit /b 1
)
set SRC=F:\~dev\rawrxd\src\deep2\Sampler.cpp
set OBJ=F:\~dev\_sampler_test.obj
set EXE=F:\~dev\_sampler_test_compile_check.exe
cl /nologo /std:c++17 /EHsc /O2 /MT /c "%SRC%" /Fo"%OBJ%" /I"F:\~dev\rawrxd\src\deep2" 2>&1
if errorlevel 1 (
  echo COMPILE_FAIL
  exit /b 1
)
echo COMPILE_OK
link /nologo /OUT:"%EXE%" "%OBJ%" 2>&1
echo DONE
