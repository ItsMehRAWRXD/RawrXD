@echo off
set "VCTOOLS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build"
call "%VCTOOLS%\vcvarsall.bat" x64
cl /nologo /O2 /EHsc /std:c++20 F:\rawrxd\tmp_check_f32.cpp /link /nologo /machine:x64 /OUT:F:\rawrxd\check_f32.exe
if errorlevel 1 (
  echo COMPILE_FAILED
  exit /b 1
)
echo COMPILE_OK
F:\rawrxd\check_f32.exe
