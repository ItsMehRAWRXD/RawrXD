@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if "%INCLUDE%"=="" ( echo VCVARS_FAILED & exit /b 1 )
cd /d F:\rawrxd
cl /nologo /std:c++17 /EHsc /O2 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS ^
  /I "C:\Users\Garrett\AppData\Local\Temp\kilo\parity\llama.cpp-c479922ac520a08969b4c1dc154d7bbb3c386d85\ggml\include" ^
  /I "C:\Users\Garrett\AppData\Local\Temp\kilo\parity\llama.cpp-c479922ac520a08969b4c1dc154d7bbb3c386d85\ggml\src" ^
  /I "C:\Users\Garrett\AppData\Local\Temp\kilo\parity\llama.cpp-c479922ac520a08969b4c1dc154d7bbb3c386d85\include" ^
  tools\q8_boundary_audit.cpp ^
  /Fe:tools\q8_boundary_audit.exe ^
  /link /LIBPATH:"C:\Users\Garrett\AppData\Local\Temp\kilo\parity\llama.cpp-c479922ac520a08969b4c1dc154d7bbb3c386d85\build\ggml\src\Release" ggml.lib ggml-base.lib ggml-cpu.lib
echo CL_EXIT=%errorlevel%

