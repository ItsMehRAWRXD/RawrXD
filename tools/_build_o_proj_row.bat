@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d F:\~dev\rawrxd\build-ninja
cmake --build . --target InferenceEngine -j 8
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /EHsc /O2 /arch:AVX2 /I F:\~dev\rawrxd\src\deep2 /I F:\~dev\rawrxd\include /Fe:F:\~dev\rawrxd\tools\bin\test_o_proj_row_probe.exe F:\~dev\rawrxd\tools\test_o_proj_row_probe.cpp /link /LIBPATH:F:\~dev\rawrxd\build-ninja InferenceEngine.lib bcrypt.lib
exit /b %ERRORLEVEL%
