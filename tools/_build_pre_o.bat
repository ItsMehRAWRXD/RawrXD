@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d F:\~dev\rawrxd
cl /nologo /std:c++20 /EHsc /O2 /arch:AVX2 /I src\deep2 /I include /Fe:tools\bin\test_pre_o_expand_authority.exe tools\test_pre_o_expand_authority.cpp /link /LIBPATH:build-ninja InferenceEngine.lib
exit /b %ERRORLEVEL%
