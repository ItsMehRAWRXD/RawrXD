@echo off
setlocal
cl /nologo /std:c++17 /EHsc /O2 d2_request_compiler.cpp selftest.cpp /Fe:d2_request_compiler_selftest.exe
if errorlevel 1 exit /b 1
d2_request_compiler_selftest.exe
if errorlevel 1 exit /b 1

cl /nologo /std:c11 /TC /c c_api_selftest.c /Fo:c_api_selftest.obj
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /EHsc /O2 /c d2_request_compiler.cpp /Fo:d2_request_compiler.obj
if errorlevel 1 exit /b 1
link /nologo d2_request_compiler.obj c_api_selftest.obj /OUT:d2_request_compiler_c_abi_selftest.exe
if errorlevel 1 exit /b 1
d2_request_compiler_c_abi_selftest.exe
exit /b %errorlevel%
