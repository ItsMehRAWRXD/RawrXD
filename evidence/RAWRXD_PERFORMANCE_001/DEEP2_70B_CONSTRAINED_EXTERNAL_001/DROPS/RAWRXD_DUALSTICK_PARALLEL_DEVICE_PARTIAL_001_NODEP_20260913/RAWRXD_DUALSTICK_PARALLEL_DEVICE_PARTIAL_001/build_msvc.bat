@echo off
setlocal
cl /nologo /std:c++17 /O2 /W4 /WX /permissive- /sdl /EHsc /Iinclude ^
  src\ds_parallel_device_partial.cpp tests\selftest.cpp /Fe:dsdp_selftest.exe
if errorlevel 1 exit /b %errorlevel%
dsdp_selftest.exe
exit /b %errorlevel%
