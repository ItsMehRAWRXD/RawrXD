@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d f:\~dev\rawrxd
cl /std:c++20 /EHsc /I. /Isrc certification/native_toolchain_cert.cpp src/compiler_backend/*.cpp src/sovereign/puppeteer/*.cpp /Fe:cert_test.exe /O2
