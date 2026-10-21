@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 exit /b 1
set INCLUDE=%INCLUDE%;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt
set LIB=%LIB%;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64
cl /EHsc /O2 /std:c++20 /I..\..\src\runtime\memory /I..\..\src b015_residency_debug.cpp ..\..\src\runtime\memory\BlockTable.cpp ..\..\src\runtime\memory\SSDWriteBackQueue.cpp ..\..\src\runtime\memory\DRP_EvictionEngine.cpp ..\..\src\runtime\memory\ResidencyCertification.cpp ..\..\src\runtime\memory\StreamingMatMulResidencyBridge.cpp /Fe:b015_residency_debug.exe
cl /EHsc /O2 /std:c++20 /I..\..\src\runtime\memory /I..\..\src b015_residency_cert_test.cpp ..\..\src\runtime\memory\BlockTable.cpp ..\..\src\runtime\memory\SSDWriteBackQueue.cpp ..\..\src\runtime\memory\DRP_EvictionEngine.cpp ..\..\src\runtime\memory\ResidencyCertification.cpp ..\..\src\runtime\memory\StreamingMatMulResidencyBridge.cpp /Fe:b015_residency_cert_test.exe
