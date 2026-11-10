@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
cl /std:c++20 /I F:\rawrxd\kartgib_work\merged\src /EHsc /O2 F:\rawrxd\kartgib_work\merged\tests\streaming_tests.cpp F:\rawrxd\kartgib_work\merged\src\streaming\streaming.cpp /Fe:F:\rawrxd\kartgib_work\debug_streaming_exact.exe
F:\rawrxd\kartgib_work\debug_streaming_exact.exe
