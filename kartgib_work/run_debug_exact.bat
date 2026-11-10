@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
F:\rawrxd\kartgib_work\debug_streaming_exact.exe
echo EXIT_CODE=%ERRORLEVEL%
