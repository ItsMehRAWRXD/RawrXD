@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64
cd F:\rawrxd\build_cmake
cmake .. -G "Visual Studio 17 2022" -A x64