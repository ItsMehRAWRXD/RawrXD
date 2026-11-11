@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64
if errorlevel 1 exit /b 1

cl /nologo /std:c++20 /EHsc /W4 /I src/deep2 /Fe:q5_0_decoder_reference.exe tests/q5_0_decoder_reference.cpp
if errorlevel 1 exit /b 1

q5_0_decoder_reference.exe
if errorlevel 1 exit /b 1

echo q5_0_decoder_reference passed