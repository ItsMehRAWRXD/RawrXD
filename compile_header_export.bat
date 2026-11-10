@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl /std:c++20 /O2 /W4 /EHsc /I "F:\rawrxd\src\deep2\modelgenie" /I "F:\rawrxd\src" /I "F:\rawrxd\include" /I "F:\rawrxd\generated\DeepSeek-V2-Lite-Chat" "F:\rawrxd\tools\rawrxd_modelgenie_header_export.cpp" /Fe"F:\rawrxd\build-modelgenie-tools\bin\rawrxd_modelgenie_header_export.exe" > "F:\rawrxd\evidence\header_export_compile.log" 2>&1
echo Compile EXIT=%ERRORLEVEL%