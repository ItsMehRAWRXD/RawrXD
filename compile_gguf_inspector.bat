@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl /std:c++20 /O2 /EHsc /I "F:\rawrxd\src\deep2\modelgenie" /I "F:\rawrxd\src" /I "F:\rawrxd\include" /I "F:\rawrxd\generated\DeepSeek-V2-Lite-Chat" "F:\rawrxd\tools\gguf_inspector.cpp" /Fe"F:\rawrxd\build-modelgenie-tools\bin\gguf_inspector.exe" > "F:\rawrxd\evidence\gguf_inspector_compile.log" 2>&1
echo Compile EXIT=%ERRORLEVEL%