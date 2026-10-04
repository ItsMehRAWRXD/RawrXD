@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >NUL 2>NUL
cd /d F:\~dev\rawrxd
cl /nologo /std:c++20 /EHsc /O2 /I src /I src\deep2 /I "F:\~dev\_deps\nlohmann_json-src\include" /Fe:F:\~dev\kilo_tmp\gguf_reverse_cursor.exe tools\gguf_reverse_cursor_006.cpp src\deep2\GGUFLoader.cpp src\deep2\QuantKernelRegistry.cpp
echo BUILD_EXIT=%errorlevel%