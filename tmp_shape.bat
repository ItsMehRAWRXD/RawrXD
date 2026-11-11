@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
cl /nologo /std:c++17 /EHsc /O2 /DNOMINMAX /I F:\rawrxd\src F:\rawrxd\tmp_shape.cpp F:\rawrxd\src\GGUFLoader.cpp /FeF:\rawrxd\tmp_shape.exe /link >nul 2>&1
if errorlevel 1 ( echo BUILD_FAILED & exit /b 1 )
F:\rawrxd\tmp_shape.exe "F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"