@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
set GGML_SRC=F:\rawrxd\3rdparty\ggml
set GGML_BUILD=F:\rawrxd\build_ggml_profiler
set PATH=%GGML_BUILD%\bin\Release;%PATH%
cl /nologo /std:c++17 /EHsc /O2 /DNOMINMAX /I %GGML_SRC%\include /I F:\rawrxd /I F:\rawrxd\include /I F:\rawrxd\src /I F:\rawrxd\src\deep2 /I F:\rawrxd\src\deep2\modelgenie F:\rawrxd\tools\tmp_mladims.cpp F:\rawrxd\src\deep2\modelgenie\universal_gguf.cpp /FeF:\rawrxd\tools\tmp_mladims.exe /link /LIBPATH:%GGML_BUILD%\src\Release ggml.lib ggml-cpu.lib ggml-base.lib /LIBPATH:%GGML_BUILD%\bin\Release
if errorlevel 1 ( echo BUILD_FAILED & exit /b 1 )
F:\rawrxd\tools\tmp_mladims.exe %1