@echo off
setlocal

echo Building Q4_0 comparison test...

set "CL=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe"
set "INCLUDE=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um"
set "LIB=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"

cd /d "%~dp0"

"%CL%" /std:c++17 /EHsc /O2 /I"..\..\3rdparty\ggml\include" /I"..\..\3rdparty\ggml\src" /DGGML_VERSION=\"1.0.0\" /DGGML_COMMIT=\"abc123\" /Fe:q4_0_llama_comparison.exe q4_0_llama_comparison.cpp "..\..\3rdparty\ggml\src\ggml-quants.c" "..\..\3rdparty\ggml\src\ggml.c" kernels\masm\q4_0_dequant.obj /link

if errorlevel 1 (
    echo Build failed
    exit /b 1
)

echo Build successful!
echo Running test...
q4_0_llama_comparison.exe

pause
