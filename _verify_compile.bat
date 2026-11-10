@echo off
setlocal
set MSVC_INC="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\include"
set UCRT="C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt"
set UM="C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um"
set SHARED="C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared"
set INCLUDES=-I"F:\rawrxd\include" -I"F:\rawrxd\src" -I"F:\rawrxd\src\deep2" -I"F:\rawrxd\3rdparty\ggml\include" -I"F:\rawrxd\3rdparty\ggml\src" -I%MSVC_INC% -I%UCRT% -I%UM% -I%SHARED%
set FLAGS=/nologo /Zs /c /std:c++20 /DNOMINMAX /D_WIN32_WINNT=0x0A00 /D_CRT_SECURE_NO_WARNINGS
set CL="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe"

echo === Compiling gguf_loader.cpp ===
%CL% %FLAGS% %INCLUDES% F:\rawrxd\src\gguf_loader.cpp 2>&1
echo === Compiling streaming_gguf_loader.cpp ===
%CL% %FLAGS% %INCLUDES% F:\rawrxd\src\streaming_gguf_loader.cpp 2>&1
echo === Compiling QuantKernelRegistry.cpp ===
%CL% %FLAGS% %INCLUDES% F:\rawrxd\src\deep2\QuantKernelRegistry.cpp 2>&1
echo DONE
