@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

set INCLUDES=/I "f:\~dev\rawrxd\include" /I "f:\~dev\rawrxd\src\deep2" /I "f:\~dev\rawrxd\src\tokenizer" /I "f:\~dev\rawrxd\src" /I "f:\~dev\rawrxd\src\inference" /I "f:\~dev\rawrxd\src\engine" /I "f:\~dev\rawrxd\src\core" /I "f:\~dev\rawrxd\src\codec" /I "f:\~dev\rawrxd\src\masm" /I "f:\~dev\rawrxd\src\runtime\governance" /I "C:\VulkanSDK\1.4.357.0\Include"

set LIBS="F:\~dev\rawrxd\build\Release\InferenceEngine.lib" "C:\VulkanSDK\1.4.357.0\Lib\vulkan-1.lib" kernel32.lib user32.lib

cl.exe /nologo /EHsc /W4 /std:c++20 /arch:AVX512 /O2 %INCLUDES% "f:\~dev\rawrxd\src\deep2\test_generate_313_tokens.cpp" /Fe"f:\~dev\rawrxd\build\bin\Release\test_generate_313_tokens.exe" /link %LIBS%

