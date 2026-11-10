call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /nologo /std:c++20 /W4 /EHsc /O2 /I"F:\rawrxd\src" /I"F:\rawrxd\3rdparty" "F:\rawrxd\tmp_audit_gguf.cpp" /Fe"F:\rawrxd\tmp_build\audit_gguf.exe"
