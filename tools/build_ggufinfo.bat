@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl /std:c++20 /EHsc /O2 /W3 /nologo /I F:\rawrxd\include /I F:\rawrxd\src\gguf ^
  /FeF:\rawrxd\tmp_build\ggufinfo.exe ^
  F:\rawrxd\tools\ggufinfo.cpp ^
  F:\rawrxd\src\gguf\RawrXDGgufReader.cpp
