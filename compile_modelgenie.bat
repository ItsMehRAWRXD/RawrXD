@echo off
cd /d F:\rawrxd
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /nologo /std:c++20 /W4 /WX- /EHsc /O2 ^
    /I "F:\rawrxd\src" ^
    /I "F:\rawrxd\include" ^
    /I "F:\rawrxd\src\deep2" ^
    /I "F:\rawrxd\src\deep2\modelgenie" ^
    "F:\rawrxd\tools\rawrxd_modelgenie_header_export.cpp" ^
    "F:\rawrxd\src\deep2\modelgenie\ModelGenomeReader.cpp" ^
    "F:\rawrxd\src\deep2\modelgenie\ModelGenome.cpp" ^
    "F:\rawrxd\src\deep2\modelgenie\HeaderEmitter.cpp" ^
    "F:\rawrxd\src\deep2\modelgenie\ModelGenomeValidator.cpp" ^
    /Fe"F:\rawrxd\tmp_build\modelgenie_header_export.exe"