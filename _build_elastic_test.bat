@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe" /std:c++17 /EHsc /nologo /I F:\~dev\rawrxd\src\deep2 /FeF:\~dev\_elastic_test.exe F:\~dev\rawrxd\src\deep2\ElasticResidencyManager.cpp F:\~dev\rawrxd\src\deep2\ElasticResidencyManager_test.cpp > F:\~dev\_elastic_build.txt 2>&1
