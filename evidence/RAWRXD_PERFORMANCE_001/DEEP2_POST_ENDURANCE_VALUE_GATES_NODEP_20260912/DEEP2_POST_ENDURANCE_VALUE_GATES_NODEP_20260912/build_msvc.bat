@echo off
setlocal
if not exist bin mkdir bin
cl /nologo /std:c++17 /O2 /EHsc /Iinclude src\d2_gen_quality.cpp /Fe:bin\d2_gen_quality.exe
if errorlevel 1 exit /b 1
bin\d2_gen_quality.exe tests\good.txt tests\good.trace.txt
if errorlevel 1 exit /b 2
bin\d2_gen_quality.exe tests\bad.txt tests\good.trace.txt
if not errorlevel 1 exit /b 3
echo DEEP2_POST_ENDURANCE_VALUE_GATES_SELFTEST=PASS
exit /b 0
