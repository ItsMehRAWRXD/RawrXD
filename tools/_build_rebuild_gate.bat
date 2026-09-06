@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d F:\~dev\rawrxd
if not exist tools\bin mkdir tools\bin
cl /nologo /std:c++20 /EHsc /O2 /I src\deep2 /I src\tokenizer /Fe:tools\bin\tokenizer_rebuild_gate.exe tools\tokenizer_rebuild_gate.cpp /link bcrypt.lib
exit /b %ERRORLEVEL%
