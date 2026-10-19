@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd
cl /nologo /EHsc /std:c++20 /O2 /I. /Isrc /Isrc\deep2 /Iinclude /Fo"evidence\ONE_LOCAL_MODEL_AUTHORITY\\" /Fe"evidence\ONE_LOCAL_MODEL_AUTHORITY\probe_tensors.exe" evidence\ONE_LOCAL_MODEL_AUTHORITY\probe_tensors.cpp src\deep2\GGUFLoader.cpp
if errorlevel 1 exit /b 1
"evidence\ONE_LOCAL_MODEL_AUTHORITY\probe_tensors.exe" > "evidence\ONE_LOCAL_MODEL_AUTHORITY\probe_tensors.out"
echo EXIT=%ERRORLEVEL%
