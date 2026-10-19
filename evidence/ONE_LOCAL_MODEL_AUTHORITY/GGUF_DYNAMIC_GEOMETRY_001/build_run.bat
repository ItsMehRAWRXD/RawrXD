@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d G:\~dev\rawrxd
if not exist "evidence\ONE_LOCAL_MODEL_AUTHORITY\GGUF_DYNAMIC_GEOMETRY_001" mkdir "evidence\ONE_LOCAL_MODEL_AUTHORITY\GGUF_DYNAMIC_GEOMETRY_001"
cl /nologo /EHsc /std:c++20 /O2 /I. /Isrc /Isrc\deep2 /Iinclude /Fo"evidence\ONE_LOCAL_MODEL_AUTHORITY\GGUF_DYNAMIC_GEOMETRY_001\\" /Fe"evidence\ONE_LOCAL_MODEL_AUTHORITY\GGUF_DYNAMIC_GEOMETRY_001\gguf_dynamic_geometry_001.exe" certs\gguf_dynamic_geometry_001.cpp src\deep2\GGUFLoader.cpp
echo CL_EXIT=%ERRORLEVEL%
"evidence\ONE_LOCAL_MODEL_AUTHORITY\GGUF_DYNAMIC_GEOMETRY_001\gguf_dynamic_geometry_001.exe"
echo RUN_EXIT=%ERRORLEVEL%
