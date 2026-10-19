@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd
cl /nologo /EHsc /std:c++20 /O2 /I. /Isrc /Isrc\deep2 /Iinclude /Fe"G:\~dev\rawrxd\evidence\ONE_LOCAL_MODEL_AUTHORITY\DEEP2_SESSION_PREFILL_001\link_probe.exe" "G:\~dev\rawrxd\evidence\ONE_LOCAL_MODEL_AUTHORITY\DEEP2_SESSION_PREFILL_001\link_probe.cpp" /link /LIBPATH:build-ninja-infer InferenceEngine.lib
echo LINK_EXIT=%ERRORLEVEL%
