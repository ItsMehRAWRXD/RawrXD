@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001 || exit /b 1
cl /nologo /TP /EHsc /std:c++latest /MT /O2 /arch:AVX512 /GS- /W0 /DWIN32 /D_WINDOWS /DNOMINMAX /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS /DNDEBUG /IG:\~dev\rawrxd\include /IG:\~dev\rawrxd\src /IG:\~dev\rawrxd\src\deep2 /IG:\~dev\rawrxd\src\inference /Fo_probe_ffn_down_10_q4.obj /Fe_probe_ffn_down_10_q4.exe _probe_ffn_down_10_q4.cpp /link /nologo /LIBPATH:G:\~dev\rawrxd\build_ninja InferenceEngine.lib
echo CL_EXIT=%ERRORLEVEL%
if errorlevel 1 exit /b 1
_probe_ffn_down_10_q4.exe
echo PROBE_EXIT=%ERRORLEVEL%
exit /b %ERRORLEVEL%
