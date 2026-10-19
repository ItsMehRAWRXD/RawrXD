call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd
cl /nologo /EHsc /std:c++20 /O2 /MT /I. /Isrc /Isrc\deep2 /Isrc\deep2\lavapath /Iinclude /Iinclude\core /Fo"G:\~dev\rawrxd\evidence\ONE_LOCAL_MODEL_AUTHORITY\DEEP2_SESSION_PREFILL_001\\" /Fe"G:\~dev\rawrxd\evidence\ONE_LOCAL_MODEL_AUTHORITY\DEEP2_SESSION_PREFILL_001\inproc_probe.exe" "G:\~dev\rawrxd\evidence\ONE_LOCAL_MODEL_AUTHORITY\DEEP2_SESSION_PREFILL_001\inproc_probe.cpp" /link /LIBPATH:build InferenceEngine.lib ws2_32.lib advapi32.lib user32.lib gdi32.lib shell32.lib ole32.lib dxgi.lib d3d12.lib
echo LINK_EXIT=%ERRORLEVEL%
