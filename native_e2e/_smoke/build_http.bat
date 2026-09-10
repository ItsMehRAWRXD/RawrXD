@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "G:\~dev\rawrxd\native_e2e"
cl /nologo /EHsc /O2 /DWIN32 /D_CRT_SECURE_NO_WARNINGS /I. /Fo"G:\~dev\rawrxd\native_e2e\_smoke\\" /Fe"G:\~dev\rawrxd\native_e2e\_smoke\native_prepare_http_smoke.exe" native_prepare_http_smoke.cpp rawr_native_http_adapter.cpp runtime_gguf_roots.cpp runtime_gguf_disk_resolve.cpp runtime_gguf_disk_try.cpp native_prepare_smoke_stubs.cpp /link /SUBSYSTEM:CONSOLE kernel32.lib ws2_32.lib
echo CL_EXIT=%ERRORLEVEL%
