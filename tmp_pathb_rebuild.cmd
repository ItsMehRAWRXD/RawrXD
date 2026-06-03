@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b %errorlevel%
cmake --build d:\rawrxd\build_ggufplan --target RawrXD-InferenceSmoke --clean-first -- -j1
if errorlevel 1 exit /b %errorlevel%
d:\rawrxd\build_ggufplan\bin\RawrXD-InferenceSmoke.exe D:\phi3mini.gguf
exit /b %errorlevel%
