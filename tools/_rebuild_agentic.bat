@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d F:\~dev\rawrxd\build-ninja
cmake --build . --target InferenceEngine RawrXD-Agentic -j 8
exit /b %ERRORLEVEL%
