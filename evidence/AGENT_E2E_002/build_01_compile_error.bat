@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cmake --build "F:\~dev\rawrxd\fixtures\agent_e2e_002\01_compile_error\build"
exit /b %ERRORLEVEL%
