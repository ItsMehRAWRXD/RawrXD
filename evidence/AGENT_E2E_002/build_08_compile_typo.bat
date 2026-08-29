@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cmake --build "F:\~dev\rawrxd\fixtures\agent_e2e_002\08_compile_typo\build"
exit /b %ERRORLEVEL%
