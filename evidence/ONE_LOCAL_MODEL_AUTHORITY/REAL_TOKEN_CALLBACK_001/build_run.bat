@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd
set OUT=evidence\ONE_LOCAL_MODEL_AUTHORITY\REAL_TOKEN_CALLBACK_001
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /EHsc /std:c++20 /O2 /I. /Isrc /Isrc\deep2 /Iinclude /Fo"%OUT%\\" /Fe"%OUT%\real_token_callback_001.exe" certs\real_token_callback_001.cpp src\deep2\GGUFLoader.cpp
if errorlevel 1 exit /b 1
"%OUT%\real_token_callback_001.exe"
echo RUN_EXIT=%ERRORLEVEL%
