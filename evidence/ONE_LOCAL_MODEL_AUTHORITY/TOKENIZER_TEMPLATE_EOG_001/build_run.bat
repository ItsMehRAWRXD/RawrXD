@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd
cl /nologo /EHsc /std:c++20 /O2 /I. /Isrc /Isrc\deep2 /Iinclude /Fo"evidence\ONE_LOCAL_MODEL_AUTHORITY\TOKENIZER_TEMPLATE_EOG_001\\" /Fe"evidence\ONE_LOCAL_MODEL_AUTHORITY\TOKENIZER_TEMPLATE_EOG_001\tokenizer_template_eog_001.exe" certs\tokenizer_template_eog_001.cpp src\deep2\GGUFLoader.cpp
echo CL_EXIT=%ERRORLEVEL%
if errorlevel 1 exit /b 1
"evidence\ONE_LOCAL_MODEL_AUTHORITY\TOKENIZER_TEMPLATE_EOG_001\tokenizer_template_eog_001.exe"
echo RUN_EXIT=%ERRORLEVEL%
