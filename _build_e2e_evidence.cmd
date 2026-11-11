@echo off
REM Build the E2E evidence tool.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91
cd /d F:\rawrxd
if not exist tmp_build_e2e\obj_e2e mkdir tmp_build_e2e\obj_e2e >nul
cl /nologo /EHsc /O2 /std:c++20 /Fo:tmp_build_e2e\obj_e2e\ ^
 /I src /I src\modelgenie /I src\deep2 /I src\deep2\modelgenie /I include ^
 /I generated\DeepSeek-V2-Lite-Chat /I tools /I tmp_llama-clone\include ^
 tools\e2e_evidence.cpp src\modelgenie\ModelGenieExecutor.cpp ^
 src\deep2\modelgenie\ModelGenome.cpp src\deep2\modelgenie\ModelGenomeReader.cpp ^
 /Fe:tmp_build_e2e\e2e_evidence.exe
exit /b %errorlevel%
