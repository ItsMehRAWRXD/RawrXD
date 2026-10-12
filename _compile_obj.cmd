@echo off
REM Compile ModelGenieExecutor.cpp straight into the shared object dir.
setlocal
set VSDEV=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat
call "%VSDEV%" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91

set OBJ=%~1
if "%OBJ%"=="" set OBJ=tmp_build_mg\obj
if not exist "%OBJ%" mkdir "%OBJ%" >nul

cl /nologo /c /EHsc /MD /O2 /Ob2 /std:c++20 /W1 /permissive- ^
   /I . /I src /I src\deep2 /I src\deep2\modelgenie /I src\modelgenie ^
   /I tools /I generated\DeepSeek-V2-Lite-Chat /I src\tokenizer ^
   /Fo"%OBJ%\\" /Fd"%OBJ%\mg_exec.pdb" ^
   src\modelgenie\ModelGenieExecutor.cpp
exit /b %ERRORLEVEL%
