@echo off
REM Compile the extracted ModelGenie executor translation unit.
setlocal
set VSDev="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
call %VSDev% -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91
set OUTDIR=%~1
if "%OUTDIR%"=="" set OUTDIR=tmp_build_mg
if not exist "%OUTDIR%" mkdir "%OUTDIR%"
cl /nologo /c /EHsc /MD /O2 /Ob2 /std:c++20 /W1 /Zi /permissive- ^
   /I tools ^
   /I tools\..\src ^
   /I tools\..\src\deep2 ^
   /I tools\..\src\deep2\modelgenie ^
   /I . ^
   /I src ^
   /I src\deep2 ^
   /I src\deep2\modelgenie ^
   /I src\modelgenie ^
   /I generated\DeepSeek-V2-Lite-Chat ^
   /Fo"%OUTDIR%\\" ^
   /Fd"%OUTDIR%\mg_exec.pdb" ^
   src\modelgenie\ModelGenieExecutor.cpp 2>&1
exit /b %ERRORLEVEL%
