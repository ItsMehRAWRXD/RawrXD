@echo off
REM RAWRXD tokenizer parity - compile gguf_embedded_tokenizer.cpp into the object dir
setlocal
set VSDEV=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat
call "%VSDEV%" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91

set OBJ=%~1
if "%OBJ%"=="" set OBJ=tmp_build_mg\obj
if not exist "%OBJ%" mkdir "%OBJ%" >nul

cl /nologo /c /EHsc /MD /O2 /Ob2 /std:c++20 /W1 /permissive- ^
   /DNOMINMAX /DWIN32_LEAN_AND_MEAN ^
   /I . /I include /I src /I src\tokenizer /I src\deep2 /I src\modelgenie ^
   /I generated\DeepSeek-V2-Lite-Chat ^
   /Fo"%OBJ%\\" /Fd"%OBJ%\tok.pdb" ^
   src\tokenizer\gguf_embedded_tokenizer.cpp
exit /b %ERRORLEVEL%
