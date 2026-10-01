@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 ( echo VCVARS_FAIL & exit /b 1 )
set OBJ=%~dp0..\build_remote64\obj
if not exist "%~dp0..\build_remote64\bin" mkdir "%~dp0..\build_remote64\bin"
ml64 /nologo /c /I "%~dp0..\src\remote64" /Fo"%OBJ%\aead.obj" "%~dp0..\src\remote64\aead.asm" >nul 2>&1
if errorlevel 1 ( echo AASM_FAIL & exit /b 1 )
cl /nologo /EHsc /std:c++17 /O2 /MT /Fo"%~dp0..\build_remote64\bin\\" ^
   /Fe"%~dp0..\build_remote64\bin\aead_probe.exe" ^
   "%~dp0remote64_aead_probe.cpp" ^
   /link /SUBSYSTEM:CONSOLE "%OBJ%\aead.obj" "%OBJ%\memory.obj" bcrypt.lib kernel32.lib
if errorlevel 1 ( echo LINK_FAIL & exit /b 1 )
echo LINK=PASS
"%~dp0..\build_remote64\bin\aead_probe.exe"
exit /b %errorlevel%
