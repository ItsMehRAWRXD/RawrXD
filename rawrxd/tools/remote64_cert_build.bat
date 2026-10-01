@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 ( echo VCVARS_FAIL & exit /b 1 )

set SRC=%~dp0..\src\remote64
set BUILD=%~dp0..\build_remote64
set OBJ=%BUILD%\obj

if not exist "%OBJ%" mkdir "%OBJ%"

echo === assemble ===
for %%F in ("%SRC%\*.asm") do (
  ml64 /nologo /c /I "%SRC%" /Fo"%OBJ%\%%~nF.obj" "%%F" > "%OBJ%\%%~nF.log" 2>&1
  if errorlevel 1 (
    echo ASM_FAIL %%~nF
    type "%OBJ%\%%~nF.log"
    exit /b 1
  )
)
echo ASM_PASS=64

echo === compile driver ===
if not exist "%BUILD%\bin" mkdir "%BUILD%\bin"
cl /nologo /EHsc /std:c++17 /W3 /O2 /MT /Fo"%BUILD%\bin\\" /Fe"%BUILD%\bin\remote64_cert.exe" ^
   "%~dp0remote64_cert_driver.cpp" ^
   /link /SUBSYSTEM:CONSOLE ^
   "%OBJ%\*.obj" ^
   ws2_32.lib bcrypt.lib user32.lib gdi32.lib kernel32.lib
if errorlevel 1 ( echo LINK_FAIL & exit /b 1 )
echo LINK=PASS
echo EXE=%BUILD%\bin\remote64_cert.exe
exit /b 0
