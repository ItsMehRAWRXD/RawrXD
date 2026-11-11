@echo off
REM RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001 - dequantized weight dumper
setlocal
set VSDEV=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat
call "%VSDEV%" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91

set OBJ=%~1
if "%OBJ%"=="" set OBJ=tmp_build_mg\obj
set DEST=%~2
if "%DEST%"=="" set DEST=tmp_build_mg\
if not exist "%OBJ%" mkdir "%OBJ%" >nul

cl /nologo /c /EHsc /MD /O2 /std:c++20 /W1 /permissive- ^
   /DNOMINMAX /DWIN32_LEAN_AND_MEAN ^
   /I . /I src /I src\deep2 /I src\deep2\modelgenie /I src\modelgenie ^
   /I tools /I generated\DeepSeek-V2-Lite-Chat /I src\tokenizer ^
   /Fo"%OBJ%\\" /Fd"%OBJ%\dump.pdb" ^
   tools\dump_weight.cpp
if errorlevel 1 (
  echo COMPILE_FAILED
  exit /b 1
)

cl /nologo /EHsc /MD /O2 /std:c++20 ^
   /I . /I src /I src\deep2 ^
   /Fe:"%DEST%\dump_weight.exe" ^
   "%OBJ%\dump_weight.obj" ^
   "%OBJ%\ModelGenieExecutor.obj" ^
   "%OBJ%\ModelGenome.obj" ^
   "%OBJ%\ModelGenomeReader.obj" ^
   /link
if errorlevel 1 (
  echo LINK_FAILED
  exit /b 2
)
echo BUILD_OK
