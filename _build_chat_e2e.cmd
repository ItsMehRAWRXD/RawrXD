@echo off
REM RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001 - native IDE chat end-to-end
setlocal
set VSDEV=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat
call "%VSDEV%" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91

set OBJ=%~1
if "%OBJ%"=="" set OBJ=tmp_build_mg\obj

cl /nologo /c /EHsc /MD /O2 /std:c++20 /W1 /permissive- ^
   /DNOMINMAX /DWIN32_LEAN_AND_MEAN ^
   /I . /I include /I src /I src\core /I src\core\dll /I src\deep2 ^
   /I src\deep2\modelgenie /I src\modelgenie /I src\tokenizer ^
   /I tools /I generated\DeepSeek-V2-Lite-Chat /I "%OBJ%" ^
   /Fo"%OBJ%\\" /Fd"%OBJ%\chat_e2e.pdb" ^
   tools\mg_chat_e2e.cpp
if errorlevel 1 (
  echo COMPILE_FAILED
  exit /b 1
)

cl /nologo /EHsc /MD /O2 /std:c++20 ^
   /I . /I include /I src /I src\deep2 ^
   /Fe:"%OBJ%\..\mg_chat_e2e.exe" ^
   "%OBJ%\mg_chat_e2e.obj" ^
   "%OBJ%\cpu_inference_engine.obj" ^
   "%OBJ%\ModelGenieExecutor.obj" ^
   "%OBJ%\ModelGenieRuntime.obj" ^
   "%OBJ%\gguf_embedded_tokenizer.obj" ^
   "%OBJ%\ModelGenome.obj" ^
   "%OBJ%\ModelGenomeReader.obj" ^
   /link
if errorlevel 1 (
  echo LINK_FAILED
  exit /b 2
)
echo BUILD_OK
