@echo off
REM Build RawrXDCore.dll with the ModelGenie runtime linked in.
setlocal
set VSDEV=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat
call "%VSDEV%" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91

set OBJ=%~1
if "%OBJ%"=="" set OBJ=tmp_build_mg\obj
set DEST=%~2
if "%DEST%"=="" set DEST=tmp_build_mg\

if not exist "%OBJ%" mkdir "%OBJ%" >nul

set INC=/I . ^
 /I include ^
 /I src ^
 /I src\core ^
 /I src\core\dll ^
 /I src\deep2 ^
 /I src\deep2\modelgenie ^
 /I src\modelgenie ^
 /I src\tokenizer ^
 /I tools ^
 /I generated\DeepSeek-V2-Lite-Chat ^
 /I "%DEST%" ^
 /I C:\VulkanSDK\1.4.357.0\Include

echo [1/2] compiling
cl /nologo /c /EHsc /MD /O2 /std:c++20 /W1 /permissive- ^
   /DRAWRXD_CORE_DLL_BUILD /DRawrXDCore_EXPORTS /DRAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001 ^
   /DNOMINMAX /DWIN32_LEAN_AND_MEAN ^
   %INC% ^
   /Fo"%OBJ%\\" /Fd"%OBJ%\rawrxd.pdb" ^
   src\core\dll\RawrXDCore.cpp ^
   src\modelgenie\ModelGenieExecutor.cpp ^
   src\modelgenie\ModelGenieRuntime.cpp ^
   src\tokenizer\gguf_embedded_tokenizer.cpp ^
   src\core\dll\Deep2InferenceAdapter.cpp ^
   src\cpu_inference_engine.cpp ^
   src\GGUFLoader.cpp ^
   src\deep2\modelgenie\ModelGenome.cpp ^
   src\deep2\modelgenie\ModelGenomeReader.cpp
if errorlevel 1 (
  echo COMPILE_FAILED
  exit /b 1
)

echo [2/2] linking
for %%F in (RawrXDCore ModelGenieExecutor ModelGenieRuntime gguf_embedded_tokenizer Deep2InferenceAdapter cpu_inference_engine GGUFLoader ModelGenome ModelGenomeReader) do (
  if not exist "%OBJ%\%%F.obj" (
    echo MISSING %OBJ%\%%F.obj
    exit /b 3
  )
)
cl /nologo /EHsc /MD /O2 /std:c++20 ^
   %INC% ^
   /LD ^
   /Fe"%OBJ%\\" ^
   "%OBJ%\RawrXDCore.obj" ^
   "%OBJ%\ModelGenieExecutor.obj" ^
   "%OBJ%\ModelGenieRuntime.obj" ^
   "%OBJ%\gguf_embedded_tokenizer.obj" ^
   "%OBJ%\Deep2InferenceAdapter.obj" ^
   "%OBJ%\cpu_inference_engine.obj" ^
   "%OBJ%\GGUFLoader.obj" ^
   "%OBJ%\ModelGenome.obj" ^
   "%OBJ%\ModelGenomeReader.obj" ^
   /link psapi.lib
if errorlevel 1 (
  echo LINK_FAILED
  exit /b 2
)
copy /y "%OBJ%\RawrXDCore.dll" "%DEST%\" >nul
echo BUILD_OK
exit /b 0
