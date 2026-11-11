@echo off
REM RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001 - DLL logit parity harness
REM Compares the DLL's ModelGenie-driven logits against the standalone
%% ModelGenie IR executor for the same GGUF / token / position / cache state.
setlocal
set VSDEV=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat
call "%VSDEV%" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91

set OUT=%~1
if "%OUT%"=="" set OUT=tmp_build_mg
if not exist "%OUT%\obj" mkdir "%OUT%\obj" >nul

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
 /I "%OUT%" ^
 /I C:\VulkanSDK\1.4.357.0\Include

echo [1/2] compiling parity harness
cl /nologo /c /EHsc /MD /O2 /std:c++20 /W1 /permissive- ^
   /DNOMINMAX /DWIN32_LEAN_AND_MEAN ^
   %INC% ^
   /Fo"%OUT%\obj\\" /Fd"%OUT%\obj\parity.pdb" ^
   tools\dll_parity_main.cpp
if errorlevel 1 (
  echo COMPILE_FAILED
  exit /b 1
)

echo [2/2] linking
cl /nologo /EHsc /MD /O2 /std:c++20 ^
   %INC% ^
   /Fe"%OUT%\dll_parity.exe" ^
   "%OUT%\obj\dll_parity_main.obj" ^
   "%OUT%\obj\ModelGenieExecutor.obj" ^
   /link /LIBPATH:"%OUT%\obj" RawrXDCore.lib user32.lib
if errorlevel 1 (
  echo LINK_FAILED
  exit /b 2
)
echo BUILD_OK
exit /b 0
