@echo off
REM Establish a clean MSVC build of the standalone ModelGenie IR executor.
REM RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001 - baseline build

setlocal enabledelayedexpansion
set VSDev="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
if not exist %VSDev% (
  echo ERROR: VsDevCmd.bat not found at %VSDev%
  exit /b 90
)

call %VSDev% -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 (
  echo ERROR: vcvarsall failed
  exit /b 91
)

set OUTDIR=%~1
if "%OUTDIR%"=="" set OUTDIR=tmp_build_mg

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

cl /nologo /c /EHsc /MD /O2 /Ob2 /std:c++20 /W1 /Zi ^
   /I tools ^
   /I tools\..\src ^
   /I tools\..\src\deep2 ^
   /I tools\..\src\deep2\modelgenie ^
   /I . ^
   /I src ^
   /I src\deep2 ^
   /I src\deep2\modelgenie ^
   /I generated\DeepSeek-V2-Lite-Chat ^
   /I tools\build_token0\src\deep2\modelgenie ^
   /I src\modelgenie ^
   /Fo"%OUTDIR%\\" ^
   /Fd"%OUTDIR%\mg_ir_exec.pdb" ^
   src\modelgenie\ModelGenieExecutor.cpp
if errorlevel 1 (
  echo LIB_COMPILE_FAILED
  exit /b 3
)

cl /nologo /c /EHsc /MD /O2 /Ob2 /std:c++20 /W1 /Zi ^
   /I . ^
   /I src ^
   /I src\deep2 ^
   /I src\deep2\modelgenie ^
   /I src\modelgenie ^
   /I generated\DeepSeek-V2-Lite-Chat ^
   /Fo"%OUTDIR%\\" ^
   /Fd"%OUTDIR%\mg_ir_exec.pdb" ^
   tools\rawrxd_modelgenie_ir_executor.cpp
if errorlevel 1 (
  echo TOOL_COMPILE_FAILED
  exit /b 4
)

cl /nologo /EHsc /MD /O2 /std:c++20 ^
   /Fo"%OUTDIR%\\" ^
   "%OUTDIR%\rawrxd_modelgenie_ir_executor.obj" ^
   "%OUTDIR%\ModelGenieExecutor.obj" ^
   src\deep2\modelgenie\ModelGenome.cpp ^
   src\deep2\modelgenie\ModelGenomeReader.cpp ^
   /Fe"%OUTDIR%\rawrxd_modelgenie_ir_executor.exe" ^
   /link
if errorlevel 1 (
  echo LINK_FAILED
  exit /b 2
)

echo BUILD_OK
exit /b 0
