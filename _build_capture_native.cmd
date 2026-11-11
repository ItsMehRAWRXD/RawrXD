@echo off
REM Build the native teacher-forced logits capture tool from the CURRENT tree.
REM RAWRXD_CORE_DLL_NATIVE_E2E_001 - independent 64-position differential
REM
REM The tool drives the same mg_* C API the production DLL serves
REM (ModelGenieRuntime), so a capture made with it exercises the production
REM runtime path. Two capture modes exist:
REM   default  - one re-prefill pass per position (O(n^2), historic mode)
REM   --single - one token per generate call, KV grows naturally (O(n))
REM Both modes must agree with each other and with the immutable reference.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91

set OUTDIR=%~1
if "%OUTDIR%"=="" set OUTDIR=tmp_build_cap
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

cd /d F:\rawrxd
cl /nologo /EHsc /MD /O2 /Ob2 /std:c++20 /W1 /DNOMINMAX /DWIN32_LEAN_AND_MEAN /permissive- ^
   /I . /I include /I src /I src\deep2 /I src\deep2\modelgenie /I src\modelgenie ^
   /I src\tokenizer /I tools /I generated\DeepSeek-V2-Lite-Chat ^
   /Fo:"%OUTDIR%\\" ^
   tools\capture_native_logits.cpp ^
   src\modelgenie\ModelGenieExecutor.cpp ^
   src\modelgenie\ModelGenieRuntime.cpp ^
   src\deep2\modelgenie\ModelGenome.cpp ^
   src\deep2\modelgenie\ModelGenomeReader.cpp ^
   src\tokenizer\gguf_embedded_tokenizer.cpp ^
   /Fe:"%OUTDIR%\capture_native_logits.exe"
if errorlevel 1 (
  echo CAPTURE_BUILD_FAILED
  exit /b 2
)
echo CAPTURE_BUILD_OK
exit /b 0
