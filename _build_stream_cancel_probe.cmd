@echo off
REM Build the RAWRXD_STREAM_CANCEL_001 streaming/cancellation probe
REM against the current runtime sources.
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
   tools\stream_cancel_probe.cpp ^
   src\modelgenie\ModelGenieExecutor.cpp ^
   src\modelgenie\ModelGenieRuntime.cpp ^
   src\deep2\modelgenie\ModelGenome.cpp ^
   src\deep2\modelgenie\ModelGenomeReader.cpp ^
   src\tokenizer\gguf_embedded_tokenizer.cpp ^
   /Fe:"%OUTDIR%\stream_cancel_probe.exe"
if errorlevel 1 (
  echo STREAM_PROBE_BUILD_FAILED
  exit /b 2
)
echo STREAM_PROBE_BUILD_OK
exit /b 0
