@echo off
REM Build the RAWRXD ownership test from the extracted feat/hexmag sources
REM (DEEP2_RUNTIME_OWNERSHIP_001): the live tree is temporarily on another
REM branch, so the sources are extracted from the certified commit.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91

set SRC=F:\rawrxd_owns_src
set OUT=F:\rawrxd\tmp_build_owns2
if not exist "%OUT%" mkdir "%OUT%"

cd /d %SRC%
cl /nologo /EHsc /MD /O2 /Ob2 /std:c++20 /W1 /DNOMINMAX /DWIN32_LEAN_AND_MEAN /permissive- ^
   /I . /I include /I src /I src\deep2 /I src\deep2\modelgenie /I src\modelgenie ^
   /I src\tokenizer /I tools /I generated\DeepSeek-V2-Lite-Chat ^
   /Fo:"%OUT%\\" ^
   tools\ownership_test_pinned.cpp ^
   tools\Deep2RuntimeClient.cpp ^
   src\modelgenie\ModelGenieExecutor.cpp ^
   src\modelgenie\ModelGenieRuntime.cpp ^
   src\deep2\modelgenie\ModelGenome.cpp ^
   src\deep2\modelgenie\ModelGenomeReader.cpp ^
   src\tokenizer\gguf_embedded_tokenizer.cpp ^
   /Fe:"%OUT%\ownership_test.exe"
if errorlevel 1 (
  echo OWNERSHIP_BUILD_FAILED
  exit /b 2
)
echo OWNERSHIP_BUILD_OK
exit /b 0
