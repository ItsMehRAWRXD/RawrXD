@echo off
REM Build the isolated DEEP2_RUNTIME_OWNERSHIP_001 ownership test.
REM
REM The executor/runtime sources come from git HEAD (the live tree is under
REM concurrent edit); the Deep2 client shim and the ownership test come from
REM the pinned copies under tools/. This build is intentionally isolated from
REM the DLL's CMake graph: the live src/core/dll/Deep2InferenceAdapter.cpp is
#' deliberately excluded from every build target.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91
cd /d F:\rawrxd
py -3 tools\snapshot_ownership.py
if errorlevel 1 exit /b 92

cd /d F:\rawrxd\tmp_build_owns
if exist obj del /q obj\*.obj
if not exist obj mkdir obj >nul
for %%f in (ModelGenieExecutor ModelGenieRuntime ModelGenome ModelGenomeReader gguf_embedded_tokenizer Deep2RuntimeClient ownership_test_pinned) do (
    cl /nologo /EHsc /O2 /std:c++20 /DNOMINMAX /DWIN32_LEAN_AND_MEAN /c ^
     /I . /I ..\include /I ..\src\deep2 /I ..\src\deep2\modelgenie /I ..\src\modelgenie ^
     /I ..\src\tokenizer /I ..\generated\DeepSeek-V2-Lite-Chat /I ..\tools ^
     %%f.cpp /Fo:obj\%%f.obj > obj\%%f.log 2>&1
    if errorlevel 1 ( echo FAILED %%f & type obj\%%f.log & exit /b 9 )
)
cl /nologo /EHsc /O2 /std:c++20 /DNOMINMAX obj\*.obj /Fe:ownership_test.exe
exit /b %errorlevel%
