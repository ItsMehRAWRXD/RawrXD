@echo off
REM Build the isolated authority-only bisect (no adapter) to localize the crash.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91
cd /d F:\rawrxd\tmp_build_owns
cl /nologo /EHsc /O2 /std:c++20 /DNOMINMAX /DWIN32_LEAN_AND_MEAN ^
 /I . /I ..\include /I ..\src\deep2 /I ..\src\deep2\modelgenie /I ..\src\modelgenie ^
 /I ..\src\tokenizer /I ..\generated\DeepSeek-V2-Lite-Chat /I ..\tools ^
 authority_bisect.cpp ModelGenieExecutor.cpp ModelGenieRuntime.cpp ^
 ModelGenome.cpp ModelGenomeReader.cpp gguf_embedded_tokenizer.cpp ^
 /Fe:auth_bisect.exe > build_auth.txt 2>&1
echo BUILD_EXIT=%errorlevel%
findstr /C:"error" build_auth.txt
exit /b 0
