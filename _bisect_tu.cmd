@echo off
REM Diagnostic: build one TU at a time to find which fails.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul
cd /d F:\rawrxd\tmp_build_owns
cl /nologo /EHsc /O2 /std:c++20 /DNOMINMAX /DWIN32_LEAN_AND_MEAN /c ^
 /I . /I ..\include /I ..\src\deep2 /I ..\src\deep2\modelgenie /I ..\src\modelgenie ^
 /I ..\src\tokenizer /I ..\generated\DeepSeek-V2-Lite-Chat /I ..\tools ^
 ownership_test.cpp ModelGenieRuntime.cpp ModelGenieExecutor.cpp gguf_embedded_tokenizer.cpp
exit /b %errorlevel%
