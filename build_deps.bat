@echo off
set "MINGW=C:\ProgramData\mingw64\mingw64\bin"
set "PATH=%MINGW%;%PATH%"
set "INC=-Isrc -Isrc\engine -Isrc\orchestration -Isrc\metrics -Isrc\ui -Isrc\security"
set "OUT=out\"
cd /d D:\rawrxd-ci-bootstrap

echo === Compiling transformer.cpp ===
g++ -c -std=c++17 -O2 %INC% -o %OUT%transformer.o src\engine\transformer.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1
echo OK

echo === Compiling streaming_gguf_loader.cpp ===
g++ -c -std=c++17 -O2 %INC% -o %OUT%streaming_gguf_loader.o src\streaming_gguf_loader.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1
echo OK

echo === Compiling gguf_loader.cpp ===
g++ -c -std=c++17 -O2 %INC% -o %OUT%gguf_loader.o src\gguf_loader.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1
echo OK

echo === Compiling bpe_tokenizer.cpp ===
g++ -c -std=c++17 -O2 %INC% -o %OUT%bpe_tokenizer.o src\engine\bpe_tokenizer.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1
echo OK

echo === Compiling memory_core.cpp ===
g++ -c -std=c++17 -O2 %INC% -o %OUT%memory_core.o src\memory_core.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1
echo OK

echo === Compiling inference_kernels.cpp ===
g++ -c -std=c++17 -O2 %INC% -o %OUT%inference_kernels.o src\engine\inference_kernels.cpp
if %ERRORLEVEL% NEQ 0 exit /b 1
echo OK

echo === ALL DEPENDENCIES COMPILED ===
