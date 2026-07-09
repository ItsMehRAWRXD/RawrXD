@echo off
REM Build script for Embedding Lookup (Step C3)

echo ========================================
echo Building Embedding Lookup Test Suite
echo ========================================

set CXX=C:\ProgramData\mingw64\mingw64\bin\g++.exe
set INCLUDES=-I. -I.. -I../..
set FLAGS=-std=c++17 -O2 -mavx2 -mfma -Wall

echo Compiling embedding_lookup.cpp...
%CXX% %FLAGS% %INCLUDES% -c embedding_lookup.cpp -o embedding_lookup.obj
if errorlevel 1 (
    echo FAILED: embedding_lookup.cpp
    exit /b 1
)

echo Compiling test_embedding_lookup.cpp...
%CXX% %FLAGS% %INCLUDES% -c test_embedding_lookup.cpp -o test_embedding_lookup.obj
if errorlevel 1 (
    echo FAILED: test_embedding_lookup.cpp
    exit /b 1
)

echo Linking test executable...
%CXX% %FLAGS% -o test_embedding_lookup.exe embedding_lookup.obj test_embedding_lookup.obj ..
..\model\model_context.obj ..
..\runtime\tokenizer_runtime.obj
if errorlevel 1 (
    echo FAILED: Linking
    exit /b 1
)

echo.
echo ========================================
echo Build successful!
echo ========================================
echo.
echo Running tests...
test_embedding_lookup.exe
