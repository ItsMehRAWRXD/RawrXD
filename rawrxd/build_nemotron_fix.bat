@echo off
REM Build script for nemotron architecture fix
REM Must be run in "x64 Native Tools Command Prompt for VS 2022"

set SOURCE=src\deep2\Deep2Engine.cpp
set OBJ=build\CMakeFiles\InferenceEngine.dir\src\deep2\Deep2Engine.cpp.obj
set LIBRARY=build\lib\Release\InferenceEngine.lib
set TEST_SRC=src\deep2\test_generate_313_tokens.cpp
set TEST_OBJ=build\CMakeFiles\test_generate_313_tokens.dir\src\deep2\test_generate_313_tokens.cpp.obj
set TEST_EXE=build\bin\Release\test_generate_313_tokens.exe

echo ==========================================
echo Nemotron Fix Build Script
echo ==========================================
echo.

REM Step 1: Compile Deep2Engine.cpp (single file)
echo [1/3] Compiling Deep2Engine.cpp with nemotron_h_moe fix...
cl.exe /nologo /W3 /EHsc /O2 /MD /std:c++20 ^
  /I src\deep2 ^
  /I src ^
  /I include ^
  /D NOMINMAX ^
  /D WIN32_LEAN_AND_MEAN ^
  /c %SOURCE% /Fo%OBJ%

if errorlevel 1 (
  echo ERROR: Failed to compile Deep2Engine.cpp
  exit /b 1
)

REM Step 2: Rebuild the static library
echo [2/3] Rebuilding InferenceEngine.lib...
REM Find all existing object files and rebuild the library
lib.exe /nologo /out:%LIBRARY% build\CMakeFiles\InferenceEngine.dir\src\deep2\*.obj

if errorlevel 1 (
  echo ERROR: Failed to rebuild library
  exit /b 1
)

REM Step 3: Relink test executable
echo [3/3] Relinking test_generate_313_tokens.exe...
cl.exe /nologo /W3 /EHsc /O2 /MD /std:c++20 ^
  %TEST_SRC% ^
  /I src\deep2 ^
  /I src ^
  /I include ^
  /link %LIBRARY% ^
  /out:%TEST_EXE%

if errorlevel 1 (
  echo ERROR: Failed to link test executable
  exit /b 1
)

echo.
echo ==========================================
echo Build complete! Test with:
echo   test_generate_313_tokens.exe "G:\~dev\rawrxd\models\_matrix_f\blobs\sha256-5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3"
echo ==========================================
