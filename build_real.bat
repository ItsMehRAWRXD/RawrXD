@echo off
REM build_real.bat — Build all real implementation files
REM Run from any directory, uses full paths

set GCC=C:\ProgramData\mingw64\mingw64\bin\g++.exe
set SRC=d:\rawrxd-ci-bootstrap\src
set OUT=d:\rawrxd-ci-bootstrap\build\bin
set INC=-I%SRC% -I%SRC%\engine

echo Building cpu_inference_engine_real.cpp...
"%GCC%" -c -O2 -std=c++17 %INC% -o %OUT%\cpu_inference_engine_real.o %SRC%\cpu_inference_engine_real.cpp
if %ERRORLEVEL% equ 0 (echo   OK) else (echo   FAILED)

echo Building AIRuntime.cpp...
"%GCC%" -c -O2 -std=c++17 %INC% -o %OUT%\AIRuntime.o %SRC%\engine\AIRuntime\AIRuntime.cpp
if %ERRORLEVEL% equ 0 (echo   OK) else (echo   FAILED)

echo Building RealGGUFInference.cpp...
"%GCC%" -c -O2 -std=c++17 %INC% -o %OUT%\RealGGUFInference.o %SRC%\engine\AIRuntime\RealGGUFInference.cpp
if %ERRORLEVEL% equ 0 (echo   OK) else (echo   FAILED)

echo.
echo All builds complete.
dir %OUT%\*.o 2>nul
