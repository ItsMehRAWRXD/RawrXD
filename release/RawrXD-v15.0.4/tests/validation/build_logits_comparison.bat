@echo off
REM build_logits_comparison.bat
REM Build Phase 1 logits comparison validation with stubs

echo Building Phase 1 logits comparison...

set SRC=d:\rawrxd-ci-bootstrap\tests\validation\logits_comparison.cpp
set STUBS=d:\rawrxd-ci-bootstrap\tests\validation\validation_stubs.cpp
set OUT=d:\rawrxd-ci-bootstrap\tests\validation\logits_comparison.exe

C:\ProgramData\mingw64\mingw64\bin\g++.exe -O2 -Wall -std=c++17 -o %OUT% %SRC% %STUBS%

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    exit /b 1
)

echo Build successful: %OUT%
echo.
echo To run: logits_comparison.exe ^<model.gguf^>
echo (Currently uses stub implementations - perfect match expected)
exit /b 0
