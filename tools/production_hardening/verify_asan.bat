@echo off
REM Verify the AddressSanitizer path used by .github/workflows/ci.yml compiles
REM and runs locally (so the CI definition is known-good, not aspirational).
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
setlocal enabledelayedexpansion
set ROOT=%CD%
set OUT=%ROOT%\build_asan_check
if not exist "%OUT%" mkdir "%OUT%"

echo === Compiling with /fsanitize=address ^(mirrors ci.yml^) ===
cl.exe /nologo /std:c++20 /EHsc /W4 /permissive- /O1 /fsanitize=address /Zi /Fe:"%OUT%\hardening_asan.exe" /I"%ROOT%\include" /I"%ROOT%\tests" src\utils\input_sanitizer.cpp src\utils\secure_buffer.cpp src\utils\crash_handler.cpp tests\test_input_sanitizer.cpp tests\test_crash_resilience.cpp tests\main_hardening_tests.cpp /link dbghelp.lib bcrypt.lib 2>&1
if errorlevel 1 (
    echo ASAN COMPILE FAILED
    exit /b 1
)

echo === Running under AddressSanitizer ===
"%OUT%\hardening_asan.exe" 2>&1
set RC=%errorlevel%
echo === exit code: %RC% ^(ASan failures also return non-zero^) ===
exit /b %RC%