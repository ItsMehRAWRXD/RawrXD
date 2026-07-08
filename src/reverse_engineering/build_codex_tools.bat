@echo off
REM Build Codex Tools (Fuzzing, Corpus Validator, IDE Integration)
setlocal

set "CL_EXE=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe"
set "LINK_EXE=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"

set "SDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "SDK_VER=10.0.22621.0"
set "MSVC_ROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"

set "INCLUDE=%MSVC_ROOT%\include;%SDK_ROOT%\Include\%SDK_VER%\ucrt;%SDK_ROOT%\Include\%SDK_VER%\um;%SDK_ROOT%\Include\%SDK_VER%\shared"
set "LIB=%MSVC_ROOT%\lib\x64;%SDK_ROOT%\Lib\%SDK_VER%\ucrt\x64;%SDK_ROOT%\Lib\%SDK_VER%\um\x64"

set "SRC_DIR=d:\rawrxd\src\reverse_engineering"
set "ASM_DIR=d:\rawrxd\src\asm"
set "BUILD_DIR=d:\rawrxd\build_codex_tools"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/6] Compiling fuzzing harness...
"%CL_EXE%" /EHsc /std:c++17 /W4 /O2 /I"%SRC_DIR%" /Fo"%BUILD_DIR%\codex_fuzz_harness.obj" /c "%SRC_DIR%\codex_fuzz_harness.cpp"
if errorlevel 1 (
    echo ERROR: Fuzzing harness compilation failed
    exit /b 1
)

echo [2/6] Linking fuzzing harness...
"%LINK_EXE%" /SUBSYSTEM:CONSOLE /LARGEADDRESSAWARE:NO /OUT:"%BUILD_DIR%\codex_fuzz_harness.exe" "%BUILD_DIR%\codex_fuzz_harness.obj" "%ASM_DIR%\RawrCodex_Multi_Reference_v2.obj" kernel32.lib user32.lib
if errorlevel 1 (
    echo ERROR: Fuzzing harness linking failed
    exit /b 1
)

echo [3/6] Compiling corpus validator...
"%CL_EXE%" /EHsc /std:c++17 /W4 /O2 /I"%SRC_DIR%" /Fo"%BUILD_DIR%\codex_corpus_validator.obj" /c "%SRC_DIR%\codex_corpus_validator.cpp"
if errorlevel 1 (
    echo ERROR: Corpus validator compilation failed
    exit /b 1
)

echo [4/6] Linking corpus validator...
"%LINK_EXE%" /SUBSYSTEM:CONSOLE /LARGEADDRESSAWARE:NO /OUT:"%BUILD_DIR%\codex_corpus_validator.exe" "%BUILD_DIR%\codex_corpus_validator.obj" "%ASM_DIR%\RawrCodex_Multi_Reference_v2.obj" kernel32.lib user32.lib
if errorlevel 1 (
    echo ERROR: Corpus validator linking failed
    exit /b 1
)

echo [5/6] Compiling IDE integration...
"%CL_EXE%" /EHsc /std:c++17 /W4 /O2 /I"%SRC_DIR%" /Fo"%BUILD_DIR%\codex_ide_integration.obj" /c "%SRC_DIR%\codex_ide_integration.cpp"
if errorlevel 1 (
    echo ERROR: IDE integration compilation failed
    exit /b 1
)

echo [6/6] Linking IDE integration...
"%LINK_EXE%" /SUBSYSTEM:CONSOLE /LARGEADDRESSAWARE:NO /OUT:"%BUILD_DIR%\codex_ide_integration.exe" "%BUILD_DIR%\codex_ide_integration.obj" "%ASM_DIR%\RawrCodex_Multi_Reference_v2.obj" kernel32.lib user32.lib
if errorlevel 1 (
    echo ERROR: IDE integration linking failed
    exit /b 1
)

echo.
echo === Build Complete ===
echo Location: %BUILD_DIR%
echo.
echo Executables:
echo   - codex_fuzz_harness.exe    (Fuzzing tool)
echo   - codex_corpus_validator.exe (Corpus validation)
echo   - codex_ide_integration.exe  (CLI/GUI IDE tool)
echo.

REM Run quick tests
echo Running quick validation tests...
echo.

echo [Test 1/3] Corpus Validator:
"%BUILD_DIR%\codex_corpus_validator.exe"
if errorlevel 1 (
    echo WARNING: Corpus validator had failures
) else (
    echo Corpus validator: PASSED
)

echo.
echo [Test 2/3] Fuzzing Harness (1000 iterations):
"%BUILD_DIR%\codex_fuzz_harness.exe" -i 1000
if errorlevel 1 (
    echo WARNING: Fuzzing harness detected crashes
) else (
    echo Fuzzing harness: PASSED
)

echo.
echo [Test 3/3] IDE Integration CLI:
"%BUILD_DIR%\codex_ide_integration.exe" decode arm64 1F2003D5
if errorlevel 1 (
    echo WARNING: IDE integration CLI test failed
) else (
    echo IDE integration CLI: PASSED
)

echo.
echo === All Codex Tools Built and Tested ===