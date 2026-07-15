@echo off
REM RawrXD-Script Build Verification Script
REM Verifies all components compile and link correctly

setlocal EnableDelayedExpansion

echo ========================================
echo RawrXD-Script Build Verification
echo ========================================
echo.

set "BUILD_DIR=d:\rawrxd\build"
set "SRC_DIR=d:\rawrxd\src\script"
set "MASM_DIR=d:\rawrxd\src\script\masm"

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

set "ERRORS=0"
set "WARNINGS=0"

REM ============================================================================
REM Phase 1: C++ Frontend Compilation
REM ============================================================================
echo [Phase 1] Compiling C++ Frontend...
echo.

REM Compiler flags
set "CXXFLAGS=/std:c++17 /EHsc /W4 /O2 /I%SRC_DIR% /I%SRC_DIR%\.."

REM Compile lexer
cl %CXXFLAGS% /c "%SRC_DIR%\lexer\lexer.cpp" /Fo"%BUILD_DIR%\lexer.obj" 2>"%BUILD_DIR%\lexer.log"
if errorlevel 1 (
    echo   [FAIL] lexer.cpp
    set /a ERRORS+=1
) else (
    echo   [PASS] lexer.cpp
)

REM Compile parser
cl %CXXFLAGS% /c "%SRC_DIR%\parser\parser.cpp" /Fo"%BUILD_DIR%\parser.obj" 2>"%BUILD_DIR%\parser.log"
if errorlevel 1 (
    echo   [FAIL] parser.cpp
    set /a ERRORS+=1
) else (
    echo   [PASS] parser.cpp
)

REM Compile bytecode
cl %CXXFLAGS% /c "%SRC_DIR%\bytecode\bytecode.cpp" /Fo"%BUILD_DIR%\bytecode.obj" 2>"%BUILD_DIR%\bytecode.log"
if errorlevel 1 (
    echo   [FAIL] bytecode.cpp
    set /a ERRORS+=1
) else (
    echo   [PASS] bytecode.cpp
)

REM Compile emitter
cl %CXXFLAGS% /c "%SRC_DIR%\compiler\bytecode_emitter.cpp" /Fo"%BUILD_DIR%\bytecode_emitter.obj" 2>"%BUILD_DIR%\emitter.log"
if errorlevel 1 (
    echo   [FAIL] bytecode_emitter.cpp
    set /a ERRORS+=1
) else (
    echo   [PASS] bytecode_emitter.cpp
)

REM Compile native bridge
cl %CXXFLAGS% /c "%SRC_DIR%\native\native_bridge.cpp" /Fo"%BUILD_DIR%\native_bridge.obj" 2>"%BUILD_DIR%\native_bridge.log"
if errorlevel 1 (
    echo   [FAIL] native_bridge.cpp
    set /a ERRORS+=1
) else (
    echo   [PASS] native_bridge.cpp
)

echo.

REM ============================================================================
REM Phase 2: MASM Assembly Compilation
REM ============================================================================
echo [Phase 2] Assembling MASM Backend...
echo.

set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"

REM Assemble interpreter
"%ML64%" /c /W3 /nologo /Zi /Fo"%BUILD_DIR%\interpreter.obj" "%MASM_DIR%\interpreter.asm" 2>"%BUILD_DIR%\interpreter_asm.log"
if errorlevel 1 (
    echo   [FAIL] interpreter.asm
    set /a ERRORS+=1
) else (
    echo   [PASS] interpreter.asm
)

REM Assemble shape system
"%ML64%" /c /W3 /nologo /Zi /Fo"%BUILD_DIR%\shape_system.obj" "%MASM_DIR%\objects\shape_system.asm" 2>"%BUILD_DIR%\shape_system.log"
if errorlevel 1 (
    echo   [FAIL] shape_system.asm
    set /a ERRORS+=1
) else (
    echo   [PASS] shape_system.asm
)

REM Assemble array optimization
"%ML64%" /c /W3 /nologo /Zi /Fo"%BUILD_DIR%\array_optimization.obj" "%MASM_DIR%\objects\array_optimization.asm" 2>"%BUILD_DIR%\array_optimization.log"
if errorlevel 1 (
    echo   [FAIL] array_optimization.asm
    set /a ERRORS+=1
) else (
    echo   [PASS] array_optimization.asm
)

REM Assemble function optimization
"%ML64%" /c /W3 /nologo /Zi /Fo"%BUILD_DIR%\function_optimization.obj" "%MASM_DIR%\objects\function_optimization.asm" 2>"%BUILD_DIR%\function_optimization.log"
if errorlevel 1 (
    echo   [FAIL] function_optimization.asm
    set /a ERRORS+=1
) else (
    echo   [PASS] function_optimization.asm
)

REM Assemble native bridge
"%ML64%" /c /W3 /nologo /Zi /Fo"%BUILD_DIR%\native_bridge_asm.obj" "%MASM_DIR%\native_bridge.asm" 2>"%BUILD_DIR%\native_bridge_asm.log"
if errorlevel 1 (
    echo   [FAIL] native_bridge.asm
    set /a ERRORS+=1
) else (
    echo   [PASS] native_bridge.asm
)

echo.

REM ============================================================================
REM Phase 3: Linking
REM ============================================================================
echo [Phase 3] Linking...
echo.

set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

REM Link test executable
"%LINK%" /SUBSYSTEM:CONSOLE /OUT:"%BUILD_DIR%\RawrXD_Script_Test.exe" ^
    "%BUILD_DIR%\lexer.obj" ^
    "%BUILD_DIR%\parser.obj" ^
    "%BUILD_DIR%\bytecode.obj" ^
    "%BUILD_DIR%\bytecode_emitter.obj" ^
    "%BUILD_DIR%\native_bridge.obj" ^
    "%BUILD_DIR%\interpreter.obj" ^
    "%BUILD_DIR%\shape_system.obj" ^
    "%BUILD_DIR%\array_optimization.obj" ^
    "%BUILD_DIR%\function_optimization.obj" ^
    "%BUILD_DIR%\native_bridge_asm.obj" ^
    kernel32.lib user32.lib ^
    2>"%BUILD_DIR%\link.log"

if errorlevel 1 (
    echo   [FAIL] Linking test executable
    set /a ERRORS+=1
) else (
    echo   [PASS] Linked RawrXD_Script_Test.exe
)

echo.

REM ============================================================================
REM Phase 4: Test Execution
REM ============================================================================
echo [Phase 4] Running Tests...
echo.

if exist "%BUILD_DIR%\RawrXD_Script_Test.exe" (
    "%BUILD_DIR%\RawrXD_Script_Test.exe"
    if errorlevel 1 (
        echo   [FAIL] Tests failed
        set /a ERRORS+=1
    ) else (
        echo   [PASS] All tests passed
    )
) else (
    echo   [SKIP] Test executable not found
)

echo.

REM ============================================================================
REM Summary
REM ============================================================================
echo ========================================
echo Build Verification Summary
echo ========================================
echo Errors:   %ERRORS%
echo Warnings: %WARNINGS%
echo.

if %ERRORS% == 0 (
    echo [SUCCESS] Build verification passed!
    exit /b 0
) else (
    echo [FAILURE] Build verification failed with %ERRORS% error(s)
    echo.
    echo Check log files in %BUILD_DIR% for details:
    dir /b "%BUILD_DIR%\*.log" 2>nul
    exit /b 1
)
