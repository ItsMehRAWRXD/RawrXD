@echo off
REM Working Toolchain Integration Test
REM Demonstrates: asm -> obj -> exe pipeline

echo ==========================================
echo RawrXD Working Toolchain Integration Test
echo ==========================================
echo.

set ASM_FILE=test_program.asm
set OBJ_FILE=test_program.obj
set EXE_FILE=test_program.exe

echo Step 1: Assembling %ASM_FILE%...
working_assembler.exe %ASM_FILE% %OBJ_FILE%
if errorlevel 1 (
    echo FAILED: Assembly failed
    exit /b 1
)
echo SUCCESS: Created %OBJ_FILE%
echo.

echo Step 2: Linking %OBJ_FILE%...
working_linker.exe %OBJ_FILE% %EXE_FILE%
if errorlevel 1 (
    echo FAILED: Linking failed
    exit /b 1
)
echo SUCCESS: Created %EXE_FILE%
echo.

echo Step 3: Verifying PE structure...
if exist %EXE_FILE% (
    for %%F in (%EXE_FILE%) do (
        echo File size: %%~zF bytes
    )
) else (
    echo FAILED: Output file not created
    exit /b 1
)
echo.

echo Step 4: Running %EXE_FILE%...
%EXE_FILE%
echo Exit code: %ERRORLEVEL%
echo.

if %ERRORLEVEL% equ 42 (
    echo ==========================================
    echo SUCCESS: Toolchain working correctly!
    echo Expected exit code 42, got %ERRORLEVEL%
    echo ==========================================
) else (
    echo WARNING: Unexpected exit code %ERRORLEVEL%
    echo Expected: 42
)

echo.
echo Files created:
dir /b %OBJ_FILE% %EXE_FILE% 2>nul

echo.
echo Test complete.
