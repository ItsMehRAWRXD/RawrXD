@echo off
setlocal enabledelayedexpansion

echo ============================================
echo RawrXD Bootstrap Build System
echo Self-Hosting Toolchain Initialization
echo ============================================
echo.

set "BOOTSTRAP_DIR=d:\rawrxd\compilers\bootstrap"
set "STAGE1=%BOOTSTRAP_DIR%\stage1"
set "STAGE2=%BOOTSTRAP_DIR%\stage2"
set "STAGE3=%BOOTSTRAP_DIR%\stage3"

REM Check if already self-hosted
if exist "%STAGE3%\rawrxd_native_assembler.exe" (
    if exist "%STAGE3%\rawrxd_native_linker_v2.exe" (
        echo Self-hosted toolchain found!
        echo.
        echo Run 'bootstrap verify' to test it
        echo Run 'bootstrap clean' to rebuild from scratch
        echo.
        goto :parse_args
    )
)

echo No self-hosted toolchain found.
echo Starting bootstrap process...
echo.

:stage1
echo ============================================
echo STAGE 1: Building seed toolchain with MinGW
echo ============================================
call "%BOOTSTRAP_DIR%\stage1_build.bat"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Stage 1 failed
    exit /b 1
)
echo.

:stage2
echo ============================================
echo STAGE 2: Testing self-assembly
echo ============================================
call "%BOOTSTRAP_DIR%\stage2_self_asm.bat"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Stage 2 failed
    exit /b 1
)
echo.

:stage3
echo ============================================
echo STAGE 3: Self-linking
echo ============================================
echo Note: Self-linking requires assembly source of linker
echo Skipping for now - requires manual implementation
echo.

:stage4
echo ============================================
echo STAGE 4: Verification
echo ============================================
if exist "%STAGE3%\rawrxd_native_assembler.exe" (
    call "%BOOTSTRAP_DIR%\stage4_verify.bat"
    if %ERRORLEVEL% neq 0 (
        echo ERROR: Stage 4 failed
        exit /b 1
    )
) else (
    echo Skipping verification - no self-built tools yet
)
echo.

echo ============================================
echo Bootstrap process complete!
echo ============================================
echo.
echo Summary:
echo   Stage 1 (MinGW build):     DONE
if exist "%STAGE2%\self_test.obj" (
    echo   Stage 2 (Self-assembly): DONE
) else (
    echo   Stage 2 (Self-assembly): PENDING
)
if exist "%STAGE3%\rawrxd_native_assembler.exe" (
    echo   Stage 3 (Self-linking):  DONE
) else (
    echo   Stage 3 (Self-linking):  PENDING
)
if exist "%STAGE3%\rawrxd_native_assembler.exe" (
    echo   Stage 4 (Verification):  DONE
) else (
    echo   Stage 4 (Verification):  PENDING
)
echo.
exit /b 0

:parse_args
if "%~1"=="verify" goto :do_verify
if "%~1"=="clean" goto :do_clean
if "%~1"=="help" goto :do_help
goto :do_help

:do_verify
echo Running verification...
call "%BOOTSTRAP_DIR%\stage4_verify.bat"
exit /b %ERRORLEVEL%

:do_clean
echo Cleaning bootstrap directories...
if exist "%STAGE1%" rmdir /s /q "%STAGE1%"
if exist "%STAGE2%" rmdir /s /q "%STAGE2%"
if exist "%STAGE3%" rmdir /s /q "%STAGE3%"
echo Clean complete. Run bootstrap again to rebuild.
exit /b 0

:do_help
echo Usage: bootstrap [command]
echo.
echo Commands:
echo   (none)  - Run full bootstrap process
echo   verify  - Verify self-hosted toolchain
echo   clean   - Clean all bootstrap directories
echo   help    - Show this help message
echo.
exit /b 0
