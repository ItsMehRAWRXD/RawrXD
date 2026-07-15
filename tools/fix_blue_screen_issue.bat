@echo off
REM Complete Fix for "This app can't run on your PC" / Blue Screen Issues
REM Production Ready - Fully automated repair process

echo ================================================================
echo   Blue Screen / "Access Denied" Fix Tool v1.0
echo ================================================================
echo.
echo This script will diagnose and fix PE executable issues.
echo.

set "TOOLS_DIR=%~dp0"
set "BIN_DIR=%TOOLS_DIR%\bin"

REM Check if tools are built
if not exist "%BIN_DIR%\pe_analyzer.exe" (
    echo [1/6] Building diagnostic tools...
    echo.
    call "%TOOLS_DIR%\build_pe_tools.bat"
    if errorlevel 1 (
        echo ❌ Failed to build tools
        exit /b 1
    )
) else (
    echo [1/6] Tools already built ✓
)

echo.
echo [2/6] Checking for problematic executables...
echo.

set "FOUND_ISSUES=0"
set "FIXED_COUNT=0"

REM Check native_toolchain directory
if exist "%~dp0..\native_toolchain" (
    cd /d "%~dp0..\native_toolchain"
    
    for %%E in (*.exe) do (
        echo Checking: %%E
        
        REM Test execution
        "%%E" --help >nul 2>&1
        set "EXIT_CODE=!ERRORLEVEL!"
        
        if !EXIT_CODE!==9009 (
            echo   ❌ Corrupted PE detected: %%E
            set "FOUND_ISSUES=1"
            
            REM Analyze
            echo   Analyzing...
            "%BIN_DIR%\pe_analyzer.exe" "%%E" >"%%E.analysis.txt" 2>&1
            
            REM Try to fix
            echo   Attempting repair...
            "%BIN_DIR%\pe_fixer.exe" "%%E" "%%E.fixed.exe"
            
            if exist "%%E.fixed.exe" (
                echo   ✅ Created fixed version: %%E.fixed.exe
                
                REM Test fixed version
                "%%E.fixed.exe" >nul 2>&1
                if !ERRORLEVEL!==0 (
                    echo   ✅ Fixed version works!
                    move /y "%%E.fixed.exe" "%%E" >nul
                    set /a "FIXED_COUNT+=1"
                ) else (
                    echo   ⚠️  Fixed version still has issues
                )
            )
        ) else if !EXIT_CODE!==5 (
            echo   ⚠️  Access denied (may be security software): %%E
        ) else (
            echo   ✓ Working (exit code: !EXIT_CODE!)
        )
    )
)

echo.
echo [3/6] Creating minimal working test executable...
echo.

if exist "%BIN_DIR%\pe_fixer.exe" (
    "%BIN_DIR%\pe_fixer.exe" --create-minimal "%BIN_DIR%\test_minimal.exe"
    
    if exist "%BIN_DIR%\test_minimal.exe" (
        echo ✅ Created minimal test executable
        
        REM Test it
        "%BIN_DIR%\test_minimal.exe"
        if !ERRORLEVEL!==42 (
            echo ✅ Test executable works correctly (returns 42)
        ) else (
            echo ⚠️  Test executable returned: !ERRORLEVEL!
        )
    ) else (
        echo ❌ Failed to create test executable
    )
)

echo.
echo [4/6] Checking assembly syntax issues...
echo.

if exist "%~dp0..\native_toolchain\test.asm" (
    echo Found test.asm - checking syntax...
    
    REM Check for MASM directives that our assembler doesn't understand
    findstr /i "option casemap" "%~dp0..\native_toolchain\test.asm" >nul && (
        echo ⚠️  Found 'option casemap' - MASM directive not supported
        echo   Converting to NASM syntax...
        
        if exist "%BIN_DIR%\asm_converter.exe" (
            "%BIN_DIR%\asm_converter.exe" "%~dp0..\native_toolchain\test.asm" "%~dp0..\native_toolchain\test_converted.asm"
            echo   ✅ Created test_converted.asm
        )
    )
)

echo.
echo [5/6] Generating report...
echo.

echo ================================================================>"%TOOLS_DIR%\fix_report.txt"
echo PE Fix Report - %date% %time%>>"%TOOLS_DIR%\fix_report.txt"
echo ================================================================>>"%TOOLS_DIR%\fix_report.txt"
echo.>>"%TOOLS_DIR%\fix_report.txt"

if "%FOUND_ISSUES%"=="1" (
    echo Issues Found: YES>>"%TOOLS_DIR%\fix_report.txt"
    echo Fixed: %FIXED_COUNT% executables>>"%TOOLS_DIR%\fix_report.txt"
) else (
    echo Issues Found: NO>>"%TOOLS_DIR%\fix_report.txt"
    echo All executables appear to be working.>>"%TOOLS_DIR%\fix_report.txt"
)

echo.>>"%TOOLS_DIR%\fix_report.txt"
echo System Information:>>"%TOOLS_DIR%\fix_report.txt"
echo   OS: %OS%>>"%TOOLS_DIR%\fix_report.txt"
echo   Processor: %PROCESSOR_ARCHITECTURE%>>"%TOOLS_DIR%\fix_report.txt"
echo.>>"%TOOLS_DIR%\fix_report.txt"

echo ✅ Report saved to: %TOOLS_DIR%\fix_report.txt

echo.
echo [6/6] Summary
echo.
echo ================================================================

if "%FOUND_ISSUES%"=="1" (
    if %FIXED_COUNT% GTR 0 (
        echo ✅ Fixed %FIXED_COUNT% corrupted executable(s)
        echo.
        echo The blue screen issue should now be resolved.
        echo Try running your executables again.
    ) else (
        echo ⚠️  Found issues but could not automatically fix all.
        echo.
        echo Manual steps required:
        echo 1. Check individual analysis files (*.analysis.txt)
        echo 2. Review fix_report.txt for details
        echo 3. Consider rebuilding from source
    )
) else (
    echo ✅ No corrupted executables found.
    echo.
    echo If you're still experiencing issues:
    echo 1. Check Windows Defender / antivirus exclusions
    echo 2. Run as Administrator
    echo 3. Check file permissions
)

echo.
echo ================================================================
echo.
echo Tools available:
echo   pe_analyzer.exe ^<file.exe^>     - Detailed PE analysis
echo   pe_fixer.exe ^<in.exe^> ^<out.exe^> - Fix corrupted PE
echo   diagnose_exe.bat ^<file.exe^>   - Quick diagnostic
echo.

exit /b 0
