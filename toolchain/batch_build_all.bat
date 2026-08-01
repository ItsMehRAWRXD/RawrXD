@echo off
setlocal EnableDelayedExpansion

REM ============================================================================
REM Batch Build Orchestrator — Sovereign Migration for 500+ ASM Files
REM ============================================================================
REM Usage: batch_build_all.bat [options]
REM   Options:
REM     /resume          — Resume from last failed batch
REM     /parallel=N      — Process N files in parallel (default: 1)
REM     /filter=PATTERN  — Only process files matching PATTERN
REM     /triage          — Generate triage report for failures
REM ============================================================================

REM Configuration
set "SRC_DIR=d:\rawrxd\src\asm"
set "BUILD_DIR=d:\rawrxd-ci-bootstrap\build\sovereign"
set "LOG_DIR=%BUILD_DIR%\logs"
set "REPORT_DIR=%BUILD_DIR%\reports"
set "PIPELINE=d:\rawrxd-ci-bootstrap\toolchain\sovereign_pipeline.bat"
set "STATUS_FILE=%BUILD_DIR%\migration_status.json"

REM Parse arguments
set RESUME=0
set PARALLEL=1
set FILTER=*
set TRIAGE=0
set START_BATCH=0

:parse_args
if "%~1"=="" goto :done_parse
if /I "%~1"=="/resume" set RESUME=1
if /I "%~1"=="/triage" set TRIAGE=1
if /I "%~1"=="/parallel" (
    set PARALLEL=%~2
    shift
)
if /I "%~1"=="/filter" (
    set FILTER=%~2
    shift
)
if /I "%~1"=="/start" (
    set START_BATCH=%~2
    shift
)
shift
goto :parse_args
:done_parse

REM Create directories
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

REM Initialize status tracking
echo { > "%STATUS_FILE%"
echo   "start_time": "%date% %time%", >> "%STATUS_FILE%"
echo   "src_dir": "%SRC_DIR:=\\%", >> "%STATUS_FILE%"
echo   "build_dir": "%BUILD_DIR:=\\%", >> "%STATUS_FILE%"
echo   "batches": [ >> "%STATUS_FILE%"

REM Count total files
set TOTAL_FILES=0
for %%f in ("%SRC_DIR%\%FILTER%.asm") do (
    set /a TOTAL_FILES+=1
)

echo.
echo ============================================================================
echo SOVEREIGN BATCH BUILD ORCHESTRATOR
echo ============================================================================
echo Source:      %SRC_DIR%
echo Build:       %BUILD_DIR%
echo Filter:      %FILTER%
echo Parallel:    %PARALLEL%
echo Total Files: %TOTAL_FILES%
echo ============================================================================
echo.

if %TOTAL_FILES% EQU 0 (
    echo ERROR: No .asm files found in %SRC_DIR%
    exit /b 1
)

REM Process files
set PROCESSED=0
set SUCCESS=0
set FAILED=0
set SKIPPED=0
set BATCH_NUM=%START_BATCH%

for %%f in ("%SRC_DIR%\%FILTER%.asm") do (
    set /a BATCH_NUM+=1
    set "FILE_NAME=%%~nf"
    set "FILE_PATH=%%~ff"
    set "LOG_FILE=%LOG_DIR%\%%~nf.log"
    set "OBJ_FILE=%BUILD_DIR%\%%~nf.obj"
    set "EXE_FILE=%BUILD_DIR%\%%~nf.exe"
    
    set /a PROCESSED+=1
    
    REM Skip if already built and not in resume mode
    if exist "!EXE_FILE!" (
        if %RESUME%==0 (
            echo [!PROCESSED!/%TOTAL_FILES%] [SKIP] %%~nf.asm ^(already built^)
            set /a SKIPPED+=1
            goto :next_file
        )
    )
    
    echo [!PROCESSED!/%TOTAL_FILES%] [BUILD] %%~nf.asm
    
    REM Run the pipeline
    call "%PIPELINE%" "!FILE_PATH!" "!EXE_FILE!" > "!LOG_FILE!" 2^>&1
    
    if !errorlevel! EQU 0 (
        if exist "!EXE_FILE!" (
            echo [!PROCESSED!/%TOTAL_FILES%] [SUCCESS] %%~nf.exe
            set /a SUCCESS+=1
            
            REM Update status JSON
            echo     {"file": "%%~nf.asm", "status": "success", "exe": "%%~nf.exe"}, >> "%STATUS_FILE%"
        ) else (
            echo [!PROCESSED!/%TOTAL_FILES%] [FAILED] %%~nf.asm ^(no output^) - Check !LOG_FILE!
            set /a FAILED+=1
            echo     {"file": "%%~nf.asm", "status": "failed", "reason": "no_output"}, >> "%STATUS_FILE%"
        )
    ) else (
        echo [!PROCESSED!/%TOTAL_FILES%] [FAILED] %%~nf.asm - Check !LOG_FILE!
        set /a FAILED+=1
        
        REM Analyze failure type for triage
        call :analyze_failure "%%~nf" "!LOG_FILE!"
    )
    
    :next_file
)

REM Finalize status JSON
echo   ], >> "%STATUS_FILE%"
echo   "summary": { >> "%STATUS_FILE%"
echo     "total": %TOTAL_FILES%, >> "%STATUS_FILE%"
echo     "success": %SUCCESS%, >> "%STATUS_FILE%"
echo     "failed": %FAILED%, >> "%STATUS_FILE%"
echo     "skipped": %SKIPPED% >> "%STATUS_FILE%"
echo   }, >> "%STATUS_FILE%"
echo   "end_time": "%date% %time%" >> "%STATUS_FILE%"
echo } >> "%STATUS_FILE%"

echo.
echo ============================================================================
echo MIGRATION COMPLETE
echo ============================================================================
echo Total:   %TOTAL_FILES%
echo Success: %SUCCESS%
echo Failed:  %FAILED%
echo Skipped: %SKIPPED%
echo ============================================================================
echo.
echo Reports:
echo   Status:   %STATUS_FILE%
echo   Logs:     %LOG_DIR%
echo   Binaries: %BUILD_DIR%

if %FAILED% GTR 0 (
    echo.
    echo WARNING: %FAILED% files failed to build.
    echo Run with /triage flag to generate failure analysis report.
    exit /b 1
)

exit /b 0

REM ============================================================================
REM Subroutine: Analyze failure type for triage report
REM ============================================================================
:analyze_failure
set "BASE_NAME=%~1"
set "LOG_PATH=%~2"

set FAILURE_TYPE=unknown

REM Check log for specific error patterns
findstr /I "Preprocessor" "%LOG_PATH%" >nul 2>nul
if !errorlevel! EQU 0 set FAILURE_TYPE=preprocessor

findstr /I "Assembler" "%LOG_PATH%" >nul 2>nul
if !errorlevel! EQU 0 set FAILURE_TYPE=assembler

findstr /I "Linker" "%LOG_PATH%" >nul 2>nul
if !errorlevel! EQU 0 set FAILURE_TYPE=linker

findstr /I "INCLUDE" "%LOG_PATH%" >nul 2>nul
if !errorlevel! EQU 0 set FAILURE_TYPE=include

findstr /I "MACRO" "%LOG_PATH%" >nul 2>nul
if !errorlevel! EQU 0 set FAILURE_TYPE=macro

findstr /I "INVOKE" "%LOG_PATH%" >nul 2>nul
if !errorlevel! EQU 0 set FAILURE_TYPE=invoke

echo     {"file": "%BASE_NAME%.asm", "status": "failed", "reason": "%FAILURE_TYPE%"}, >> "%STATUS_FILE%"

if %TRIAGE%==1 (
    echo [TRIAGE] %BASE_NAME%.asm - %FAILURE_TYPE% >> "%REPORT_DIR%\triage_report.txt"
)

goto :eof
