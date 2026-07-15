@echo off
setlocal EnableDelayedExpansion

:: RawrXD MASM64 Batch Build - Robust CMD Version
:: Compiles all .asm files in reverse order, batches of 15

set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "OBJ_DIR=d:\rawrxd\build\obj"
set "LOG_DIR=d:\rawrxd\build\logs"

:: Create directories
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

echo ========================================
echo RawrXD MASM64 Production Build
echo ========================================

:: Get all .asm files from production source directories
set "FILE_LIST=%TEMP%\rawrxd_files.txt"
set "FAILED_LIST=%TEMP%\rawrxd_failed.txt"

dir /s /b "d:\rawrxd\src\*.asm" 2>nul > "%FILE_LIST%"
dir /s /b "d:\rawrxd\asm\*.asm" 2>nul >> "%FILE_LIST%"
dir /s /b "d:\rawrxd\asm-sources\*.asm" 2>nul >> "%FILE_LIST%"
dir /s /b "d:\rawrxd\backend\*.asm" 2>nul >> "%FILE_LIST%"
dir /s /b "d:\rawrxd\tools\*.asm" 2>nul >> "%FILE_LIST%"
dir /s /b "d:\rawrxd\UEC-X\core\masm64\*.asm" 2>nul >> "%FILE_LIST%"

:: Filter out archived orphans, tests, and duplicates
findstr /v /i "\.archived_orphans" "%FILE_LIST%" | findstr /v /i "test_output_" | findstr /v /i "extracted_chats" | sort /r > "%FILE_LIST%.filtered"

:: Count files
for /f %%a in ('type "%FILE_LIST%.filtered" ^| find /c /v ""') do set "TOTAL_FILES=%%a"
echo Total Source Files: %TOTAL_FILES%

:: Calculate batches
set /a BATCHES=(TOTAL_FILES + 14) / 15
echo Total Batches: %BATCHES%
echo Batch Size: 15 files
echo Order: REVERSE (last first)
echo ========================================

set FILE_INDEX=0
set BATCH_NUM=1
set SUCCESS_COUNT=0
set FAIL_COUNT=0
set BATCH_SUCCESS=0

for /f "usebackq delims=" %%f in ("%FILE_LIST%.filtered") do (
    set /a FILE_INDEX+=1
    set /a MOD15=FILE_INDEX %% 15
    
    if !MOD15! equ 1 (
        if !BATCH_NUM! gtr 1 (
            echo.
            echo Batch !BATCH_NUM! completed - !BATCH_SUCCESS!/15 successful
        )
        set /a BATCH_NUM=(FILE_INDEX - 1) / 15 + 1
        set BATCH_SUCCESS=0
        echo.
        echo ========================================
        echo BATCH [!BATCH_NUM!/%BATCHES%]
        echo ========================================
    )
    
    set "FILE_PATH=%%f"
    set "FILE_NAME=%%~nxf"
    set "OBJ_PATH=%OBJ_DIR%\%%~nf.obj"
    set "LOG_PATH=%LOG_DIR%\batch!BATCH_NUM!_%%~nf.log"
    
    <nul set /p =[!BATCH_NUM!/%BATCHES%] (!MOD15!/15) Compiling: !FILE_NAME! 
    
    "%ML64%" /c /W3 /nologo /Zi /Fo "!OBJ_PATH!" "!FILE_PATH!" > "!LOG_PATH!" 2>&1
    
    if !errorlevel! equ 0 (
        echo [OK]
        set /a SUCCESS_COUNT+=1
        set /a BATCH_SUCCESS+=1
    ) else (
        echo [FAIL]
        set /a FAIL_COUNT+=1
        echo %%f >> "%FAILED_LIST%"
        type "!LOG_PATH!"
        echo.
        echo BUILD CONTINUING - See %FAILED_LIST% for all failures
    )
)

echo.
echo ========================================
echo BUILD SUMMARY
echo ========================================
echo Total Files: %FILE_INDEX%
echo Successful: %SUCCESS_COUNT%
echo Failed: %FAIL_COUNT%

if %FAIL_COUNT% equ 0 (
    echo.
    echo ALL FILES COMPILED SUCCESSFULLY
echo Objects in: %OBJ_DIR%
    for /f %%a in ('dir /b "%OBJ_DIR%\*.obj" 2^>nul ^| find /c /v ""') do (
        echo Object files ready: %%a
    )
    echo.
    echo Ready for linking phase.
) else (
    echo.
    echo See %FAILED_LIST% for complete list of failed files
)

:: Cleanup
del "%FILE_LIST%" 2>nul
del "%FILE_LIST%.filtered" 2>nul

endlocal
