@echo off
setlocal EnableDelayedExpansion

:: RawrXD MASM64 Mass Build - Reverse Order
:: Build all MASM files in batches of 15, starting from last

set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "OBJ_DIR=d:\rawrxd\build\obj"
set "LOG_DIR=d:\rawrxd\build\logs"

if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

echo ========================================
echo RawrXD MASM64 Production Build
echo ========================================

set "FILE_LIST=%TEMP%\rawrxd_files.txt"
set "FAILED_LIST=%TEMP%\rawrxd_failed.txt"

dir /s /b "d:\rawrxd\src\*.asm" 2>nul > "%FILE_LIST%"
dir /s /b "d:\rawrxd\asm\*.asm" 2>nul >> "%FILE_LIST%"
dir /s /b "d:\rawrxd\asm-sources\*.asm" 2>nul >> "%FILE_LIST%"
dir /s /b "d:\rawrxd\backend\*.asm" 2>nul >> "%FILE_LIST%"
dir /s /b "d:\rawrxd\tools\*.asm" 2>nul >> "%FILE_LIST%"
dir /s /b "d:\rawrxd\UEC-X\core\masm64\*.asm" 2>nul >> "%FILE_LIST%"

findstr /v /i "\.archived_orphans" "%FILE_LIST%" | findstr /v /i "test_output_" | findstr /v /i "extracted_chats" | sort /r > "%FILE_LIST%.filtered"

for /f %%a in ('type "%FILE_LIST%.filtered" ^| find /c /v ""') do set "TOTAL_FILES=%%a"
echo Total Source Files: %TOTAL_FILES%
echo ========================================

set FILE_INDEX=0
set SUCCESS_COUNT=0
set FAIL_COUNT=0
set BATCH_COUNT=0

for /f "usebackq delims=" %%f in ("%FILE_LIST%.filtered") do (
    set /a FILE_INDEX+=1
    set /a BATCH_COUNT+=1
    
    if !BATCH_COUNT! equ 16 (
        set BATCH_COUNT=1
        echo.
        echo --- Batch Break ---
    )
    
    set "FILE_PATH=%%f"
    set "FILE_NAME=%%~nxf"
    set "OBJ_PATH=%OBJ_DIR%\%%~nf.obj"
    set "LOG_PATH=%LOG_DIR%\%%~nf.log"
    
    echo [!FILE_INDEX!] Compiling: !FILE_NAME!
    
    "%ML64%" /c /W3 /nologo /Zi /Fo "!OBJ_PATH!" "!FILE_PATH!" > "!LOG_PATH!" 2>&1
    
    if !errorlevel! equ 0 (
        echo   [OK]
        set /a SUCCESS_COUNT+=1
    ) else (
        echo   [FAIL] - See !LOG_PATH!
        set /a FAIL_COUNT+=1
        echo %%f >> "%FAILED_LIST%"
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
    dir /b "%OBJ_DIR%\*.obj" 2>nul | find /c /v ""
) else (
    echo See %FAILED_LIST% for failed files
)

del "%FILE_LIST%" 2>nul
del "%FILE_LIST%.filtered" 2>nul

endlocal
