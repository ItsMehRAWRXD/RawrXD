@echo off
setlocal enabledelayedexpansion

echo ========================================
echo Linking All Compiler Object Files
echo ========================================

set "LINKER=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "LIB_PATH=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
set "OBJ_DIR=d:\rawrxd\compilers\all_69_final"
set "COUNT=0"

for %%f in ("%OBJ_DIR%\*.obj") do (
    set "OBJ_FILE=%%f"
    set "EXE_FILE=%%~dpnf.exe"
    
    if not exist "!EXE_FILE!" (
        echo Linking: %%~nf.exe
        "!LINKER!" /subsystem:console /entry:mainCRTStartup "!OBJ_FILE!" "!LIB_PATH!\kernel32.lib" /out:"!EXE_FILE!" > nul 2>&1
        if exist "!EXE_FILE!" (
            echo   [OK] Created %%~nf.exe
            set /a COUNT+=1
        ) else (
            echo   [FAIL] Failed to create %%~nf.exe
        )
    ) else (
        echo [SKIP] %%~nf.exe already exists
    )
)

echo.
echo ========================================
echo Linked !COUNT! new executables
echo ========================================

endlocal
