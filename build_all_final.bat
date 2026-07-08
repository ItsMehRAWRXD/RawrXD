@echo off
cd /d d:\rawrxd\compilers\all_69_final

set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

echo ========================================
echo Building Missing Compilers
echo ========================================

set COUNT=0

for %%f in (*.asm) do (
    if not exist "%%~nf.exe" (
        echo Building: %%~nf.exe
        "%ML64%" /c "%%f" /Fo:"%%~nf.obj" >nul 2>&1
        if exist "%%~nf.obj" (
            "%LINK%" /subsystem:console /entry:mainCRTStartup "%%~nf.obj" kernel32.lib /out:"%%~nf.exe" >nul 2>&1
            if exist "%%~nf.exe" (
                echo   [OK] Created %%~nf.exe
                set /a COUNT+=1
            ) else (
                echo   [FAIL] Link failed for %%~nf.exe
            )
        ) else (
            echo   [FAIL] Assembly failed for %%~nf.exe
        )
    )
)

echo.
echo ========================================
echo Built %COUNT% new compilers
echo ========================================
