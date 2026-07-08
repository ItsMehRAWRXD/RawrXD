@echo off
cd /d d:\rawrxd\compilers\all_69_final

set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"

echo Building missing compilers...

for %%f in (*.asm) do (
    set "NAME=%%~nf"
    if not exist "%%~nf.exe" (
        echo Building: %%~nf.exe
        "%ML64%" /c "%%f" /Fo:"%%~nf.obj" >nul 2>&1
        if exist "%%~nf.obj" (
            "%LINK%" /subsystem:console /entry:mainCRTStartup "%%~nf.obj" "%LIB%" /out:"%%~nf.exe" >nul 2>&1
            if exist "%%~nf.exe" (
                echo   [OK] Created %%~nf.exe
            ) else (
                echo   [FAIL] Link failed for %%~nf.exe
            )
        ) else (
            echo   [FAIL] Assembly failed for %%~nf.exe
        )
    )
)

echo Done.
