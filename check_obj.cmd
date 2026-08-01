@echo off
REM Check .obj files in build\obj
set OBJDIR=D:\rawrxd-ci-bootstrap\build\obj
if not exist "%OBJDIR%" echo No obj dir & exit /b 1
echo Checking .obj files in %OBJDIR%
echo.
for %%f in ("%OBJDIR%\*.obj") do (
    setlocal enabledelayedexpansion
    set /a SIZE=%%~zf
    if !SIZE! lss 100 (
        echo %%~nf.obj is too small: !SIZE! bytes - CORRUPT
    ) else (
        echo %%~nf.obj: %%~zf bytes
    )
    endlocal
)
echo.
echo First 4 bytes of each .obj (should be 4C 46 or 4C 01 for COFF):
for %%f in ("%OBJDIR%\*.obj") do (
    set /p "=%%~nf.obj: " <nul
    certutil -encodehex -f "%%f" "%TEMP%\hex.txt" 2>nul >nul
    if exist "%TEMP%\hex.txt" (
        set /p first=<"%TEMP%\hex.txt"
        echo !first:~0,11!
        del "%TEMP%\hex.txt" 2>nul
    ) else (
        echo CANNOT READ
    )
)
