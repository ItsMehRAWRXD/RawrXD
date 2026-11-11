@echo off
setlocal enabledelayedexpansion
cd /d d:\rawrxd\compilers\all_69

set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"

for %%O in (*.obj) do (
    set "EXE_NAME=%%~nO.exe"
    echo Linking %%O to !EXE_NAME!
    "%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:main "%%O" "%SDK_LIB%" /OUT:"!EXE_NAME!" >nul 2>&1
    if errorlevel 1 (
        echo   [FAIL] %%O
    ) else (
        echo   [OK] %%O
    )
)
