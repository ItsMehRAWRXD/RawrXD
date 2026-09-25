@echo off
setlocal
for /f "delims=" %%i in ('dir /s /b "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\*editbin.exe" 2^>nul') do (
    set "EDITBIN=%%i"
    goto :found
)
:found
if not defined EDITBIN (
    echo EDITBIN_NOT_FOUND
    exit /b 1
)
echo EDITBIN=%EDITBIN%
set "EXE=f:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe"
copy /Y "%EXE%" "%EXE%.bak"
"%EDITBIN%" /STACK:8388608 "%EXE%"
echo EDITBIN_DONE
