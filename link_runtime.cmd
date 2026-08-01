@echo off
REM link_runtime.cmd — Link all runtime .obj files into runtime_smoke.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set OBJDIR=D:\rawrxd-ci-bootstrap\build\obj
set BINDIR=D:\rawrxd-ci-bootstrap\build\bin
set RSPFILE=%TEMP%\rawrxd_link.rsp

echo -nologo > "%RSPFILE%"
echo -MACHINE:X64 >> "%RSPFILE%"
echo -OUT:"%BINDIR%\runtime_smoke.exe" >> "%RSPFILE%"
for %%f in ("%OBJDIR%\*.obj") do echo "%%f" >> "%RSPFILE%"
echo kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib shlwapi.lib ucrt.lib >> "%RSPFILE%"
echo /SUBSYSTEM:CONSOLE >> "%RSPFILE%"
echo -LIBPATH:"%OBJDIR%" >> "%RSPFILE%"
echo -LIBPATH:"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64" >> "%RSPFILE%"
echo -LIBPATH:"C:\PROGRA~2\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" >> "%RSPFILE%"
echo -LIBPATH:"C:\PROGRA~2\Windows Kits\10\Lib\10.0.26100.0\um\x64" >> "%RSPFILE%"

"%LINK%" @"%RSPFILE%"
if errorlevel 1 (
    echo LINK FAILED
    exit /b 1
)
echo LINK SUCCESS
exit /b 0
