@echo off
REM Temporary linker test
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" /nologo /MACHINE:X64 /OUT:D:\rawrxd-ci-bootstrap\build\bin\runtime_smoke.exe D:\rawrxd-ci-bootstrap\build\obj\runtime_smoke.obj kernel32.lib user32.lib /SUBSYSTEM:CONSOLE /ENTRY:WinMain /LIBPATH:D:\rawrxd-ci-bootstrap\build\obj /LIBPATH:C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64 /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64"
if errorlevel 1 echo LINK FAILED & exit /b 1
echo LINK SUCCESS
