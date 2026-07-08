@echo off
cd /d d:\rawrxd\src\asm

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /Fo test_minimal_print.obj test_minimal_print.asm
if %errorlevel% neq 0 echo "Assembly failed"

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" /SUBSYSTEM:CONSOLE /ENTRY:main /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" /OUT:test_minimal_print.exe test_minimal_print.obj kernel32.lib ucrt.lib
if %errorlevel% neq 0 echo "Link failed"

echo Build complete
