@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd
link.exe /SUBSYSTEM:CONSOLE /LIBPATH:"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" @__link_objs.txt /OUT:bin\RawrXD-Win32IDE.exe kernel32.lib user32.lib gdi32.lib shell32.lib ole32.lib advapi32.lib uuid.lib ws2_32.lib
echo LINK_EXIT_CODE=%ERRORLEVEL%
