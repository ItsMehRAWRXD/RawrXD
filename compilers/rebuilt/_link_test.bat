@echo off
cd /d d:\rawrxd\compilers\rebuilt
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB kernel32.lib /OUT:test.exe test.obj
