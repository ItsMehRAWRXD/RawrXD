@echo off
cd /d d:\rawrxd\compilers\all_69
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe /SUBSYSTEM:CONSOLE /ENTRY:main ada_compiler_from_scratch.obj "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib" /OUT:ada_compiler_from_scratch.exe
