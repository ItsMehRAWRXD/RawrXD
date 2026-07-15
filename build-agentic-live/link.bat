@echo off
set LIBPATH=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" /OUT:AgenticLive.exe /SUBSYSTEM:CONSOLE /ENTRY:AgenticMain /MACHINE:X64 /LIBPATH:"%LIBPATH%" agentic_sovereign_entry.obj agentic_aperture_live.obj aperture_q4_0_avx512_v2.obj kernel32.lib user32.lib
