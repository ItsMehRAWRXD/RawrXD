@echo off
echo [LINK] Linking from debug-pipeline context...
cd /d d:\rawrxd\build-debug-pipeline
link.exe /DLL /OUT:d:\rawrxd\build-master\bin\RawrXD_Full.dll d:\rawrxd\build-master\*.obj kernel32.lib user32.lib gdi32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64 /LARGEADDRESSAWARE /DEBUG /INCREMENTAL:NO
echo Exit: %ERRORLEVEL%
