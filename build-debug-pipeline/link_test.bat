@echo off
echo [LINK] Using local link.exe...
cd /d d:\rawrxd\build-debug-pipeline
d:\rawrxd\build-debug-pipeline\link.exe /DLL /DEBUG /INCREMENTAL:NO /NOENTRY /OUT:d:\rawrxd\build-master\bin\RawrXD_Test.dll d:\rawrxd\build-master\debug_event_ring.obj d:\rawrxd\build-master\editor_stubs.obj kernel32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64
echo Exit: %ERRORLEVEL%
