@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d G:\~dev\rawrxd\build-fd
if exist bin\RawrXD-Win32IDE.pdb del /f /q bin\RawrXD-Win32IDE.pdb
link.exe /nologo @CMakeFiles\RawrXD-Win32IDE.rsp /out:bin\RawrXD-Win32IDE.exe /implib:RawrXD-Win32IDE.lib /pdb:bin\RawrXD-Win32IDE.pdb /machine:x64 /INCREMENTAL:NO /subsystem:windows /LARGEADDRESSAWARE:NO /DEBUG:FULL /MANIFEST:NO /FORCE:MULTIPLE /STACK:4194304
echo LINK_EXIT=%ERRORLEVEL%
