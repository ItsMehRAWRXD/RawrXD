call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul
cd /d "G:\~dev\rawrxd\build-fd"
link.exe /nologo @CMakeFiles\RawrXD-Win32IDE.rsp /out:bin\RawrXD-Win32IDE_r1soft.exe /implib:RawrXD-Win32IDE_r1soft.lib /pdb:bin\RawrXD-Win32IDE_r1soft.pdb /version:0.0 /machine:x64 /INCREMENTAL:NO /subsystem:windows /LTCG /LARGEADDRESSAWARE:NO /DEBUG:FULL /MANIFEST:NO /FORCE:MULTIPLE /STACK:4194304
echo LINK_EXIT=%ERRORLEVEL%
