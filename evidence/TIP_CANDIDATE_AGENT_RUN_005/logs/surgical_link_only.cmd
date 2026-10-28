@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001"
if exist bin\RawrXD-Win32IDE.exe del /f /q bin\RawrXD-Win32IDE.exe
if exist bin\RawrXD-Win32IDE.pdb del /f /q bin\RawrXD-Win32IDE.pdb
echo === LINK START %DATE% %TIME% ===
"C:\Program Files\CMake\bin\cmake.exe" -E vs_link_exe --msvc-ver=1944 --intdir=CMakeFiles\RawrXD-Win32IDE.dir --rc="C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\rc.exe" --mt="C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\mt.exe" --manifests -- "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe" /nologo @CMakeFiles\RawrXD-Win32IDE.rsp /out:bin\RawrXD-Win32IDE.exe /implib:RawrXD-Win32IDE.lib /pdb:bin\RawrXD-Win32IDE.pdb /version:0.0 /machine:x64 /INCREMENTAL:NO /subsystem:windows /LTCG /LARGEADDRESSAWARE /DEBUG:FULL /MAP:G:/~dev/rawrxd/build_win32ide_link001/bin/RawrXD-Win32IDE.map /MAPINFO:EXPORTS /MANIFEST:NO /FORCE:MULTIPLE /STACK:4194304
set LINK_EXIT=%ERRORLEVEL%
echo LINK_EXIT=%LINK_EXIT%
if exist bin\RawrXD-Win32IDE.exe (
  echo EXE_PRESENT=1
) else (
  echo EXE_PRESENT=0
)
exit /b %LINK_EXIT%
