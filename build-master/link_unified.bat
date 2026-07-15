@echo off
pushd d:\rawrxd\build-debug-pipeline
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe /DLL /DEBUG /INCREMENTAL:NO /LIBPATH:"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\lib\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" /OUT:d:\rawrxd\build-master\bin\RawrXD_Unified.dll d:\rawrxd\build-master\*.obj kernel32.lib user32.lib
echo Exit: %ERRORLEVEL%
popd
