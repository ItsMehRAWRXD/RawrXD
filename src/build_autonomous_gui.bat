@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\src
cl.exe /nologo /O2 /DUNICODE /D_UNICODE /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" /Fe:d:\rawrxd\bin\RawrXD_Autonomous_GUI.exe AUTONOMOUS_IDE_GUI.cpp /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" user32.lib gdi32.lib comctl32.lib kernel32.lib
