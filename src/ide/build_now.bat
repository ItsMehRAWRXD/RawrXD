@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\src\ide
cl /nologo /W4 /DUNICODE /D_UNICODE /DWIN32 /D_WIN32 /EHsc /std:c++17 /O2 /DNDEBUG /MD /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" /I"d:\rawrxd\src" /I"d:\rawrxd\include" RawrXD_IDE_Win32.cpp /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" user32.lib gdi32.lib comctl32.lib comdlg32.lib shell32.lib shlwapi.lib advapi32.lib ole32.lib ws2_32.lib /OUT:..\..\bin\RawrXD_IDE.exe
