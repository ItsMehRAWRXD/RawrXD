@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat" > nul 2>&1
cd /d d:\rawrxd

echo Building RAWRXD IDE Autonomous...

cl /nologo /W4 /O2 /EHsc /std:c++17 ^
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" ^
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" ^
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" ^
   RAWRXD_IDE_AUTONOMOUS.cpp ^
   /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" ^
   /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" ^
   user32.lib gdi32.lib comctl32.lib comdlg32.lib shell32.lib ws2_32.lib advapi32.lib ^
   /SUBSYSTEM:WINDOWS /OUT:RAWRXD_IDE_AUTONOMOUS.exe

if errorlevel 1 (
    echo Build failed
    exit /b 1
)

echo Build successful: RAWRXD_IDE_AUTONOMOUS.exe
