@echo off
set ML64_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe

echo [Sovereign Build] Assembling Modules...

"%ML64_PATH%" /c /Fo D:\rawrxd\obj\Engine.obj D:\rawrxd\src\Sovereign_Engine.asm
"%ML64_PATH%" /c /Fo D:\rawrxd\obj\IPC.obj D:\rawrxd\src\Sovereign_IPC.asm
"%ML64_PATH%" /c /Fo D:\rawrxd\obj\SwarmLink.obj D:\rawrxd\src\Sovereign_SwarmLink.asm
"%ML64_PATH%" /c /Fo D:\rawrxd\obj\Memory.obj D:\rawrxd\src\Sovereign_Memory.asm

echo [Sovereign Build] Linking High-Frequency Binary...

"%LINK_PATH%" /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:D:\rawrxd\Sovereign_Engine.exe ^
    D:\rawrxd\obj\Engine.obj ^
    D:\rawrxd\obj\IPC.obj ^
    D:\rawrxd\obj\SwarmLink.obj ^
    D:\rawrxd\obj\Memory.obj ^
    kernel32.lib user32.lib

if %ERRORLEVEL% EQU 0 (
    echo [Sovereign Build] SUCCESS: D:\rawrxd\Sovereign_Engine.exe
) else (
    echo [Sovereign Build] FAILURE
    exit /b 1
)
