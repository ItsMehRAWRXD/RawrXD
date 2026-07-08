@echo off
cd /d d:\rawrxd\compilers\gui_ide

echo === Building RawrXD GUI IDE ===
echo.

"C:\Program Files\NASM\nasm.exe" -f win64 rawrxd_gui.asm -o rawrxd_gui.obj
if %ERRORLEVEL% neq 0 goto :error

echo Assembly complete. Linking...

"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe" rawrxd_gui.obj /SUBSYSTEM:WINDOWS /ENTRY:WinMain /LARGEADDRESSAWARE:NO /OUT:rawrxd_gui.exe "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\user32.lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\gdi32.lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\shell32.lib"
if %ERRORLEVEL% neq 0 goto :error

echo.
echo === Build Complete ===
echo.
dir rawrxd_gui.exe
echo.
echo === Done ===
goto :end

:error
echo Build failed!
exit /b 1

:end
