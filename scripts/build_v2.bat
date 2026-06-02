@echo off
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe" /c /Zi /I d:\ /Fo d:\rawrxd\scripts\linker_ir_harness_crash.obj d:\linker_ir_harness.asm
if errorlevel 1 goto fail
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe" /c /Zi /I d:\ /Fo d:\rawrxd\scripts\coff_linker.obj d:\coff_linker.asm
if errorlevel 1 goto fail
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe" /c /Zi /I d:\ /Fo d:\rawrxd\scripts\arena_alloc.obj d:\arena_alloc.asm
if errorlevel 1 goto fail
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe" /c /Zi /I d:\ /Fo d:\rawrxd\scripts\linker_ir.obj d:\linker_ir.asm
if errorlevel 1 goto fail
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /MACHINE:X64 /OUT:d:\rawrxd\scripts\linker_ir_harness_crash.exe d:\rawrxd\scripts\linker_ir_harness_crash.obj d:\rawrxd\scripts\coff_linker.obj d:\rawrxd\scripts\arena_alloc.obj d:\rawrxd\scripts\linker_ir.obj d:\rawrxd\scripts\kernel32.lib
if errorlevel 1 goto fail
echo BUILD SUCCESS
goto done
:fail
echo BUILD FAILED
:done
