@echo off
setlocal
set SRC=d:\rawrxd\src
set ASM=d:\rawrxd\src\asm
set OBJ=d:\rawrxd\obj
set BIN=D:\
if not exist %OBJ% mkdir %OBJ%

echo [Sovereign] Assembling Overfeatured Monolith...
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo /Zi /I%SRC% /I%ASM% /Fo %OBJ%\Sovereign_Main.obj %SRC%\Sovereign_Main.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo /Zi /I%SRC% /I%ASM% /Fo %OBJ%\Sovereign_PEB_Loader.obj %SRC%\Sovereign_PEB_Loader.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo /Zi /I%SRC% /I%ASM% /Fo %OBJ%\Sovereign_Hooks.obj %ASM%\Sovereign_Hooks.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo /Zi /I%SRC% /I%ASM% /Fo %OBJ%\Sovereign_Syscalls.obj %SRC%\Sovereign_Syscalls.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo /Zi /I%SRC% /I%ASM% /Fo %OBJ%\Sovereign_Reverse.obj %ASM%\Sovereign_Reverse_Engineering.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo /Zi /I%SRC% /I%ASM% /Fo %OBJ%\Sovereign_Graph.obj %ASM%\Sovereign_Execution_Graph_Logic.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo /Zi /I%SRC% /I%ASM% /Fo %OBJ%\Sovereign_Stubs.obj %SRC%\Sovereign_Elite_Stubs.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo /Zi /I%SRC% /I%ASM% /Fo %OBJ%\Sovereign_Globals.obj %ASM%\Sovereign_Globals.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo /Zi /I%SRC% /I%ASM% /Fo %OBJ%\Sovereign_Dump.obj %ASM%\Sovereign_Dump.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo /Zi /I%SRC% /I%ASM% /Fo %OBJ%\Sovereign_Dis.obj %ASM%\Sovereign_Dis.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo /Zi /I%SRC% /I%ASM% /Fo %OBJ%\Sovereign_Plugins.obj %ASM%\Sovereign_Plugin_Loader.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo /Zi /I%SRC% /I%ASM% /Fo %OBJ%\Sovereign_UI.obj %SRC%\Sovereign_UI_Console.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo /Zi /I%SRC% /I%ASM% /Fo %OBJ%\Sovereign_Heap.obj %SRC%\Sovereign_Heap.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo /Zi /I%SRC% /I%ASM% /Fo %OBJ%\Sovereign_Scanner.obj %SRC%\Sovereign_SIMD_Scanner.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo /Zi /I%SRC% /I%ASM% /Fo %OBJ%\Sovereign_Watchdog.obj %ASM%\Sovereign_Watchdog_Lean.asm

echo [Sovereign] Linking Overfeatured Elite Monolith...
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB /LARGEADDRESSAWARE:NO /DEBUG /OUT:%BIN%Sovereign_Elite.exe ^
    %OBJ%\Sovereign_Main.obj ^
    %OBJ%\Sovereign_PEB_Loader.obj ^
    %OBJ%\Sovereign_Hooks.obj ^
    %OBJ%\Sovereign_Syscalls.obj ^
    %OBJ%\Sovereign_Reverse.obj ^
    %OBJ%\Sovereign_Graph.obj ^
    %OBJ%\Sovereign_Stubs.obj ^
    %OBJ%\Sovereign_Globals.obj ^
    %OBJ%\Sovereign_Dump.obj ^
    %OBJ%\Sovereign_Dis.obj ^
    %OBJ%\Sovereign_Plugins.obj ^
    %OBJ%\Sovereign_UI.obj ^
    %OBJ%\Sovereign_Heap.obj ^
    %OBJ%\Sovereign_Scanner.obj ^
    %OBJ%\Sovereign_Watchdog.obj

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Linker failed.
    exit /b 1
)
echo [Sovereign] BUILD SUCCESSFUL: %BIN%Sovereign_Elite.exe