@echo off
REM build_dispatcher.bat — Build the Sovereign Inference Pipeline
REM Assembles and links: mmap_loader + Sovereign_Model_Streamer + Sovereign_Inference_Dispatcher

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe

echo [BUILD] Assembling Sovereign_Inference_Dispatcher.asm...
%ML64% /c /W3 /nologo /Zi /Fo Sovereign_Inference_Dispatcher.obj Sovereign_Inference_Dispatcher.asm
if errorlevel 1 goto :fail

echo [BUILD] Assembling Sovereign_Model_Streamer.asm...
%ML64% /c /W3 /nologo /Zi /Fo Sovereign_Model_Streamer.obj Sovereign_Model_Streamer.asm
if errorlevel 1 goto :fail

echo [BUILD] Assembling mmap_loader.asm...
%ML64% /c /W3 /nologo /Zi /Fo mmap_loader.obj mmap_loader.asm
if errorlevel 1 goto :fail

echo [BUILD] Linking dispatcher test executable...
%LINK% /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:sovereign_dispatcher_test.exe ^
    Sovereign_Inference_Dispatcher.obj ^
    Sovereign_Model_Streamer.obj ^
    mmap_loader.obj ^
    kernel32.lib
if errorlevel 1 goto :fail

echo [BUILD] SUCCESS: sovereign_dispatcher_test.exe built.
echo [BUILD] Pipeline components: mmap_loader + streamer + dispatcher
goto :eof

:fail
echo [BUILD] FAILED. Check error messages above.
exit /b 1
