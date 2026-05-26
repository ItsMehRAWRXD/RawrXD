@echo off
set "MSVC_BIN=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "ML64_EXE=%MSVC_BIN%\ml64.exe"
set "LINK_EXE=%MSVC_BIN%\link.exe"

echo [ELITE] Assembling Sovereign Modules...
"%ML64_EXE%" /c /W3 /nologo /Zi /Fo Sovereign_Main.obj Sovereign_Main.asm || goto :error
"%ML64_EXE%" /c /W3 /nologo /Zi /Fo Sovereign_PEB_Loader.obj Sovereign_PEB_Loader.asm || goto :error
"%ML64_EXE%" /c /W3 /nologo /Zi /Fo Sovereign_Jitter_Probe.obj Sovereign_Jitter_Probe.asm || goto :error
"%ML64_EXE%" /c /W3 /nologo /Zi /Fo Sovereign_Globals.obj Sovereign_Globals.asm || goto :error
"%ML64_EXE%" /c /W3 /nologo /Zi /Fo Sovereign_Heap.obj Sovereign_Heap.asm || goto :error
"%ML64_EXE%" /c /W3 /nologo /Zi /Fo Sovereign_Model_Loader.obj Sovereign_Model_Loader.asm || goto :error
"%ML64_EXE%" /c /W3 /nologo /Zi /Fo Sovereign_SIMD_Scanner.obj Sovereign_SIMD_Scanner.asm || goto :error
"%ML64_EXE%" /c /W3 /nologo /Zi /Fo Sovereign_Kernels.obj Sovereign_Kernels.asm || goto :error

echo [ELITE] Linking Sovereign Monolith...
"%LINK_EXE%" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB /OUT:Sovereign.exe ^
Sovereign_Main.obj Sovereign_PEB_Loader.obj Sovereign_Jitter_Probe.obj ^
Sovereign_Globals.obj Sovereign_Heap.obj Sovereign_Model_Loader.obj ^
Sovereign_SIMD_Scanner.obj Sovereign_Kernels.obj || goto :error

echo [ELITE] Build Successful: Sovereign.exe
exit /b 0

:error
echo [ERROR] Build Failed.
exit /b 1
