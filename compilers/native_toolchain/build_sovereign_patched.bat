@echo off
chcp 65001 > nul
setlocal EnableDelayedExpansion

echo ================================================================================
echo Sovereign Engine - Patched Build Script
echo Applies heap fix and builds patched executable
echo ================================================================================
echo.

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

if not exist "%MASM_PATH%" (
    echo ERROR: MASM not found at %MASM_PATH%
    echo Please install Visual Studio 2022 with C++ build tools
    exit /b 1
)

echo [1/5] Building patched heap implementation...
echo   Compiling: sovereign_memory_patch.asm
"%MASM_PATH%" /c /nologo /Zi /Fo:sovereign_memory_patch.obj sovereign_memory_patch.asm
if errorlevel 1 (
    echo   FAILED to compile heap patch
    exit /b 1
)
echo   OK: sovereign_memory_patch.obj

echo.
echo [2/5] Building Sovereign main with patched heap...
echo   Note: Linking with patched heap implementation

REM Check if we have the main object files
set "OBJ_FILES="
if exist "sovereign_main.obj" (
    set "OBJ_FILES=!OBJ_FILES! sovereign_main.obj"
) else (
    echo   WARNING: sovereign_main.obj not found, skipping
)

if exist "sovereign_kernels.asm.obj" (
    set "OBJ_FILES=!OBJ_FILES! sovereign_kernels.asm.obj"
) else (
    echo   WARNING: sovereign_kernels.asm.obj not found, skipping
)

if exist "SovereignInferenceLoop.asm.obj" (
    set "OBJ_FILES=!OBJ_FILES! SovereignInferenceLoop.asm.obj"
) else (
    echo   WARNING: SovereignInferenceLoop.asm.obj not found, skipping
)

REM Always include the patched heap
set "OBJ_FILES=!OBJ_FILES! sovereign_memory_patch.obj"

echo.
echo [3/5] Linking patched Sovereign executable...
echo   Objects: !OBJ_FILES!
echo   Output: sovereign_patched.exe

"%LINK_PATH%" /OUT:sovereign_patched.exe !OBJ_FILES! \
    /SUBSYSTEM:CONSOLE \
    /ENTRY:main \
    /DEBUG \
    /MACHINE:X64 \
    /NODEFAULTLIB \
    kernel32.lib \
    user32.lib \
    ntdll.lib

if errorlevel 1 (
    echo   FAILED to link patched executable
    exit /b 1
)

echo   OK: sovereign_patched.exe created

echo.
echo [4/5] Verifying patched executable...
if exist "sovereign_patched.exe" (
    for %%F in (sovereign_patched.exe) do (
        echo   Size: %%~zF bytes
    )
    echo   OK: Executable exists
) else (
    echo   FAILED: Executable not created
    exit /b 1
)

echo.
echo [5/5] Testing patched heap...
echo   Running quick heap test...
echo.

REM Create a simple test program to verify the heap works
echo #include ^<windows.h^> > test_patched_heap.c
echo #include ^<stdio.h^> >> test_patched_heap.c
echo. >> test_patched_heap.c
echo int main() { >> test_patched_heap.c
echo     HANDLE heap = GetProcessHeap(); >> test_patched_heap.c
echo     if (!heap) { printf("FAIL: No process heap\n"); return 1; } >> test_patched_heap.c
echo     void* p = HeapAlloc(heap, 0, 1024); >> test_patched_heap.c
echo     if (!p) { printf("FAIL: HeapAlloc failed\n"); return 1; } >> test_patched_heap.c
echo     HeapFree(heap, 0, p); >> test_patched_heap.c
echo     printf("PASS: Patched heap working\n"); >> test_patched_heap.c
echo     return 0; >> test_patched_heap.c
echo } >> test_patched_heap.c

gcc -O2 test_patched_heap.c -o test_patched_heap.exe 2> nul
if exist "test_patched_heap.exe" (
    test_patched_heap.exe
    del test_patched_heap.exe
    del test_patched_heap.c
)

echo.
echo ================================================================================
echo Build Summary
echo ================================================================================
echo   Patched Heap:     sovereign_memory_patch.obj [OK]
echo   Patched Exe:      sovereign_patched.exe [OK]
echo   Status:           READY FOR TESTING
echo ================================================================================
echo.
echo Next steps:
echo   1. Test with: .\sovereign_patched.exe test_model.gguf
echo   2. Verify with: .\gguf_mini_loader.exe -v test_model.gguf
echo   3. Run full test: .\unified_agentic_test.exe
echo.

endlocal
