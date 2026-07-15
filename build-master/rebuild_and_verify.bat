@echo off
setlocal

cd /d d:\rawrxd\build-master

echo ==========================================
echo RawrXD ALU Fix - Rebuild and Verify
echo ==========================================
echo.

REM Clean old binaries
if exist bin\RawrXD_Script.exe del bin\RawrXD_Script.exe 2>nul
echo [1/5] Cleaned old binaries

REM Assemble the fixed interpreter
echo [2/5] Assembling fixed interpreter.asm...
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Zi /Fo:interpreter_fixed.obj ..\src\script\masm\interpreter.asm 2>nul
if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)
echo       OK

REM Compile runtime
echo [3/5] Compiling runtime_minimal.cpp...
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe" /c /std:c++20 /W3 /O2 /nologo /Fo:runtime_minimal.obj ..\src\script\runtime\runtime_minimal.cpp /I..\src\script /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" 2>nul
if errorlevel 1 (
    echo ERROR: Runtime compilation failed
    exit /b 1
)
echo       OK

REM Compile main
echo [4/5] Compiling main_full.cpp...
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe" /c /std:c++20 /W3 /O2 /nologo /Fo:main_full.obj ..\src\script\runtime\main_full.cpp /I..\src\script /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" 2>nul
if errorlevel 1 (
    echo ERROR: Main compilation failed
    exit /b 1
)
echo       OK

REM Link
echo [5/5] Linking RawrXD_Script.exe...
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe" /nologo main_full.obj runtime_minimal.obj interpreter_fixed.obj /out:bin\RawrXD_Script.exe /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" /LIBPATH:"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64" kernel32.lib user32.lib /subsystem:console /machine:x64 2>nul
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)
echo       OK

echo.
echo ==========================================
echo ALU Verification Suite
echo ==========================================
echo.

cd bin

echo Test 1: Addition (50 + 25)
echo 50 + 25 > test_add.js
RawrXD_Script.exe test_add.js
echo.

echo Test 2: Subtraction (100 - 45)
echo 100 - 45 > test_sub.js
RawrXD_Script.exe test_sub.js
echo.

echo Test 3: Multiplication (6 * 7)
echo 6 * 7 > test_mul.js
RawrXD_Script.exe test_mul.js
echo.

echo Test 4: Division (100 / 4)
echo 100 / 4 > test_div.js
RawrXD_Script.exe test_div.js
echo.

echo ==========================================
echo Verification Complete
echo ==========================================

cd ..

exit /b 0
