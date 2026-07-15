@echo off
cd /d d:\rawrxd\build-master

echo ==========================================
echo RawrXD Smoke Test v2 - Build and Run
echo ==========================================
echo.

echo [1/2] Compiling smoke_test_suite_v2.cpp...
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe" /O2 /EHsc /std:c++20 /W4 /Fe:smoke_test_v2.exe ..\src\script\smoke_test_suite_v2.cpp /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" /LIBPATH:"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64" 2>nul
if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)
echo       OK

echo [2/2] Running smoke_test_v2.exe...
echo.
smoke_test_v2.exe

exit /b %errorlevel%
