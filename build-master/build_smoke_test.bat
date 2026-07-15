@echo off
setlocal

cd /d d:\rawrxd\build-master

echo ==========================================
echo RawrXD Smoke Test - Build and Run
echo ==========================================
echo.

REM Compile smoke test
echo [1/3] Compiling smoke_test_suite.cpp...
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe" /c /std:c++20 /W3 /O2 /nologo /Fo:smoke_test.obj ..\src\script\smoke_test_suite.cpp /I..\src\script /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" 2>nul
if errorlevel 1 (
    echo ERROR: Smoke test compilation failed
    exit /b 1
)
echo       OK

REM Compile supporting files
echo [2/3] Compiling dependencies...
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe" /c /std:c++20 /W3 /O2 /nologo /Fo:lexer.obj ..\src\script\lexer\lexer.cpp /I..\src\script /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" 2>nul
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe" /c /std:c++20 /W3 /O2 /nologo /Fo:parser.obj ..\src\script\parser\parser.cpp /I..\src\script /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" 2>nul
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe" /c /std:c++20 /W3 /O2 /nologo /Fo:compiler.obj ..\src\script\compiler\compiler.cpp /I..\src\script /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" 2>nul
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe" /c /std:c++20 /W3 /O2 /nologo /Fo:bytecode.obj ..\src\script\bytecode\bytecode.cpp /I..\src\script /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" 2>nul
echo       OK

REM Link
echo [3/3] Linking smoke_test.exe...
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe" /nologo smoke_test.obj lexer.obj parser.obj compiler.obj bytecode.obj /out:smoke_test.exe /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" /LIBPATH:"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64" kernel32.lib user32.lib /subsystem:console /machine:x64 2>nul
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)
echo       OK

echo.
echo ==========================================
echo Running Smoke Tests...
echo ==========================================
echo.

smoke_test.exe

exit /b %errorlevel%
