@echo off
setlocal

:: Set up paths
set "MSVC_ROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"
set "SDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "SDK_VER=10.0.22621.0"

:: Set environment
set "INCLUDE=%MSVC_ROOT%\include;%SDK_ROOT%\Include\%SDK_VER%\ucrt;%SDK_ROOT%\Include\%SDK_VER%\shared;%SDK_ROOT%\Include\%SDK_VER%\um"
set "LIB=%MSVC_ROOT%\lib\x64;%SDK_ROOT%\Lib\%SDK_VER%\ucrt\x64;%SDK_ROOT%\Lib\%SDK_VER%\um\x64"
set "PATH=%MSVC_ROOT%\bin\Hostx64\x64;%PATH%"

echo Building multi-arch test...

:: Create output directory
if not exist .\build-ninja mkdir .\build-ninja

:: Compile C++ files
"%MSVC_ROOT%\bin\Hostx64\x64\cl.exe" /c /EHsc /O2 /I.\include /I.\src\reverse_engineering /I.\src\asm /Fo.\build-ninja\test_multi_arch.obj .\src\reverse_engineering\test_multi_arch.cpp 2>&1
"%MSVC_ROOT%\bin\Hostx64\x64\cl.exe" /c /EHsc /O2 /I.\include /I.\src\reverse_engineering /I.\src\asm /Fo.\build-ninja\RawrCodex_Multi.obj .\src\reverse_engineering\RawrCodex_Multi.cpp 2>&1

:: Link
"%MSVC_ROOT%\bin\Hostx64\x64\link.exe" /OUT:.\build-ninja\test_multi_arch.exe .\build-ninja\test_multi_arch.obj .\build-ninja\RawrCodex_Multi.obj .\src\asm\RawrCodex.obj kernel32.lib user32.lib 2>&1

echo Done.
