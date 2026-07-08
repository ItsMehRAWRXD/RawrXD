@echo off
set "MSVC_ROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"
set "SDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "SDK_VER=10.0.22621.0"

set "INCLUDE=%MSVC_ROOT%\include;%SDK_ROOT%\Include\%SDK_VER%\ucrt;%SDK_ROOT%\Include\%SDK_VER%\shared;%SDK_ROOT%\Include\%SDK_VER%\um"
set "LIB=%MSVC_ROOT%\lib\x64;%SDK_ROOT%\Lib\%SDK_VER%\ucrt\x64;%SDK_ROOT%\Lib\%SDK_VER%\um\x64"
set "PATH=%MSVC_ROOT%\bin\Hostx64\x64;%PATH%"

cd /d d:\rawrxd\src\reverse_engineering

"%MSVC_ROOT%\bin\Hostx64\x64\cl.exe" /c /EHsc /O2 /I..\..\include /I..\reverse_engineering /I..\asm test_multi_arch.cpp
if %errorlevel% neq 0 echo "Compile failed"

dir *.obj
